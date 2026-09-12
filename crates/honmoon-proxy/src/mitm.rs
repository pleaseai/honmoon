//! TLS-terminating MITM handler (Phase 5).
//!
//! [`hudsucker`] owns the proxy accept loop; this module supplies the
//! [`HttpHandler`] that drives Honmoon's policy engine. Requests reach
//! [`HonmoonHandler::handle_request`] in three shapes:
//!
//! 1. The **CONNECT request** — host-level policy (allow / deny / pause) is
//!    applied here, exactly as the raw CONNECT proxy did. This runs for every
//!    tunnel, whether or not it is later intercepted.
//! 2. **Cleartext HTTP requests** (`http://` forward-proxy requests) — host-level
//!    policy is applied here too, so the egress allowlist can't be bypassed by
//!    skipping CONNECT. Bodies are also scanned.
//! 3. **Decrypted inner requests** over a terminated tunnel (only when
//!    intercepted) — the host was already authorized at the CONNECT; the body is
//!    scanned and PII rules are either audited or enforced according to
//!    [`PiiMode`](crate::gateway::PiiMode).
//!
//! Whether a request is an inner request (shape 3) is decided by the
//! [`AuthorizedTunnel`] this handler clone carries — the connection it arrived
//! on must have made an authorized CONNECT to that host — **not** by the URI
//! scheme: a client could send an absolute-form `GET https://…` without CONNECT
//! (or spoof `:authority` over h2), and trusting the scheme would let it skip
//! the host gate. Unrecognized requests are gated like shape 2.
//!
//! Content inspection defaults to **detect-only** for backward compatibility:
//! PII findings and the policy's would-be verdict are audited, then forwarded.
//! In block mode, the same verdict is enforced inline (`deny` returns 403 and
//! `pause` uses the shared approval registry).
//! Request-body buffering and `Content-Encoding` decoding live in
//! [`crate::body`]. By default the forwarded body remains the original encoded
//! bytes; when wire redaction is enabled, a fully buffered/decoded UTF-8 body is
//! rewritten to identity-encoded placeholder text before the upstream leg.
//!
//! Whether a tunnel is TLS-terminated is decided by
//! [`should_intercept`](HonmoonHandler::should_intercept) from the gateway's
//! [`InterceptPolicy`](crate::gateway::InterceptPolicy).

use std::collections::{BTreeSet, HashMap};

use honmoon_core::{
    AuditDraft, DEFAULT_MIN_PII_SEVERITY, Decision, EndpointProtocol, Facts, FactsSummary,
    HttpFacts, Mapping, PiiFacts, PiiSpan, RedactionOutcome, SecretTokenizer, Verdict,
    decide_explained, decide_pii_audit_only, detect_secrets, detect_spans, pii::severity_for_label,
    protocols::parse_k8s_request, redact_with_spans, summarize_spans,
};
use http_body_util::{BodyExt, Full};
use hudsucker::hyper::{Method, Request, Response, StatusCode, header};
use hudsucker::{Body, HttpContext, HttpHandler, RequestOrResponse};

use crate::approval::{HoldOutcome, hold};
use crate::body::{
    Buffered, MAX_INSPECT_BODY, StrictDecode, buffer_up_to, buffered_body, decode_strict,
    detokenizing_body, prefixed_body, retained_trailer_names, trailer_filtered_body, utf8_prefix,
};
use crate::gateway::{
    GatewayState, InterceptPolicy, PiiMode, SignedBodyMode, authority_port, canonical_host,
};
use crate::signed_body::{
    BODY_DIGEST_HEADERS, REWRITTEN_FRAMING_HEADERS, SignedBodyScheme, TRAILER_FRAMING_HEADERS,
    authentication_signs_headers, body_signature_scheme, signed_headers_among,
};

/// Names why honmoon itself produced a response, so a client (or an agent
/// reading the error) can tell it apart from an upstream failure.
const HONMOON_REASON: header::HeaderName = header::HeaderName::from_static("x-honmoon-reason");
/// Default port for a CONNECT authority or an `https://` URI without one.
const HTTPS_PORT: u16 = 443;
/// Default port for a cleartext forward-proxy request without one.
const HTTP_PORT: u16 = 80;

/// The CONNECT tunnel the connection this handler clone serves is authorized
/// for.
///
/// Authorization belongs to an accepted connection, not to an address. The
/// handler is cloned per request off a per-connection prototype; hudsucker then
/// moves the clone that handled the CONNECT into the task that owns the tunnel
/// and serves every decrypted inner request from a clone of *that* instance
/// (`InternalProxy::process_connect` → `serve_stream`). Recording the
/// authorized target on the handler therefore reaches exactly this tunnel's
/// inner requests and dies with the tunnel — where a registry keyed by the
/// client `SocketAddr` outlived the connection that earned it and lent its
/// target to whatever later connection reused the source port (#100).
///
/// A clone that carries no tunnel (a fresh connection, a plain forward-proxy
/// request) is host-gated, so losing this state can only re-gate a request, it
/// can never skip a gate.
#[derive(Clone)]
struct AuthorizedTunnel {
    host: String,
    port: u16,
}

impl AuthorizedTunnel {
    /// Whether this tunnel authorizes a request to exactly `host:port`.
    ///
    /// hudsucker forces each HTTP/1.x inner request's URI authority to its
    /// tunnel's CONNECT authority, so a genuine tunnelled request matches by
    /// construction. Anything else claiming `https://` (an absolute-form
    /// request without CONNECT, an h2 `:authority` mismatch) does not match and
    /// gets host-gated like a cleartext request.
    ///
    /// The host is load-bearing, not redundant with the connection: hudsucker
    /// rewrites the authority for HTTP/1.0 and HTTP/1.1 only (`serve_stream`),
    /// and forwards every request by re-issuing it through its own client at
    /// the request's URI rather than piping bytes down the CONNECT tunnel
    /// (`proxy`). So an h2 `:authority` that differs from the CONNECT target is
    /// where the request actually goes, and trusting the recorded tunnel target
    /// would evaluate egress against a host the bytes never reach while
    /// delivering them to one that was never gated.
    ///
    /// The port is compared for the same reason. Matching on the host alone
    /// would hand the CONNECT port back to an h2 request that named a different
    /// one: a client tunnelled to `cluster.example:443` could send
    /// `:authority: cluster.example:6443`, be evaluated at 443 (resolving no
    /// endpoint and parsing no `k8s` facts), and still have hudsucker forward
    /// it to 6443 — past a deny rule bound to that endpoint.
    fn authorizes(&self, host: &str, port: u16) -> bool {
        self.host == host && self.port == port
    }
}

struct RedactionInput<'a> {
    scanned: Option<&'a [u8]>,
    decoded: Option<&'a [u8]>,
    content_encoding_present: bool,
    content_encoding: Option<&'a str>,
    pii_spans: &'a [PiiSpan],
    is_json: bool,
    host: &'a str,
    /// Facts the caller already decided on, reused for the audit record when a
    /// body-signed request is blocked here.
    summary: &'a FactsSummary,
    /// The trailer field names the forwarded body will actually carry — what
    /// [`crate::body::retained_trailer_names`] answered on a buffered branch,
    /// and empty on the two over-cap ones, where honmoon never holds the frame.
    retained_trailers: &'a [header::HeaderName],
}

/// What wire redaction did to a policy-approved request, which decides whether
/// its trailer section is still there to be re-framed for the upstream leg.
enum Forwarded {
    /// The body is the one the client sent, trailer frame included.
    PassThrough(Request<Body>),
    /// The redaction rewrite replaced the body with `Full`, which carries no
    /// trailer frame (deliberately — see [`HonmoonHandler::redacted_request`]).
    Rewritten(Request<Body>),
    /// Answered locally instead of forwarded.
    Blocked(RequestOrResponse),
}

/// Outcome of the host-level policy gate.
enum Gate {
    /// The request may proceed (to tunnel / forward / inspection).
    Proceed,
    /// The request is finished — send this response to the client. Boxed to keep
    /// the enum small (the response type is large).
    Block(Box<RequestOrResponse>),
}

/// The [`HttpHandler`] that applies Honmoon policy to proxied traffic.
///
/// Cloned per connection (and per decrypted request) by hudsucker; all real
/// state lives behind the `Arc`s in [`GatewayState`], so cloning is cheap.
#[derive(Clone)]
pub struct HonmoonHandler {
    state: GatewayState,
    /// Set on the clone that handles an allowed CONNECT, and inherited by the
    /// clones hudsucker serves that tunnel's inner requests from. `None` on
    /// every clone taken from the per-connection prototype, so authorization
    /// cannot outlive the connection that earned it.
    tunnel: Option<AuthorizedTunnel>,
}

impl HonmoonHandler {
    pub fn new(state: GatewayState) -> Self {
        Self {
            state,
            tunnel: None,
        }
    }

    /// Record that the connection this clone serves holds an authorized CONNECT
    /// tunnel to `host:port`.
    fn authorize_tunnel(&mut self, host: String, port: u16) {
        self.tunnel = Some(AuthorizedTunnel { host, port });
    }

    /// Whether this clone's tunnel authorizes a request to exactly `host:port`.
    /// A request that does not match still needs the host gate.
    fn tunnel_authorizes(&self, host: &str, port: u16) -> bool {
        self.tunnel
            .as_ref()
            .is_some_and(|tunnel| tunnel.authorizes(host, port))
    }

    /// Resolve the policy endpoint declared for the `(host, port)` the client
    /// dialed, returning its name and protocol.
    fn resolve_endpoint(&self, host: &str, port: u16) -> Option<(String, EndpointProtocol)> {
        let (name, endpoint) = self.state.policy.endpoint_for(host, port)?;
        tracing::debug!(domain = %host, endpoint = %name, protocol = ?endpoint.protocol, "endpoint resolved");
        Some((name.to_owned(), endpoint.protocol))
    }

    /// The facts a host-level decision is made on.
    fn host_facts(&self, host: &str, port: u16) -> Facts {
        Facts {
            domain: Some(host.to_owned()),
            endpoint: self.resolve_endpoint(host, port).map(|(name, _)| name),
            http: Some(HttpFacts {
                host: host.to_owned(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// The endpoint name when `(host, port)` names one honmoon inspects inline
    /// rather than tunnels.
    ///
    /// A CONNECT is a raw tunnel: honmoon only ever sees TLS or opaque bytes
    /// over it, never PostgreSQL frames. Carrying a `protocol: postgres`
    /// endpoint over one would take every statement past the `sql.*` rules that
    /// endpoint exists to enforce — declaring the protocol would silently turn
    /// inspection *off* on this listener.
    ///
    /// `postgres` is the only protocol affected: `kubernetes` is HTTPS and is
    /// inspected by this very handler, and `tcp` declares no inspection at all.
    fn uninspectable_endpoint(&self, host: &str, port: u16) -> Option<String> {
        let (endpoint, protocol) = self.resolve_endpoint(host, port)?;
        match protocol {
            EndpointProtocol::Postgres => Some(endpoint),
            EndpointProtocol::Kubernetes | EndpointProtocol::Tcp => None,
        }
    }

    /// Answer a CONNECT to an inline-inspected endpoint, without ever opening a
    /// tunnel honmoon could not inspect.
    ///
    /// Policy still runs and still decides the audit entry, so the transport
    /// refusal does not cost the connection its rule attribution:
    ///
    /// - `deny` is answered exactly as anywhere else — the connection was
    ///   refused on its own merits and the transport is beside the point.
    /// - `allow` becomes the transport refusal. No `Allowed` entry is recorded
    ///   for a connection that never happens.
    /// - `pause` is refused too, and is **not** held: a human cannot approve a
    ///   transport into inspecting frames it never sees, so the queue would only
    ///   offer an approval that cannot mean what it says. The rule that paused it
    ///   is still what the audit entry names.
    ///
    /// The audit entry keeps `decision` and `verdict` apart, as the hold path
    /// already does: the disposition is a denial (honmoon refused the
    /// connection) while the verdict stays whatever the policy actually said, so
    /// the entry never claims a rule denied something it allowed.
    fn refuse_uninspectable_connect(
        &self,
        host: &str,
        port: u16,
        endpoint: &str,
    ) -> RequestOrResponse {
        let facts = self.host_facts(host, port);
        let outcome = decide_explained(&self.state.policy, &facts);
        let summary = FactsSummary::from(&facts);

        if outcome.verdict == Verdict::Deny {
            tracing::info!(domain = %host, rule = ?outcome.rule, "egress denied");
            self.state.audit.record(AuditDraft {
                decision: Decision::Denied,
                verdict: Verdict::Deny,
                rule: outcome.rule,
                facts: summary,
                approval_id: None,
            });
            return status_response(StatusCode::FORBIDDEN);
        }

        tracing::info!(
            domain = %host,
            %endpoint,
            rule = ?outcome.rule,
            verdict = ?outcome.verdict,
            "CONNECT to an inline-inspected endpoint refused"
        );
        self.state.audit.record(AuditDraft {
            decision: Decision::Denied,
            verdict: outcome.verdict,
            // Whatever matched, named — an operator reading the entry needs to
            // see the rule that was in play, not a bare synthetic denial.
            rule: outcome.rule,
            facts: summary,
            approval_id: None,
        });
        uninspectable_connect_response(endpoint)
    }

    /// Apply host-level policy (allow / deny / pause) to `host`.
    ///
    /// `audit_allow` records the `Allow` decision — set for the CONNECT gate so
    /// the connection is logged, but not for individual forwarded requests (which
    /// would flood the bounded audit ring).
    async fn host_gate(&self, host: &str, port: u16, audit_allow: bool) -> Gate {
        let facts = self.host_facts(host, port);
        let outcome = decide_explained(&self.state.policy, &facts);
        let summary = FactsSummary::from(&facts);

        match outcome.verdict {
            Verdict::Allow => {
                if audit_allow {
                    self.state.audit.record(AuditDraft {
                        decision: Decision::Allowed,
                        verdict: Verdict::Allow,
                        rule: outcome.rule,
                        facts: summary,
                        approval_id: None,
                    });
                }
                Gate::Proceed
            }
            Verdict::Deny => {
                tracing::info!(domain = %host, rule = ?outcome.rule, "egress denied");
                self.state.audit.record(AuditDraft {
                    decision: Decision::Denied,
                    verdict: Verdict::Deny,
                    rule: outcome.rule,
                    facts: summary,
                    approval_id: None,
                });
                Gate::Block(Box::new(status_response(StatusCode::FORBIDDEN)))
            }
            Verdict::Pause => {
                let approval_summary = connect_summary(host, outcome.rule.as_deref());
                self.hold(host, summary, outcome.rule, approval_summary)
                    .await
            }
        }
    }

    /// Hold a `pause`d request until a human resolves it (or the hold times out).
    /// The client waits the whole time (a CONNECT stays silent until its `200`),
    /// so returning [`Gate::Proceed`] lets it through and [`Gate::Block`] closes it.
    ///
    /// The hold itself lives in [`crate::approval::hold`], shared with the SOCKS5
    /// data path; only the HTTP rendering of the outcome is decided here.
    async fn hold(
        &self,
        host: &str,
        summary: FactsSummary,
        rule: Option<String>,
        approval_summary: String,
    ) -> Gate {
        match hold(&self.state, host, summary, rule, approval_summary).await {
            HoldOutcome::Approved => Gate::Proceed,
            // A hold on this path is only ever abandoned by the caller's future
            // being dropped, which never returns here — but a client that left
            // gets the same answer a rejection does either way.
            HoldOutcome::Rejected | HoldOutcome::Abandoned => {
                Gate::Block(Box::new(status_response(StatusCode::FORBIDDEN)))
            }
            HoldOutcome::QueueFull => {
                Gate::Block(Box::new(status_response(StatusCode::SERVICE_UNAVAILABLE)))
            }
        }
    }

    /// Finalize a policy-approved request for the upstream leg.
    ///
    /// Usually a request, but wire redaction can end the request here: a
    /// body-signed request whose payload would be rewritten is answered with a
    /// local `403` under [`SignedBodyMode::Block`].
    ///
    /// The trailer re-framing [`framed_for_trailers`] applies runs only on
    /// the pass-through outcome, which is why [`redacted_request`] reports which
    /// one it reached rather than returning a bare request: once the rewrite has
    /// replaced the body with `Full`, there is no trailer frame left to carry,
    /// and declaring one would leave the upstream a `Trailer` header naming
    /// fields that never arrive.
    ///
    /// [`redacted_request`]: Self::redacted_request
    fn forwarded_request(
        &self,
        request: Request<Body>,
        input: RedactionInput<'_>,
    ) -> RequestOrResponse {
        let host = input.host.to_owned();
        let retained = input.retained_trailers;
        match self.redacted_request(request, input) {
            Forwarded::PassThrough(request) => framed_for_trailers(request, retained, &host).into(),
            Forwarded::Rewritten(request) => request.into(),
            Forwarded::Blocked(response) => response,
        }
    }

    /// Apply wire redaction to a policy-approved request, reporting whether the
    /// body it carries is still the one the client sent.
    fn redacted_request(&self, mut request: Request<Body>, input: RedactionInput<'_>) -> Forwarded {
        let RedactionInput {
            scanned,
            decoded,
            content_encoding_present,
            content_encoding,
            pii_spans,
            is_json,
            host,
            summary,
            retained_trailers: _,
        } = input;
        let Some(redaction) = &self.state.redaction else {
            return Forwarded::PassThrough(request);
        };

        // Ask upstreams for text we can safely detokenize on the response path.
        // A server may ignore this, in which case handle_response fails open.
        //
        // The negotiation is skipped when *either* predicate holds.
        // `authentication_signs_headers` carries it: some SigV4 signers list
        // `accept-encoding` in `SignedHeaders` even when the payload itself is
        // unsigned (`UNSIGNED-PAYLOAD`), and RFC 9421 / draft-cavage signatures
        // cover whichever headers their component or `headers=` list names.
        // `signature_scheme` is the belt to that braces: every scheme this
        // module recognizes as body-signing also carries the header-signing
        // evidence the first predicate looks for, so it adds nothing today, but
        // a body-signed request is forwarded verbatim under `--signed-body
        // forward` and must keep the `Accept-Encoding` it was signed with even
        // if a future scheme breaks that implication.
        //
        // Over-inclusion here is fail-safe: a compressed response is simply not
        // detokenized, as everywhere else.
        let signature_scheme = body_signature_scheme(request.headers(), request.uri());
        if signature_scheme.is_none()
            && !authentication_signs_headers(request.headers(), request.uri())
        {
            request.headers_mut().insert(
                header::ACCEPT_ENCODING,
                header::HeaderValue::from_static("identity"),
            );
        }

        // A partial upload's Content-Range describes the original body bytes;
        // rewriting the body would desynchronize the declared range from the
        // payload, so fail open and forward the request unmodified.
        if request.headers().contains_key(header::CONTENT_RANGE) {
            tracing::warn!(
                domain = %host,
                "wire redaction bypassed for Content-Range (partial upload) request"
            );
            return Forwarded::PassThrough(request);
        }

        let Some(_raw) = scanned else {
            tracing::warn!(
                domain = %host,
                limit = MAX_INSPECT_BODY,
                "wire redaction bypassed for over-cap request body"
            );
            return Forwarded::PassThrough(request);
        };
        if content_encoding_present && content_encoding.is_none() {
            tracing::warn!(
                domain = %host,
                "wire redaction bypassed because Content-Encoding was not valid text"
            );
            return Forwarded::PassThrough(request);
        }
        let Some(decoded) = decoded else {
            tracing::warn!(
                domain = %host,
                encoding = ?content_encoding,
                "wire redaction bypassed because request encoding was not fully decodable"
            );
            return Forwarded::PassThrough(request);
        };
        // Rewriting a UTF-8 prefix would discard the remaining request bytes.
        // Only a fully decoded, fully valid text body is eligible for rewriting.
        let Ok(text) = std::str::from_utf8(decoded) else {
            tracing::warn!(
                domain = %host,
                "wire redaction bypassed because request body is not valid UTF-8"
            );
            return Forwarded::PassThrough(request);
        };
        let outcome = if is_json {
            let (eligible_spans, skipped_json_spans) = quoted_json_spans(text, pii_spans);
            if skipped_json_spans != 0 {
                tracing::warn!(
                    domain = %host,
                    skipped = skipped_json_spans,
                    "wire redaction skipped unquoted JSON PII to preserve valid syntax"
                );
            }
            redact_json_with_spans(
                text,
                &redaction.salt,
                DEFAULT_MIN_PII_SEVERITY,
                &eligible_spans,
            )
        } else {
            redact_with_spans(text, &redaction.salt, DEFAULT_MIN_PII_SEVERITY, pii_spans)
        };
        if !outcome.redacted {
            return Forwarded::PassThrough(request);
        }

        // Honmoon holds none of the client's signing credentials, so it cannot
        // re-sign a body it rewrote: forwarding the original signature over new
        // bytes only earns an opaque upstream rejection. The decision belongs
        // here, after the outcome is known — a signed request with nothing to
        // redact is forwarded untouched.
        if let Some(scheme) = signature_scheme {
            return match redaction.signed_body {
                SignedBodyMode::Forward => {
                    tracing::warn!(
                        domain = %host,
                        scheme = scheme.label(),
                        "wire redaction bypassed for body-signed request (fail open)"
                    );
                    Forwarded::PassThrough(request)
                }
                SignedBodyMode::Block => {
                    tracing::warn!(
                        domain = %host,
                        scheme = scheme.label(),
                        "body-signed request blocked: wire redaction would invalidate its signature"
                    );
                    self.state.audit.record(AuditDraft {
                        decision: Decision::Denied,
                        verdict: Verdict::Deny,
                        rule: Some("wire-redaction/signed-body".to_owned()),
                        facts: summary.clone(),
                        approval_id: None,
                    });
                    Forwarded::Blocked(signed_body_response(scheme))
                }
            };
        }

        let labels = outcome.labels();
        let bytes = hudsucker::hyper::body::Bytes::from(outcome.text);
        let length = bytes.len();

        // SigV4 and its peers sign *headers* even when the payload is out of
        // the signature (`UNSIGNED-PAYLOAD`), and the rewrite changes headers a
        // `SignedHeaders` list routinely names — an AWS SDK upload signs
        // `content-length`, an S3 upload `content-md5`. Breaking the signature
        // that way earns the same opaque upstream rejection as rewriting a
        // signed body, so it takes the same `--signed-body` decision. Only the
        // headers this rewrite would actually change are asked about: a signed
        // `Content-Encoding` the request never sent, or a signed
        // `Content-Length` the redacted body happens to match, survives it.
        let rewritten = rewritten_headers(request.headers(), length);
        let broken = signed_headers_among(request.headers(), request.uri(), &rewritten);
        if !broken.is_empty() {
            let signed = broken
                .iter()
                .map(header::HeaderName::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            return match redaction.signed_body {
                SignedBodyMode::Forward => {
                    tracing::warn!(
                        domain = %host,
                        headers = %signed,
                        "wire redaction bypassed for header-signed request (fail open)"
                    );
                    Forwarded::PassThrough(request)
                }
                SignedBodyMode::Block => {
                    tracing::warn!(
                        domain = %host,
                        headers = %signed,
                        "header-signed request blocked: replacing the redacted body would \
                         rewrite or drop those headers and invalidate its signature"
                    );
                    self.state.audit.record(AuditDraft {
                        decision: Decision::Denied,
                        verdict: Verdict::Deny,
                        rule: Some("wire-redaction/signed-headers".to_owned()),
                        facts: summary.clone(),
                        approval_id: None,
                    });
                    Forwarded::Blocked(signed_headers_response(&signed))
                }
            };
        }

        redaction.mappings.record(outcome.mapping);
        tracing::info!(
            domain = %host,
            labels = ?labels,
            label_count = labels.len(),
            "request body redacted"
        );

        // `Full` has no trailers, and here that is the point: the rewrite
        // replaces the payload, so any digest the client computed over the
        // original bytes is stale whether it rode in a header or a trailer.
        // Dropping the trailer frame is the same fail-safe choice as stripping
        // `BODY_DIGEST_HEADERS` below.
        *request.body_mut() = Body::from(Full::new(bytes));
        request.headers_mut().insert(
            header::CONTENT_LENGTH,
            header::HeaderValue::from_str(&length.to_string())
                .expect("usize is a valid Content-Length"),
        );
        // The replacement is decoded UTF-8 text, not the client's original
        // compressed representation.
        request.headers_mut().remove(header::CONTENT_ENCODING);
        request.headers_mut().remove(header::TRANSFER_ENCODING);
        for name in BODY_DIGEST_HEADERS {
            request.headers_mut().remove(name);
        }
        Forwarded::Rewritten(request)
    }

    /// Scan a request body for PII. Detect mode audits findings and forwards;
    /// block mode enforces the resulting policy verdict inline.
    ///
    /// **Bodies only.** Everything the scan sees derives from `scanned`, which
    /// is set exclusively from the collected or buffered body bytes. Header and
    /// trailer values are never scanned for PII or secrets and never redacted
    /// (headers *are* read, for framing, decoding and signature metadata — what
    /// never happens is a detector running over them; whether a trailer
    /// is *forwarded* is a separate, conditional matter — `forwarded_request`'s
    /// redaction rewrite drops the frame, and `trailer_filtered_body` drops the
    /// field names RFC 9110 §6.5.1 and RFC 9113 §8.2.2 forbid in a trailer
    /// section, by name and never by value; see ADR-0009) — `facts.pii` stays
    /// empty for them, so no *positive-finding* rule (`pii.count > 0`, a
    /// `pii.types` match) fires on a secret placed in a chunked trailer. An
    /// absence rule still does: the engine binds `pii` with its empty default,
    /// so `pii.count == 0` reads such a request as clean. That is the stated
    /// contract, not
    /// an oversight, and it is silent by design: unlike the over-cap, non-UTF-8,
    /// undecodable-encoding and `Content-Range` cases below, nothing was
    /// attempted, so there is no fail-open `warn` to log. Do not widen the scan
    /// to header-shaped fields without revisiting
    /// `.please/docs/decisions/0009-body-only-inspection-contract.md` — trailers
    /// are visible on the buffered branches only, so such a scan would be
    /// silently absent on the two over-cap ones.
    ///
    /// `port` is the port the client actually dialed (the tunnel's CONNECT port
    /// for an inner request), which is what an `endpoints` entry matches on.
    async fn inspect_body(&self, req: Request<Body>, port: u16) -> RequestOrResponse {
        let method = req.method().clone();
        let host = request_host(&req);
        let path = req.uri().path().to_owned();
        let endpoint = self.resolve_endpoint(&host, port);
        // Only a `kubernetes` endpoint gets k8s facts: this is the one path
        // where the method and path of a Kubernetes API call are in the clear.
        let k8s = endpoint
            .as_ref()
            .filter(|(_, protocol)| *protocol == EndpointProtocol::Kubernetes)
            .map(|_| parse_k8s_request(method.as_str(), &path));

        let content_length = req
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok());

        let is_json = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim)
            .is_some_and(|mime| {
                mime.eq_ignore_ascii_case("application/json")
                    || mime.to_ascii_lowercase().ends_with("+json")
            });
        let content_encoding_present = req.headers().contains_key(header::CONTENT_ENCODING);
        let content_encoding = req
            .headers()
            .get(header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        let (parts, body) = req.into_parts();

        // Buffer small bodies for scanning; stream anything larger than
        // `MAX_INSPECT_BODY` through un-inspected so a large upload can't
        // exhaust memory. Unknown-length bodies (e.g. chunked) are buffered up
        // to the same cap — omitting `Content-Length` must not skip the scan.
        //
        // Both buffered paths rebuild the body with `buffered_body` rather than
        // `Full`, which has no trailers: the client's trailer frame has to reach
        // the upstream leg intact, because a body signature can cover a
        // `Content-Digest` sent there and `--signed-body forward` promises to
        // reproduce the request as signed.
        // `retained` is the trailer field names the forwarded body will still
        // carry, which `framed_for_trailers` has to declare in a `Trailer`
        // header while `parts` is still in hand. Only the two buffered branches
        // can answer: on the over-cap ones the frame is unread and stays that
        // way, so their trailers keep reaching an h1 upstream leg only when the
        // client framed the request to carry them (#136).
        let (new_body, scanned, body_size, retained) = match content_length {
            Some(len) if len <= MAX_INSPECT_BODY => match body.collect().await {
                Ok(collected) => {
                    let trailers = collected.trailers().cloned();
                    let retained = retained_names(trailers.as_ref(), &parts.headers);
                    let bytes = collected.to_bytes();
                    let size = bytes.len() as i64;
                    (
                        buffered_body(bytes.clone(), trailers),
                        Some(bytes),
                        size,
                        retained,
                    )
                }
                // Failing to read the *client's* body is a client-side error.
                Err(_) => return status_response(StatusCode::BAD_REQUEST),
            },
            Some(len) => (body, None, len as i64, Vec::new()),
            None => match buffer_up_to(body, MAX_INSPECT_BODY).await {
                Ok(Buffered::Complete { bytes, trailers }) => {
                    let retained = retained_names(trailers.as_ref(), &parts.headers);
                    let size = bytes.len() as i64;
                    (
                        buffered_body(bytes.clone(), trailers),
                        Some(bytes),
                        size,
                        retained,
                    )
                }
                // Over the cap — forward the buffered prefix plus the rest of
                // the stream untouched, unscanned (same as an over-cap
                // `Content-Length` body).
                Ok(Buffered::Overflow { prefix, rest }) => {
                    (prefixed_body(prefix, rest), None, -1, Vec::new())
                }
                Err(_) => return status_response(StatusCode::BAD_REQUEST),
            },
        };

        // Compressed bodies must not evade the scan: decode supported
        // `Content-Encoding`s before scanning. Only the scan sees the decoded
        // bytes — the original (still-encoded) body is forwarded. Decoded
        // output that overflows the inspection cap is reported as `None`
        // (leaving the body unscanned, like any other over-cap body) so a
        // content verdict is never applied to a truncated prefix.
        let strict_decode = scanned
            .as_deref()
            .map(|raw| decode_strict(content_encoding.as_deref(), raw));
        match strict_decode.as_ref() {
            Some(StrictDecode::Overflow) => tracing::debug!(
                encoding = ?content_encoding,
                "decoded output exceeds inspection cap; leaving body unscanned"
            ),
            Some(StrictDecode::Unavailable) => tracing::debug!(
                encoding = ?content_encoding,
                "content-encoding unavailable for strict decode; scanning raw bytes"
            ),
            Some(StrictDecode::Decoded(_)) | None => {}
        }
        let decoded = strict_decode.as_ref().and_then(|decoded| match decoded {
            StrictDecode::Decoded(bytes) => Some(bytes.as_ref()),
            StrictDecode::Overflow | StrictDecode::Unavailable => None,
        });
        let inspected = match strict_decode.as_ref() {
            Some(StrictDecode::Decoded(bytes)) => Some(bytes.as_ref()),
            Some(StrictDecode::Unavailable) => scanned.as_deref(),
            Some(StrictDecode::Overflow) | None => None,
        };
        let inspected_text = inspected.and_then(utf8_prefix);
        let pii_spans = inspected_text.map(detect_spans).unwrap_or_default();
        let pii = summarize_spans(&pii_spans);
        // Applied to every branch above at the one point they converge, so the
        // two streaming branches — whose trailers honmoon never holds as a
        // `HeaderMap` — are filtered on the same rule as the buffered ones
        // (#134). `parts.headers` is read here rather than later because the
        // request's `Connection` nominations have to be resolved while the
        // header section is still in hand.
        let filtered = trailer_filtered_body(new_body, &parts.headers, &host);
        let forwarded = Request::from_parts(parts, filtered);

        // An oversized, over-cap-decoded, or non-text body was not inspected,
        // but the policy engine still runs so HTTP-metadata rules (method,
        // path, host, body_size) cannot be bypassed by an uninspectable body.
        // `pii` stays `None` — the engine binds the empty default, so unscanned
        // content never satisfies a `pii.count > 0` condition (the same
        // forwarding outcome as skipping evaluation) and the `count > 0` audit
        // gates below keep these forwards quiet.
        let facts = Facts {
            domain: Some(host.clone()),
            endpoint: endpoint.map(|(name, _)| name),
            http: Some(HttpFacts {
                method: method.as_str().to_owned(),
                host: host.clone(),
                path: path.clone(),
                body_size,
            }),
            k8s,
            pii: pii.clone(),
            ..Default::default()
        };
        let outcome = decide_explained(&self.state.policy, &facts);
        let summary = FactsSummary::from(&facts);

        // Detect mode holds back the verdicts PII *caused*, which
        // `decide_pii_audit_only` attributes per rule: the rule that fired only
        // because of the summary is skipped and the rest of the policy still
        // decides, so an endpoint/Kubernetes or HTTP-metadata deny is enforced
        // in every mode. Detect-only is a promise about the PII scanner, not a
        // bypass for the rest of the policy — including when an earlier
        // `pii.count == 0 -> allow` rule would have matched on a clean body.
        // Holding a verdict back is not the same as downgrading it: continuing
        // the walk can reach a stricter rule the first match had shadowed (see
        // the note on `decide_pii_audit_only`). A real outcome of `Allow` needs
        // no second pass — the audit-only walk holds nothing back before a rule
        // (or the egress lists) has decided `Allow`.
        let enforced = match self.state.pii_mode {
            PiiMode::Block => Some(outcome.clone()),
            PiiMode::Detect if outcome.verdict != Verdict::Allow => {
                let enforceable = decide_pii_audit_only(&self.state.policy, &facts);
                (enforceable.verdict != Verdict::Allow).then_some(enforceable)
            }
            PiiMode::Detect => None,
        };

        let Some(outcome) = enforced else {
            // Keep the detect-only default quiet for clean traffic: only actual
            // findings produce the would-be verdict audit event.
            if let Some(pii) = pii.filter(|p| p.count > 0) {
                tracing::info!(
                    domain = %host,
                    pii_types = ?pii.types,
                    pii_count = pii.count,
                    would_be = ?outcome.verdict,
                    "pii detected (detect-only)"
                );
                self.state.audit.record(AuditDraft {
                    decision: Decision::Allowed,
                    verdict: outcome.verdict,
                    rule: outcome.rule,
                    facts: summary.clone(),
                    approval_id: None,
                });
            }
            return self.forwarded_request(
                forwarded,
                RedactionInput {
                    scanned: scanned.as_deref(),
                    decoded,
                    content_encoding_present,
                    content_encoding: content_encoding.as_deref(),
                    pii_spans: &pii_spans,
                    is_json,
                    host: &host,
                    summary: &summary,
                    retained_trailers: &retained,
                },
            );
        };

        match outcome.verdict {
            Verdict::Allow => {
                // Keep block mode as quiet as detect mode for clean traffic:
                // only actual PII findings are audited. Recording every clean
                // Allow would flood the bounded audit ring and cycle out the
                // Deny/Pause records that matter (see `host_gate`'s
                // `audit_allow`).
                if pii.as_ref().is_some_and(|p| p.count > 0) {
                    self.state.audit.record(AuditDraft {
                        decision: Decision::Allowed,
                        verdict: Verdict::Allow,
                        rule: outcome.rule,
                        facts: summary.clone(),
                        approval_id: None,
                    });
                }
                self.forwarded_request(
                    forwarded,
                    RedactionInput {
                        scanned: scanned.as_deref(),
                        decoded,
                        content_encoding_present,
                        content_encoding: content_encoding.as_deref(),
                        pii_spans: &pii_spans,
                        is_json,
                        host: &host,
                        summary: &summary,
                        retained_trailers: &retained,
                    },
                )
            }
            Verdict::Deny => {
                tracing::info!(domain = %host, rule = ?outcome.rule, "request denied by content policy");
                self.state.audit.record(AuditDraft {
                    decision: Decision::Denied,
                    verdict: Verdict::Deny,
                    rule: outcome.rule,
                    facts: summary,
                    approval_id: None,
                });
                status_response(StatusCode::FORBIDDEN)
            }
            Verdict::Pause => {
                let approval_summary = pii_summary(
                    method.as_str(),
                    &path,
                    &host,
                    facts.pii.as_ref(),
                    outcome.rule.as_deref(),
                );
                match self
                    .hold(&host, summary.clone(), outcome.rule, approval_summary)
                    .await
                {
                    Gate::Proceed => self.forwarded_request(
                        forwarded,
                        RedactionInput {
                            scanned: scanned.as_deref(),
                            decoded,
                            content_encoding_present,
                            content_encoding: content_encoding.as_deref(),
                            pii_spans: &pii_spans,
                            is_json,
                            host: &host,
                            summary: &summary,
                            retained_trailers: &retained,
                        },
                    ),
                    Gate::Block(response) => *response,
                }
            }
        }
    }
}

impl HttpHandler for HonmoonHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        if req.method() == Method::CONNECT {
            let authority = req.uri().authority().map(|a| a.as_str()).unwrap_or("");
            let host = canonical_host(authority);
            let port = authority_port(authority).unwrap_or(HTTPS_PORT);
            // An endpoint this listener cannot inspect takes its own path, which
            // still runs the policy — but never authorizes (or audits as
            // allowed) a tunnel that would carry its frames uninspected.
            if let Some(endpoint) = self.uninspectable_endpoint(&host, port) {
                return self.refuse_uninspectable_connect(&host, port, &endpoint);
            }
            return match self.host_gate(&host, port, true).await {
                Gate::Proceed => {
                    self.authorize_tunnel(host, port);
                    req.into()
                }
                Gate::Block(res) => *res,
            };
        }

        // A decrypted inner request (injected by hudsucker after TLS
        // termination) was already authorized at its CONNECT — inspect only. It
        // is recognized by the tunnel this handler clone inherited, *not* by the
        // URI scheme: an absolute-form `https://` request sent without CONNECT
        // must be host-gated like a cleartext `http://` one, or the egress
        // allowlist could be bypassed.
        // hudsucker stamps the CONNECT authority — host *and* port — onto every
        // HTTP/1.x inner request, so a genuine tunnelled request carries its
        // real destination and matches by construction. An h2 request keeps the
        // client's own `:authority`, which is where hudsucker will actually
        // forward it, so anything that does not match the tunnel is gated on the
        // destination it names.
        let host = request_host(&req);
        let port = request_port(&req);
        if !self.tunnel_authorizes(&host, port)
            && let Gate::Block(res) = self.host_gate(&host, port, false).await
        {
            return *res;
        }

        self.inspect_body(req, port).await
    }

    async fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        mut res: Response<Body>,
    ) -> Response<Body> {
        let Some(redaction) = &self.state.redaction else {
            return res;
        };
        // 1xx/204/304 responses carry no body (RFC 9110), while rewriting a
        // 206 body would invalidate its byte-range semantics.
        if res.status().is_informational()
            || res.status() == StatusCode::NO_CONTENT
            || res.status() == StatusCode::PARTIAL_CONTENT
            || res.status() == StatusCode::NOT_MODIFIED
        {
            return res;
        }
        // A non-identity response is forwarded verbatim regardless of what we've
        // minted, so make this cheap header check before touching the mapping
        // mutex.
        let identity_encoded = res
            .headers()
            .get(header::CONTENT_ENCODING)
            .map(|value| {
                value.to_str().ok().is_some_and(|value| {
                    value.trim().is_empty() || value.trim().eq_ignore_ascii_case("identity")
                })
            })
            .unwrap_or(true);
        if !identity_encoded {
            tracing::warn!(
                encoding = ?res.headers().get(header::CONTENT_ENCODING),
                "response detokenization bypassed because Content-Encoding is not identity"
            );
            return res;
        }

        // handle_request records this request's mapping before the upstream leg,
        // so this point-in-time snapshot always includes its substitutions. Take
        // it under a single lock, then skip when nothing has been minted yet;
        // snapshotting also avoids holding the MappingStore mutex while the body
        // is polled.
        let mapping = redaction.mappings.snapshot();
        if mapping.is_empty() {
            return res;
        }
        let body = std::mem::replace(res.body_mut(), Body::empty());
        *res.body_mut() = detokenizing_body(body, mapping);
        // Detokenization changes byte length; let hyper frame the streamed body.
        res.headers_mut().remove(header::CONTENT_LENGTH);
        res.headers_mut().remove(header::CONTENT_RANGE);
        // A strong ETag validates the origin bytes, not the detokenized ones we
        // deliver; leaving it would let a cache or range revalidation serve or
        // stitch stale content, so drop it with the other body validators.
        res.headers_mut().remove(header::ETAG);
        for name in BODY_DIGEST_HEADERS {
            res.headers_mut().remove(name);
        }
        res
    }

    async fn should_intercept(&mut self, _ctx: &HttpContext, req: &Request<Body>) -> bool {
        match &self.state.intercept {
            InterceptPolicy::None => false,
            InterceptPolicy::All => true,
            InterceptPolicy::Hosts(hosts) => {
                let host = canonical_host(req.uri().authority().map(|a| a.as_str()).unwrap_or(""));
                hosts.contains(&host)
            }
        }
    }
}

/// A JSON PII span whose UTF-16 start was resolved to an exact byte boundary
/// while the parser was inside a quoted string.
struct QuotedJsonSpan<'a> {
    span: &'a PiiSpan,
    byte_start: usize,
    byte_end: usize,
}

/// Incremental scanner that walks a UTF-8 JSON body by UTF-16 offset while
/// tracking whether the cursor sits inside a quoted string, so a PII span can be
/// classified as quoted or unquoted in one forward pass.
struct JsonLexer<'a> {
    chars: std::str::CharIndices<'a>,
    byte_offset: usize,
    utf16_offset: i64,
    in_string: bool,
    escaped: bool,
}

impl<'a> JsonLexer<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            chars: text.char_indices(),
            byte_offset: 0,
            utf16_offset: 0,
            in_string: false,
            escaped: false,
        }
    }

    /// Consume characters until the cursor reaches `target` (a UTF-16 offset) or
    /// the input ends, folding each into the quoted-string tracking state.
    fn advance_to(&mut self, target: i64) {
        while self.utf16_offset < target {
            let Some((byte, ch)) = self.chars.next() else {
                break;
            };
            self.byte_offset = byte + ch.len_utf8();
            self.utf16_offset += ch.len_utf16() as i64;
            self.track_string_state(ch);
        }
    }

    /// Update `in_string`/`escaped` for one consumed character.
    fn track_string_state(&mut self, ch: char) {
        if self.in_string && self.escaped {
            self.escaped = false;
        } else if self.in_string && ch == '\\' {
            self.escaped = true;
        } else if ch == '"' {
            self.in_string = !self.in_string;
        }
    }
}

/// Classify PII spans in one forward pass over the JSON text. A malformed
/// offset, including one inside a multi-unit character or past the body, is
/// skipped in the safe direction.
fn quoted_json_spans<'a>(text: &str, spans: &'a [PiiSpan]) -> (Vec<QuotedJsonSpan<'a>>, usize) {
    let mut sorted = spans.iter().collect::<Vec<_>>();
    sorted.sort_by_key(|span| span.start);

    let mut lexer = JsonLexer::new(text);
    let mut eligible = Vec::with_capacity(spans.len());

    for span in sorted {
        lexer.advance_to(span.start);

        if lexer.utf16_offset != span.start || !lexer.in_string {
            continue;
        }
        let byte_start = lexer.byte_offset;
        let byte_end = byte_start.saturating_add(span.text.len());
        let exact_surface = text
            .get(byte_start..byte_end)
            .is_some_and(|surface| surface == span.text)
            && span.end - span.start == span.text.encode_utf16().count() as i64;
        if exact_surface {
            eligible.push(QuotedJsonSpan {
                span,
                byte_start,
                byte_end,
            });
        }
    }

    let skipped = spans.len() - eligible.len();
    (eligible, skipped)
}

/// Redact JSON PII at the exact eligible occurrences while retaining the core
/// tokenizer's global matching behavior for machine-secret findings.
fn redact_json_with_spans(
    text: &str,
    salt: &[u8],
    min_pii_severity: i64,
    pii_spans: &[QuotedJsonSpan<'_>],
) -> RedactionOutcome {
    let secret_findings = detect_secrets(text);
    let mut surfaces = Vec::new();
    let mut surface_indices = HashMap::new();
    let mut secret_surface_indices = Vec::new();
    let mut secret_labels = BTreeSet::new();
    for finding in &secret_findings {
        secret_labels.insert(finding.label.clone());
        if !surface_indices.contains_key(&finding.text) {
            let surface_index = surfaces.len();
            surface_indices.insert(finding.text.clone(), surface_index);
            surfaces.push(finding.text.clone());
            secret_surface_indices.push(surface_index);
        }
    }

    let mut pii_labels = BTreeSet::new();
    let mut max_pii_severity = 0;
    for eligible in pii_spans {
        let severity = severity_for_label(&eligible.span.label);
        if severity < min_pii_severity {
            continue;
        }
        pii_labels.insert(eligible.span.label.clone());
        max_pii_severity = max_pii_severity.max(severity);
        if !surface_indices.contains_key(&eligible.span.text) {
            surface_indices.insert(eligible.span.text.clone(), surfaces.len());
            surfaces.push(eligible.span.text.clone());
        }
    }

    if surfaces.is_empty() {
        return RedactionOutcome {
            text: text.to_owned(),
            redacted: false,
            secret_labels: secret_labels.into_iter().collect(),
            pii_labels: pii_labels.into_iter().collect(),
            max_pii_severity,
            mapping: Mapping::new(),
        };
    }

    let tokenizer = SecretTokenizer::new(salt.to_vec(), surfaces.clone());
    let mut candidates = Vec::new();
    for surface_index in secret_surface_indices {
        let surface = &surfaces[surface_index];
        candidates.extend(
            text.match_indices(surface)
                .map(|(start, surface)| (start, start + surface.len(), surface_index)),
        );
    }
    for eligible in pii_spans {
        if severity_for_label(&eligible.span.label) >= min_pii_severity {
            candidates.push((
                eligible.byte_start,
                eligible.byte_end,
                surface_indices[&eligible.span.text],
            ));
        }
    }
    candidates.sort_unstable_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| (right.1 - right.0).cmp(&(left.1 - left.0)))
            .then_with(|| left.2.cmp(&right.2))
    });

    let mut output = String::with_capacity(text.len());
    let mut mapping = Mapping::new();
    let mut last_end = 0;
    for (start, end, surface_index) in candidates {
        if start < last_end {
            continue;
        }
        output.push_str(&text[last_end..start]);
        let surface = &surfaces[surface_index];
        let placeholder = tokenizer
            .placeholder_for(surface)
            .expect("registered surface has a placeholder");
        output.push_str(placeholder);
        mapping.insert(placeholder.to_owned(), surface.clone());
        last_end = end;
    }
    output.push_str(&text[last_end..]);

    RedactionOutcome {
        redacted: !mapping.is_empty(),
        text: output,
        secret_labels: secret_labels.into_iter().collect(),
        pii_labels: pii_labels.into_iter().collect(),
        max_pii_severity,
        mapping,
    }
}

/// A `403` explaining that redaction cannot rewrite a request whose signature
/// covers headers the rewrite has to change — the header-signed counterpart of
/// [`signed_body_response`].
fn signed_headers_response(signed: &str) -> RequestOrResponse {
    let reason = format!(
        "honmoon: this request's signature covers {signed}, and wire redaction would rewrite or \
         drop those headers when it replaces the redacted body; the upstream would reject the \
         forwarded request. Remove the sensitive value, or run the gateway with --signed-body \
         forward to send it unredacted.\n"
    );
    let length = reason.len();
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CONTENT_LENGTH, length.to_string())
        .header(HONMOON_REASON, "signed-header-redaction")
        .header(header::CONNECTION, "close")
        .body(Body::from(Full::new(hudsucker::hyper::body::Bytes::from(
            reason,
        ))))
        .expect("static response is valid")
        .into()
}

/// Every header replacing the body with `new_length` bytes of redacted text
/// would change on the wire: the framing headers [`reframed_headers`] re-frames,
/// plus the [`BODY_DIGEST_HEADERS`] the strip loop removes as stale validators
/// of the old bytes.
///
/// This is the decision input, not the strip list — the two stay deliberately
/// distinct. The rewrite strips every `BODY_DIGEST_HEADERS` name unconditionally,
/// because removing one the request never sent costs nothing; asking whether a
/// *signature* covers an absent header would cost a `403`, since no signature is
/// broken by stripping a header that was never there.
fn rewritten_headers(headers: &header::HeaderMap, new_length: usize) -> Vec<header::HeaderName> {
    let mut rewritten = reframed_headers(headers, new_length);
    rewritten.extend(
        BODY_DIGEST_HEADERS
            .into_iter()
            .filter(|name| headers.contains_key(name)),
    );
    rewritten
}

/// Which of [`REWRITTEN_FRAMING_HEADERS`] replacing the body with `new_length`
/// bytes of identity-encoded text would actually change on the wire.
///
/// `Content-Encoding` and `Transfer-Encoding` are only dropped when the request
/// carries them, and `Content-Length` is only re-framed when what the rewrite
/// will send differs from what the client sent — a signature over a header the
/// rewrite leaves as it found it is not broken by the rewrite.
fn reframed_headers(headers: &header::HeaderMap, new_length: usize) -> Vec<header::HeaderName> {
    REWRITTEN_FRAMING_HEADERS
        .into_iter()
        .filter(|name| {
            if *name == header::CONTENT_LENGTH {
                !content_length_survives_rewrite(headers, new_length)
            } else {
                headers.contains_key(name)
            }
        })
        .collect()
}

/// Re-frame a pass-through request so the trailer section it carries
/// survives an HTTP/1.1 upstream leg (#136).
///
/// **Why honmoon has to write framing headers it was not asked for.**
/// hyper's h1 encoder writes a request's trailer section only when both
/// conditions hold: the encoder is `Kind::Chunked(Some(fields))`, and each
/// field is named in the request's `Trailer` header. A fixed-length request
/// takes the `_` arm of `Encoder::encode_trailers`
/// (`hyper-1.10.1/src/proto/h1/encode.rs:212-215`) and a chunked one with no
/// `Trailer` header takes `Kind::Chunked(None)` (`:208-211`); both log at
/// `debug` and drop the frame. HTTP/2 imposes neither requirement, so an h2
/// client legitimately sends trailers alongside a `content-length` and
/// without a `Trailer` header, and honmoon's own buffering re-declares a
/// length even when the client sent none (`BufferedBody`'s `size_hint` is
/// exact, which is what `set_length` turns into a `Content-Length`). Every
/// one of those reaches an h1 upstream a trailer short, silently.
///
/// **Why it is safe to write them without knowing the upstream protocol.**
/// honmoon cannot know: ALPN is negotiated inside `hyper_util`'s connection
/// pool, after `handle_request` has returned. It does not have to. The two
/// headers are reconciled per-protocol by hyper itself — an h1 leg drops
/// `Content-Length` once `Transfer-Encoding` is present
/// (`role.rs:1424-1427`), and an h2 leg drops `Transfer-Encoding` as a
/// connection-specific field (`strip_connection_headers`,
/// `proto/h2/mod.rs:43`) and keeps the `Content-Length`, which is the h2
/// behavior that already worked. So the request carries both names out of
/// here and exactly one of them onto the wire.
///
/// **Why it can be declined.** `Content-Length`, `Transfer-Encoding` and
/// `Trailer` are [`TRAILER_FRAMING_HEADERS`], and a signature routinely
/// covers the first two — an AWS SDK upload signs `content-length`, and an
/// RFC 9421 or draft-cavage component list covers whatever it names. Re-framing
/// such a request to rescue its trailer would trade one signature failure for
/// another, on the path whose contract is to forward the bytes the client
/// signed (ADR-0006). So the re-frame happens only when it breaks nothing;
/// otherwise the request goes on untouched and the loss is logged, which is
/// the same fail-open shape as the other bypasses in this module.
///
/// Declining here is **not** routed through `--signed-body`: that flag
/// decides what to do about a body honmoon *rewrote*, and honmoon rewrites
/// nothing here — declining leaves the request byte-identical to what the
/// client signed, which is already what `forward` promises. It also lives on
/// `RedactionState`, so routing through it would make trailer framing depend
/// on whether secret redaction happens to be enabled. Whether honmoon should
/// instead refuse a request whose signed trailer it cannot carry is an open
/// product question, not a settled one: issue 178 states the case for
/// refusing and the three reasons this does not.
fn framed_for_trailers(
    mut request: Request<Body>,
    retained: &[header::HeaderName],
    host: &str,
) -> Request<Body> {
    if retained.is_empty() {
        return request;
    }
    let chunked = transfer_encoding_is_chunked(request.headers());
    let undeclared: Vec<&header::HeaderName> = retained
        .iter()
        .filter(|name| !declares_trailer(request.headers(), name))
        .collect();

    let mut reframed: Vec<header::HeaderName> = Vec::new();
    if !chunked {
        // Only ours to account for while *we* are the ones selecting the
        // chunked encoder: on a request the client already framed as
        // chunked, hyper drops any `Content-Length` regardless of what
        // honmoon does with it.
        if request.headers().contains_key(header::CONTENT_LENGTH) {
            reframed.push(header::CONTENT_LENGTH);
        }
        reframed.push(header::TRANSFER_ENCODING);
    }
    if !undeclared.is_empty() {
        reframed.push(header::TRAILER);
    }
    debug_assert!(
        reframed
            .iter()
            .all(|name| TRAILER_FRAMING_HEADERS.contains(name)),
        "the re-frame must only touch the headers it asks about"
    );
    if reframed.is_empty() {
        // Already chunked, already declared: the client framed a request
        // hyper will carry as it stands.
        return request;
    }

    let broken = signed_headers_among(request.headers(), request.uri(), &reframed);
    if !broken.is_empty() {
        tracing::warn!(
            domain = %host,
            headers = %join_names(&broken),
            trailers = %join_names(retained),
            "trailer re-framing bypassed for a signed request: its trailer section will not \
             reach an HTTP/1.1 upstream leg (fail open)"
        );
        return request;
    }

    if !chunked {
        // Appended rather than inserted: a `Transfer-Encoding` the client
        // already sent is a codec list this re-frame has no business
        // rewriting, and `chunked` last is what both the RFC and hyper's
        // `is_chunked` require.
        request.headers_mut().append(
            header::TRANSFER_ENCODING,
            header::HeaderValue::from_static("chunked"),
        );
    }
    if !undeclared.is_empty() {
        let declared = join_names(undeclared.iter().copied());
        request.headers_mut().append(
            header::TRAILER,
            header::HeaderValue::from_str(&declared)
                .expect("header names are valid header-value bytes"),
        );
    }
    tracing::debug!(
        domain = %host,
        trailers = %join_names(retained),
        "re-framed request as chunked so its trailer section survives an HTTP/1.1 upstream leg"
    );
    request
}

/// The trailer field names a forwarded body will still carry, or none when the
/// branch never held the frame.
fn retained_names(
    trailers: Option<&header::HeaderMap>,
    headers: &header::HeaderMap,
) -> Vec<header::HeaderName> {
    trailers.map_or_else(Vec::new, |trailers| {
        retained_trailer_names(trailers, headers)
    })
}

/// Whether hyper's h1 encoder will read this request as chunked — the last
/// `Transfer-Encoding` token is `chunked`.
///
/// Mirrors `headers::is_chunked` (`hyper-1.10.1/src/proto/h1/headers.rs`), which
/// is what actually selects the encoder: the last value of the last field line,
/// because the RFC requires `chunked` to come last.
fn transfer_encoding_is_chunked(headers: &header::HeaderMap) -> bool {
    headers
        .get_all(header::TRANSFER_ENCODING)
        .iter()
        .next_back()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit(',').next())
        .is_some_and(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"))
}

/// Whether the request's `Trailer` header already names `name`, parsed exactly
/// as hyper parses it to build the encoder's allowlist
/// (`hyper-1.10.1/src/proto/h1/role.rs:1406-1413`): every field value, split on
/// commas, trimmed, each read as a `HeaderName`.
fn declares_trailer(headers: &header::HeaderMap, name: &header::HeaderName) -> bool {
    headers
        .get_all(header::TRAILER)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|declared| header::HeaderName::from_bytes(declared.trim().as_bytes()).ok())
        .any(|declared| declared == *name)
}

/// Header names as one comma-separated string, for a log field.
fn join_names<'a>(names: impl IntoIterator<Item = &'a header::HeaderName>) -> String {
    names
        .into_iter()
        .map(header::HeaderName::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Whether the `Content-Length` the rewrite inserts is byte-identical to the
/// one the client sent — the only case where a signature over that header
/// survives.
///
/// The comparison is on the wire bytes, not on a parsed length: the rewrite
/// writes the canonical `new_length.to_string()`, so a non-canonical `012` or
/// `+12` that parses to the same number is still a different value than the
/// one the client signed. Absent, repeated, or non-canonical values all count
/// as changed, which is the fail-closed reading.
fn content_length_survives_rewrite(headers: &header::HeaderMap, new_length: usize) -> bool {
    let mut values = headers.get_all(header::CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    value.as_bytes() == new_length.to_string().as_bytes()
}

/// A `403` explaining that redaction cannot rewrite a body-signed request, so
/// the operator sees an actionable local failure instead of an opaque upstream
/// signature rejection.
fn signed_body_response(scheme: SignedBodyScheme) -> RequestOrResponse {
    let reason = format!(
        "honmoon: request body is covered by {} and contains data that wire redaction would \
         rewrite; the upstream would reject the re-signed body. Remove the sensitive value, or \
         run the gateway with --signed-body forward to send it unredacted.\n",
        scheme.description()
    );
    let length = reason.len();
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CONTENT_LENGTH, length.to_string())
        .header(HONMOON_REASON, "signed-body-redaction")
        .header(header::CONNECTION, "close")
        .body(Body::from(Full::new(hudsucker::hyper::body::Bytes::from(
            reason,
        ))))
        .expect("static response is valid")
        .into()
}

/// A `403` explaining that this endpoint is inspected inline, so it must be
/// dialled through the SOCKS5 listener rather than tunnelled over CONNECT.
fn uninspectable_connect_response(endpoint: &str) -> RequestOrResponse {
    // The listener's address is a CLI flag the data plane never receives, and
    // `--socks-addr off` disables it entirely — so the message names the flag
    // rather than inventing a port that may not be listening.
    let reason = format!(
        "honmoon: endpoint {endpoint} is declared `protocol: postgres`, so its statements are \
         inspected inline and it cannot be carried over a CONNECT tunnel. Dial it through the \
         gateway's SOCKS5 listener instead (ALL_PROXY=socks5h://<the gateway's --socks-addr>); \
         if the gateway was started with `--socks-addr off` there is no such listener and this \
         endpoint is unreachable.\n"
    );
    let length = reason.len();
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CONTENT_LENGTH, length.to_string())
        .header(HONMOON_REASON, "uninspectable-connect")
        .header(header::CONNECTION, "close")
        .body(Body::from(Full::new(hudsucker::hyper::body::Bytes::from(
            reason,
        ))))
        .expect("static response is valid")
        .into()
}

/// A `Content-Length: 0` response with the given status.
fn status_response(status: StatusCode) -> RequestOrResponse {
    Response::builder()
        .status(status)
        .header(header::CONTENT_LENGTH, "0")
        .header(header::CONNECTION, "close")
        .body(Body::empty())
        .expect("static response is valid")
        .into()
}

/// A short human description of a held request, for the approval queue.
fn connect_summary(host: &str, rule: Option<&str>) -> String {
    match rule {
        Some(r) => format!("CONNECT {host} (rule: {r})"),
        None => format!("CONNECT {host}"),
    }
}

/// A PII-safe summary of a held body request. It names only labels/count, never
/// matched text, so the approval queue cannot become a second PII leak.
fn pii_summary(
    method: &str,
    path: &str,
    host: &str,
    pii: Option<&PiiFacts>,
    rule: Option<&str>,
) -> String {
    let (types, count) = match pii {
        Some(pii) => (pii.types.join(","), pii.count),
        None => ("none".to_owned(), 0),
    };
    match rule {
        Some(rule) => {
            format!("{method} {host}{path}: PII [{types}] ({count} finding(s), rule: {rule})")
        }
        None => format!("{method} {host}{path}: PII [{types}] ({count} finding(s))"),
    }
}

/// The canonicalized destination host of a request: the URI authority when
/// present (absolute-form / h2), else the `Host` header (origin-form requests
/// like `POST /submit` carry their destination only there).
fn request_host(req: &Request<Body>) -> String {
    if let Some(host) = req.uri().host() {
        return host.trim_end_matches('.').to_ascii_lowercase();
    }
    req.headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(canonical_host)
        .unwrap_or_default()
}

/// The port a non-CONNECT request targets, resolved with the same precedence as
/// [`request_host`]: the URI authority when it carries one, else the `Host`
/// header (origin-form requests only), else the scheme default.
///
/// The `Host` header is client-controlled, so it is only consulted when the URI
/// has no authority of its own. Otherwise a client could pair a real URI host
/// with a fabricated `Host: other:5432` port and have the request resolve to an
/// `endpoints` entry it never dialed.
fn request_port(req: &Request<Body>) -> u16 {
    req.uri()
        .port_u16()
        .or_else(|| {
            if req.uri().host().is_some() {
                return None;
            }
            req.headers()
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
                .and_then(authority_port)
        })
        .unwrap_or(match req.uri().scheme_str() {
            Some("https") => HTTPS_PORT,
            _ => HTTP_PORT,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).expect("gzip write");
        enc.finish().expect("gzip finish")
    }

    #[test]
    fn json_span_classification_rejects_mid_character_and_past_end_offsets() {
        let text = r#"{"note":"😀user@example.com"}"#;
        let detected = detect_spans(text);
        assert_eq!(quoted_json_spans(text, &detected).0.len(), 1);

        let mut mid_character = detected[0].clone();
        mid_character.start -= 1;
        let mut past_end = detected[0].clone();
        past_end.start = 10_000;
        past_end.end = 10_000 + past_end.text.encode_utf16().count() as i64;

        let malformed = [mid_character, past_end];
        let (eligible, skipped) = quoted_json_spans(text, &malformed);
        assert!(eligible.is_empty());
        assert_eq!(skipped, 2);
    }

    /// The rewrite only breaks a signature over a framing header it actually
    /// changes, so only those may take the `--signed-body` decision.
    #[test]
    fn only_the_framing_headers_the_rewrite_changes_are_reframed() {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::CONTENT_LENGTH, "12".parse().expect("length"));
        assert!(
            reframed_headers(&headers, 12).is_empty(),
            "a redacted body of the same size re-frames nothing"
        );
        assert_eq!(reframed_headers(&headers, 20), [header::CONTENT_LENGTH]);

        headers.insert(header::CONTENT_ENCODING, "gzip".parse().expect("encoding"));
        assert_eq!(
            reframed_headers(&headers, 12),
            [header::CONTENT_ENCODING],
            "a Content-Encoding the request carries is always dropped"
        );

        // A chunked request declares no length, so the Content-Length the
        // rewrite adds is a change from what the client sent.
        let mut chunked = header::HeaderMap::new();
        chunked.insert(header::TRANSFER_ENCODING, "chunked".parse().expect("te"));
        assert_eq!(
            reframed_headers(&chunked, 12),
            [header::CONTENT_LENGTH, header::TRANSFER_ENCODING]
        );

        // The rewrite writes the canonical decimal, so a non-canonical value
        // that parses to the same number is still replaced on the wire — and a
        // repeated Content-Length is not a value the rewrite preserves either.
        let mut non_canonical = header::HeaderMap::new();
        non_canonical.insert(header::CONTENT_LENGTH, "012".parse().expect("length"));
        assert_eq!(
            reframed_headers(&non_canonical, 12),
            [header::CONTENT_LENGTH],
            "a leading-zero length the rewrite rewrites to `12` is not preserved"
        );

        let mut repeated = header::HeaderMap::new();
        repeated.append(header::CONTENT_LENGTH, "12".parse().expect("length"));
        repeated.append(header::CONTENT_LENGTH, "12".parse().expect("length"));
        assert_eq!(reframed_headers(&repeated, 12), [header::CONTENT_LENGTH]);
    }

    /// The rewrite strips the body-digest validators as well as re-framing, so
    /// they belong in the decision — but only the ones the request carries: a
    /// signature naming a digest header the client never sent is not broken by
    /// a strip that removes nothing.
    #[test]
    fn carried_body_digest_headers_join_the_reframed_ones() {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::CONTENT_LENGTH, "12".parse().expect("length"));
        assert!(
            rewritten_headers(&headers, 12).is_empty(),
            "a same-size redaction with no digest header changes nothing"
        );

        headers.insert(
            header::HeaderName::from_static("content-md5"),
            "stale".parse().expect("digest"),
        );
        assert_eq!(
            rewritten_headers(&headers, 12),
            [header::HeaderName::from_static("content-md5")],
            "a carried digest header is stripped even when nothing is re-framed"
        );
        assert_eq!(
            rewritten_headers(&headers, 20),
            [
                header::CONTENT_LENGTH,
                header::HeaderName::from_static("content-md5")
            ]
        );

        // Reads from the constant the strip loop itself iterates, so a
        // validator added there is covered here without editing this test.
        let mut every = header::HeaderMap::new();
        every.insert(header::CONTENT_LENGTH, "12".parse().expect("length"));
        for name in BODY_DIGEST_HEADERS {
            every.insert(name, "stale".parse().expect("digest"));
        }
        assert_eq!(rewritten_headers(&every, 12), BODY_DIGEST_HEADERS);
    }

    #[test]
    fn request_port_falls_back_to_the_scheme_default() {
        let with_authority_port = Request::builder()
            .uri("https://k8s.internal:6443/api/v1/pods")
            .body(Body::empty())
            .expect("build request");
        assert_eq!(request_port(&with_authority_port), 6443);

        let with_host_header = Request::builder()
            .uri("/api/v1/pods")
            .header(header::HOST, "k8s.internal:6443")
            .body(Body::empty())
            .expect("build request");
        assert_eq!(request_port(&with_host_header), 6443);

        let https_no_port = Request::builder()
            .uri("https://k8s.internal/api/v1/pods")
            .body(Body::empty())
            .expect("build request");
        assert_eq!(request_port(&https_no_port), HTTPS_PORT);

        let cleartext_no_port = Request::builder()
            .uri("http://k8s.internal/api/v1/pods")
            .body(Body::empty())
            .expect("build request");
        assert_eq!(request_port(&cleartext_no_port), HTTP_PORT);

        // A client-supplied `Host` port must not override a URI that already
        // carries its own authority — pairing a real host with a fabricated
        // port would resolve an `endpoints` entry the client never dialed.
        let spoofed_host_header = Request::builder()
            .uri("http://k8s.internal/api/v1/pods")
            .header(header::HOST, "k8s.internal:6443")
            .body(Body::empty())
            .expect("build request");
        assert_eq!(request_port(&spoofed_host_header), HTTP_PORT);
    }

    /// A handler prototype, as [`hudsucker::Proxy`] holds it before cloning one
    /// per connection.
    fn handler_prototype() -> HonmoonHandler {
        let policy =
            honmoon_core::Policy::from_yaml("egress:\n  default: allow\n").expect("policy");
        HonmoonHandler::new(GatewayState::new(policy))
    }

    #[test]
    fn tunnel_authorization_requires_the_port_to_match_too() {
        // hudsucker forwards an h2 request to the `:authority` it names, so a
        // tunnel to :443 must not lend its authorization to a request naming
        // :6443 — that would evaluate the request at 443, resolve no endpoint,
        // parse no `k8s` facts, and still reach the API server on 6443.
        let mut tunnel = handler_prototype();
        tunnel.authorize_tunnel("cluster.example".to_owned(), HTTPS_PORT);

        assert!(
            tunnel.tunnel_authorizes("cluster.example", HTTPS_PORT),
            "the CONNECT target itself stays authorized"
        );
        assert!(
            !tunnel.tunnel_authorizes("cluster.example", 6443),
            "a different port on the same host is a different destination"
        );
        assert!(
            !tunnel.tunnel_authorizes("other.example", HTTPS_PORT),
            "a different host is still gated"
        );
    }

    #[test]
    fn tunnel_authorization_reaches_inner_requests_but_not_a_later_connection() {
        // The clone chain hudsucker drives: one prototype, a clone per accepted
        // connection, a clone per request off that, and — for a CONNECT — the
        // tunnel task keeping the request clone and serving every decrypted
        // inner request from a clone of it.
        let prototype = handler_prototype();

        let mut connection = prototype.clone();
        let mut tunnel = connection.clone();
        tunnel.authorize_tunnel("cluster.example".to_owned(), HTTPS_PORT);
        assert!(
            tunnel
                .clone()
                .tunnel_authorizes("cluster.example", HTTPS_PORT),
            "a decrypted inner request over this tunnel must be recognized"
        );

        // The tunnel closes; a later connection reuses the same client
        // SocketAddr (a recycled source port, or an intermediate NAT). It gets
        // its own clone of the prototype, so it inherits nothing: authorization
        // is scoped to the connection that earned it, not to an address.
        drop(tunnel);
        let reused_addr = prototype.clone();
        assert!(
            !reused_addr.tunnel_authorizes("cluster.example", HTTPS_PORT),
            "a later connection reusing the address must not inherit the tunnel"
        );
        // The connection the CONNECT arrived on is likewise untouched: the
        // authorization lives on the request clone, not on shared state.
        connection.authorize_tunnel("other.example".to_owned(), HTTPS_PORT);
        assert!(
            !prototype.tunnel_authorizes("other.example", HTTPS_PORT),
            "authorizing a tunnel must not write back to the shared prototype"
        );
    }

    #[tokio::test]
    async fn forwarded_body_stays_encoded_after_inspection() {
        // Only the scan sees decoded bytes — the forwarded body must be the
        // original (still-encoded) bytes, or every gzip request would break.
        let policy =
            honmoon_core::Policy::from_yaml("egress:\n  default: allow\n").expect("policy");
        let handler = HonmoonHandler::new(GatewayState::new(policy));

        let compressed = gzip(b"rrn=670125-1230644");
        let req = Request::builder()
            .method("POST")
            .uri("https://localhost/submit")
            .header(header::CONTENT_ENCODING, "gzip")
            .header(header::CONTENT_LENGTH, compressed.len().to_string())
            .body(Body::from(compressed.clone()))
            .expect("build request");

        let RequestOrResponse::Request(forwarded) = handler.inspect_body(req, HTTPS_PORT).await
        else {
            panic!("detect-only inspection must forward the request");
        };
        let body = forwarded
            .into_body()
            .collect()
            .await
            .expect("collect forwarded body")
            .to_bytes();
        assert_eq!(
            &body[..],
            &compressed[..],
            "forwarded body must stay encoded"
        );
    }

    /// HTTP/1.1 forbids trailers alongside a declared `Content-Length`, but
    /// HTTP/2 allows them and hudsucker negotiates h2 over an intercepted
    /// tunnel — so this arm buffers with `collect()` for real h2 traffic and
    /// has to hand the trailers back, exactly as the chunked arm does.
    #[tokio::test]
    async fn forwarded_body_keeps_trailers_on_the_content_length_path() {
        let policy =
            honmoon_core::Policy::from_yaml("egress:\n  default: allow\n").expect("policy");
        let handler = HonmoonHandler::new(GatewayState::new(policy));

        let payload = hudsucker::hyper::body::Bytes::from_static(b"key=value");
        let mut sent = hudsucker::hyper::HeaderMap::new();
        sent.insert(
            "content-digest",
            header::HeaderValue::from_static("sha-256=:ZGlnZXN0:"),
        );
        let req = Request::builder()
            .method("POST")
            .uri("https://localhost/submit")
            .header(header::CONTENT_LENGTH, payload.len().to_string())
            .body(buffered_body(payload.clone(), Some(sent.clone())))
            .expect("build request");

        let RequestOrResponse::Request(forwarded) = handler.inspect_body(req, HTTPS_PORT).await
        else {
            panic!("detect-only inspection must forward the request");
        };
        let collected = forwarded
            .into_body()
            .collect()
            .await
            .expect("collect forwarded body");
        assert_eq!(
            collected.trailers().cloned().expect("trailers preserved"),
            sent
        );
        assert_eq!(&collected.to_bytes()[..], &payload[..]);
    }

    /// #134: a trailer section can carry any syntactically valid field name —
    /// hyper's h1 chunked decoder does no name filtering — and on an h2 upstream
    /// leg nothing downstream filters it either. honmoon drops the forbidden
    /// names itself so the upstream protocol does not decide, on every branch of
    /// `inspect_body`'s `content_length` match. `payload`/`content_length` pick
    /// the branch; the returned trailers are what the upstream leg would see.
    async fn forwarded_trailers(
        payload: hudsucker::hyper::body::Bytes,
        content_length: Option<usize>,
        sent: hudsucker::hyper::HeaderMap,
    ) -> Option<hudsucker::hyper::HeaderMap> {
        forwarded_trailers_with(payload, content_length, sent, &[]).await
    }

    /// As above, with extra request headers — `Connection` nominations need the
    /// header section, not just the trailer frame.
    async fn forwarded_trailers_with(
        payload: hudsucker::hyper::body::Bytes,
        content_length: Option<usize>,
        sent: hudsucker::hyper::HeaderMap,
        headers: &[(&str, &str)],
    ) -> Option<hudsucker::hyper::HeaderMap> {
        forwarded_request_with(payload, content_length, Some(sent), headers)
            .await
            .into_body()
            .collect()
            .await
            .expect("collect forwarded body")
            .trailers()
            .cloned()
    }

    /// Drive `inspect_body` and hand back the forwarded request itself, so a
    /// test can read the framing headers honmoon wrote as well as the body.
    async fn forwarded_request_with(
        payload: hudsucker::hyper::body::Bytes,
        content_length: Option<usize>,
        sent: Option<hudsucker::hyper::HeaderMap>,
        headers: &[(&str, &str)],
    ) -> Request<Body> {
        let policy =
            honmoon_core::Policy::from_yaml("egress:\n  default: allow\n").expect("policy");
        let handler = HonmoonHandler::new(GatewayState::new(policy));

        let mut builder = Request::builder()
            .method("POST")
            .uri("https://localhost/submit");
        if let Some(len) = content_length {
            builder = builder.header(header::CONTENT_LENGTH, len.to_string());
        }
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let req = builder
            .body(buffered_body(payload, sent))
            .expect("build request");

        let RequestOrResponse::Request(forwarded) = handler.inspect_body(req, HTTPS_PORT).await
        else {
            panic!("detect-only inspection must forward the request");
        };
        forwarded
    }

    /// A single `content-digest` trailer — the RFC 9421 shape a body signature
    /// covers, and the one #136 is about losing.
    fn digest_trailer() -> hudsucker::hyper::HeaderMap {
        let mut sent = hudsucker::hyper::HeaderMap::new();
        sent.insert(
            "content-digest",
            header::HeaderValue::from_static("sha-256=:ZGlnZXN0:"),
        );
        sent
    }

    fn header_values(request: &Request<Body>, name: header::HeaderName) -> Vec<String> {
        request
            .headers()
            .get_all(name)
            .iter()
            .map(|value| value.to_str().expect("ascii header value").to_owned())
            .collect()
    }

    /// The names the issue calls out, one of each RFC 9110 §6.5.1 category, plus
    /// an ordinary trailer that must survive so the filter is not just "drop
    /// everything".
    fn hostile_trailers() -> hudsucker::hyper::HeaderMap {
        let mut sent = hudsucker::hyper::HeaderMap::new();
        for (name, value) in [
            ("transfer-encoding", "chunked"),
            ("content-length", "0"),
            ("host", "attacker.example"),
            ("authorization", "Bearer smuggled"),
            ("proxy-authorization", "Basic smuggled"),
            ("cookie", "session=smuggled"),
            ("set-cookie", "session=smuggled"),
            ("connection", "keep-alive"),
            ("x-note", "kept"),
        ] {
            sent.insert(name, header::HeaderValue::from_static(value));
        }
        sent
    }

    fn assert_filtered(trailers: &hudsucker::hyper::HeaderMap, branch: &str) {
        for name in [
            "transfer-encoding",
            "content-length",
            "host",
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
            "connection",
        ] {
            assert!(
                !trailers.contains_key(name),
                "{branch}: `{name}` must not reach the upstream in a trailer"
            );
        }
        assert_eq!(
            trailers.get("x-note").map(|v| v.as_bytes()),
            Some(&b"kept"[..]),
            "{branch}: an ordinary trailer must still be forwarded"
        );
    }

    #[tokio::test]
    async fn forbidden_trailers_are_dropped_on_the_buffered_content_length_path() {
        let payload = hudsucker::hyper::body::Bytes::from_static(b"key=value");
        let trailers = forwarded_trailers(payload.clone(), Some(payload.len()), hostile_trailers())
            .await
            .expect("the surviving trailer keeps the frame");
        assert_filtered(&trailers, "Content-Length within cap");
    }

    #[tokio::test]
    async fn forbidden_trailers_are_dropped_on_the_buffered_unknown_length_path() {
        let payload = hudsucker::hyper::body::Bytes::from_static(b"key=value");
        let trailers = forwarded_trailers(payload, None, hostile_trailers())
            .await
            .expect("the surviving trailer keeps the frame");
        assert_filtered(&trailers, "unknown length within cap");
    }

    /// The two streaming branches are the ones a filter inside `buffered_body`
    /// would miss: the body is forwarded untouched and honmoon never holds its
    /// trailers as a `HeaderMap` at all.
    #[tokio::test]
    async fn forbidden_trailers_are_dropped_on_the_declared_over_cap_path() {
        // The branch is chosen by the *declared* length, which is what an
        // over-cap upload announces before any of it is read.
        let payload = hudsucker::hyper::body::Bytes::from_static(b"key=value");
        let trailers = forwarded_trailers(payload, Some(MAX_INSPECT_BODY + 1), hostile_trailers())
            .await
            .expect("the surviving trailer keeps the frame");
        assert_filtered(&trailers, "declared over cap");
    }

    #[tokio::test]
    async fn forbidden_trailers_are_dropped_on_the_overflow_path() {
        let payload = hudsucker::hyper::body::Bytes::from(vec![b'x'; MAX_INSPECT_BODY + 1]);
        let trailers = forwarded_trailers(payload, None, hostile_trailers())
            .await
            .expect("the surviving trailer keeps the frame");
        assert_filtered(&trailers, "unknown length over cap");
    }

    /// RFC 9110 §7.6.1 forbids an intermediary from forwarding a field the
    /// request's `Connection` header nominates as hop-by-hop, and RFC 9113
    /// §8.2.2 forbids an HTTP/2 message from carrying one. hyper applies the
    /// nomination to the header section only, so before #134 a client could name
    /// its own field hop-by-hop and still have honmoon forward it — one field
    /// position over from the gap the issue names.
    #[tokio::test]
    async fn a_connection_nominated_trailer_is_dropped_and_an_unnominated_one_is_not() {
        let payload = hudsucker::hyper::body::Bytes::from_static(b"key=value");
        let mut sent = hudsucker::hyper::HeaderMap::new();
        sent.insert("x-hop", header::HeaderValue::from_static("nominated"));
        sent.insert("x-note", header::HeaderValue::from_static("kept"));

        let trailers = forwarded_trailers_with(
            payload,
            None,
            sent,
            // Two names, one of them not sent as a trailer, and surrounding
            // whitespace — the shape hyper's own header-side parse accepts.
            &[("connection", "x-hop, x-absent")],
        )
        .await
        .expect("the unnominated trailer keeps the frame");

        assert!(
            !trailers.contains_key("x-hop"),
            "a `Connection`-nominated field must not be forwarded in a trailer"
        );
        assert_eq!(
            trailers.get("x-note").map(|v| v.as_bytes()),
            Some(&b"kept"[..]),
            "a field the `Connection` header does not name is unaffected"
        );
    }

    /// #136: an h2 client may send trailers alongside a `Content-Length`, and
    /// HTTP/1.1 has nowhere to put them — hyper's `Encoder::length` drops the
    /// frame with a `debug!` and nothing else. honmoon writes the two framing
    /// headers that make hyper carry it instead: `Transfer-Encoding: chunked`
    /// selects a chunked encoder, and `Trailer` fills the allowlist that encoder
    /// filters the frame through.
    #[tokio::test]
    async fn a_content_length_request_is_reframed_to_carry_its_trailers() {
        let payload = hudsucker::hyper::body::Bytes::from_static(b"key=value");
        let forwarded = forwarded_request_with(
            payload.clone(),
            Some(payload.len()),
            Some(digest_trailer()),
            &[],
        )
        .await;

        assert_eq!(
            header_values(&forwarded, header::TRANSFER_ENCODING),
            ["chunked"],
            "a trailer section rides on chunked framing or on nothing"
        );
        assert_eq!(
            header_values(&forwarded, header::TRAILER),
            ["content-digest"],
            "hyper emits only the trailer fields the `Trailer` header names"
        );
        // Left as the client sent it: hyper drops it on an h1 leg once
        // `Transfer-Encoding` is present, and keeps it on an h2 leg, which is
        // the leg that already carried the trailer correctly.
        assert_eq!(
            header_values(&forwarded, header::CONTENT_LENGTH),
            [payload.len().to_string()],
        );
    }

    /// honmoon's own buffering is enough to lose a trailer even when the client
    /// declared no length at all: `BufferedBody`'s `size_hint` is exact, so
    /// hyper's `set_length` writes a `Content-Length` and picks the same
    /// fixed-length encoder. The re-frame has to cover this branch too.
    #[tokio::test]
    async fn an_unknown_length_request_is_reframed_to_carry_its_trailers() {
        let payload = hudsucker::hyper::body::Bytes::from_static(b"key=value");
        let forwarded = forwarded_request_with(payload, None, Some(digest_trailer()), &[]).await;

        assert_eq!(
            header_values(&forwarded, header::TRANSFER_ENCODING),
            ["chunked"]
        );
        assert_eq!(
            header_values(&forwarded, header::TRAILER),
            ["content-digest"]
        );
    }

    /// Only the names that survive `trailer_filtered_body` may be declared: a
    /// `Trailer` header naming a field the filter then drops would advertise a
    /// field that never arrives.
    #[tokio::test]
    async fn only_the_trailers_that_survive_the_filter_are_declared() {
        let payload = hudsucker::hyper::body::Bytes::from_static(b"key=value");
        let forwarded = forwarded_request_with(
            payload.clone(),
            Some(payload.len()),
            Some(hostile_trailers()),
            &[],
        )
        .await;

        assert_eq!(
            header_values(&forwarded, header::TRAILER),
            ["x-note"],
            "the declaration must name exactly the trailers the filter keeps"
        );
    }

    /// A request the client already framed to carry its trailers is left exactly
    /// as it framed it — no second `Transfer-Encoding`, no second `Trailer`.
    #[tokio::test]
    async fn an_already_chunked_and_declared_request_is_left_alone() {
        let payload = hudsucker::hyper::body::Bytes::from_static(b"key=value");
        let forwarded = forwarded_request_with(
            payload,
            None,
            Some(digest_trailer()),
            &[
                ("transfer-encoding", "chunked"),
                ("trailer", "Content-Digest"),
            ],
        )
        .await;

        assert_eq!(
            header_values(&forwarded, header::TRANSFER_ENCODING),
            ["chunked"]
        );
        assert_eq!(
            header_values(&forwarded, header::TRAILER),
            ["Content-Digest"],
            "the client's own declaration must not be rewritten or duplicated"
        );
    }

    /// A chunked request that declared nothing still loses its trailers on an h1
    /// upstream — hyper's `Kind::Chunked(None)` arm — so the declaration alone is
    /// added, and the framing the client chose is untouched.
    #[tokio::test]
    async fn a_chunked_request_that_declared_nothing_gains_only_the_declaration() {
        let payload = hudsucker::hyper::body::Bytes::from_static(b"key=value");
        let forwarded = forwarded_request_with(
            payload,
            None,
            Some(digest_trailer()),
            &[("transfer-encoding", "chunked")],
        )
        .await;

        assert_eq!(
            header_values(&forwarded, header::TRANSFER_ENCODING),
            ["chunked"]
        );
        assert_eq!(
            header_values(&forwarded, header::TRAILER),
            ["content-digest"]
        );
    }

    /// ADR-0006's constraint, applied to this re-frame: `Content-Length` and
    /// `Transfer-Encoding` are two of the three names the re-frame writes, and an
    /// AWS SDK upload signs `content-length`. Rescuing the trailer by breaking
    /// that signature trades one upstream rejection for another, so the request
    /// goes on exactly as the client signed it and the loss is logged instead.
    #[tokio::test]
    async fn a_signature_over_the_framing_headers_declines_the_reframe() {
        let payload = hudsucker::hyper::body::Bytes::from_static(b"key=value");
        let forwarded = forwarded_request_with(
            payload.clone(),
            Some(payload.len()),
            Some(digest_trailer()),
            &[(
                "authorization",
                "AWS4-HMAC-SHA256 Credential=AKIA/20260907/us-east-1/s3/aws4_request, \
                 SignedHeaders=content-length;host;x-amz-date, Signature=abc",
            )],
        )
        .await;

        assert!(
            header_values(&forwarded, header::TRANSFER_ENCODING).is_empty(),
            "a signed `content-length` must not be re-framed away"
        );
        assert!(
            header_values(&forwarded, header::TRAILER).is_empty(),
            "declining the re-frame must leave the header section untouched"
        );
        assert_eq!(
            header_values(&forwarded, header::CONTENT_LENGTH),
            [payload.len().to_string()]
        );
    }

    /// The same decision for the narrower case: the client already framed the
    /// request as chunked, so the only header the re-frame would write is
    /// `Trailer` — and a signature covering that name declines it on its own.
    #[tokio::test]
    async fn a_signature_over_the_trailer_header_declines_the_declaration() {
        let payload = hudsucker::hyper::body::Bytes::from_static(b"key=value");
        let forwarded = forwarded_request_with(
            payload,
            None,
            Some(digest_trailer()),
            &[
                ("transfer-encoding", "chunked"),
                (
                    "authorization",
                    "AWS4-HMAC-SHA256 Credential=AKIA/20260907/us-east-1/s3/aws4_request, \
                     SignedHeaders=host;trailer;x-amz-date, Signature=abc",
                ),
            ],
        )
        .await;

        assert!(
            header_values(&forwarded, header::TRAILER).is_empty(),
            "a signed `trailer` must not be appended to"
        );
    }

    /// A request with no trailer frame is not re-framed at all: there is nothing
    /// to carry, and switching a plain upload to chunked would change its wire
    /// framing for no reason.
    #[tokio::test]
    async fn a_request_without_trailers_is_not_reframed() {
        let payload = hudsucker::hyper::body::Bytes::from_static(b"key=value");
        let forwarded =
            forwarded_request_with(payload.clone(), Some(payload.len()), None, &[]).await;

        assert!(header_values(&forwarded, header::TRANSFER_ENCODING).is_empty());
        assert!(header_values(&forwarded, header::TRAILER).is_empty());
        assert_eq!(
            header_values(&forwarded, header::CONTENT_LENGTH),
            [payload.len().to_string()]
        );
    }

    /// The end of the chain the issue traces, driven rather than argued: the
    /// forwarded request goes onto a real hyper HTTP/1.1 client connection, and
    /// the assertion is on the bytes hyper wrote. `Encoder::encode_trailers` is
    /// what decides whether a trailer section is written at all, so nothing
    /// between honmoon's headers and the wire is simulated here.
    ///
    /// This is the only place the h2-client shape can be proven end to end: the
    /// integration harness speaks HTTP/1.1, which cannot express a request that
    /// carries both a `Content-Length` and a trailer frame.
    #[tokio::test]
    async fn a_reframed_request_puts_its_trailer_on_the_http1_wire() {
        let payload = hudsucker::hyper::body::Bytes::from_static(b"key=value");
        let mut forwarded = forwarded_request_with(
            payload.clone(),
            Some(payload.len()),
            Some(digest_trailer()),
            &[],
        )
        .await;
        // hyper_util rewrites the absolute-form URI to origin form before the
        // upstream leg (`origin_form`); at connection level that is the caller's
        // job, and hyper writes whatever it is given.
        *forwarded.uri_mut() = "/submit".parse().expect("origin-form uri");

        let wire = http1_upstream_wire(forwarded).await;
        assert!(
            wire.to_ascii_lowercase()
                .contains("transfer-encoding: chunked"),
            "hyper must frame the upstream leg as chunked; wire was:\n{wire}"
        );
        assert!(
            wire.ends_with("\r\n0\r\ncontent-digest: sha-256=:ZGlnZXN0:\r\n\r\n"),
            "the trailer section must be written after the last chunk; wire was:\n{wire}"
        );
    }

    /// Send `request` over a real hyper HTTP/1.1 client connection to a loopback
    /// listener, and return every byte hyper wrote for it.
    async fn http1_upstream_wire(request: Request<Body>) -> String {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let addr = listener.local_addr().expect("upstream addr");
        let upstream = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept upstream connection");
            let received = read_one_request(&mut socket).await;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                .await
                .expect("write upstream response");
            received
        });

        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect upstream");
        let (mut sender, connection) = hudsucker::hyper::client::conn::http1::handshake(
            hudsucker::hyper_util::rt::TokioIo::new(stream),
        )
        .await
        .expect("http/1.1 handshake");
        tokio::spawn(connection);
        let response = sender.send_request(request).await.expect("send request");
        assert_eq!(response.status(), StatusCode::OK);

        String::from_utf8(upstream.await.expect("upstream task")).expect("ascii wire bytes")
    }

    /// Read exactly one HTTP/1.1 request — fixed-length or chunked with its
    /// trailer section — and return the bytes as they arrived. Both framings are
    /// handled so the test fails on its assertion rather than by hanging when the
    /// re-frame does not happen.
    async fn read_one_request(socket: &mut tokio::net::TcpStream) -> Vec<u8> {
        use tokio::io::AsyncReadExt;

        let mut received = Vec::new();
        let mut buffer = [0u8; 1024];
        let header_end = loop {
            let read = socket
                .read(&mut buffer)
                .await
                .expect("read request headers");
            assert!(read > 0, "connection closed before the request headers");
            received.extend_from_slice(&buffer[..read]);
            if let Some(at) = received.windows(4).position(|window| window == b"\r\n\r\n") {
                break at + 4;
            }
        };
        let headers = String::from_utf8(received[..header_end].to_vec())
            .expect("ascii request headers")
            .to_ascii_lowercase();
        if headers.contains("transfer-encoding: chunked") {
            // The zero-length chunk plus its (possibly empty) trailer section.
            while !(received.windows(5).any(|window| window == b"\r\n0\r\n")
                && received.ends_with(b"\r\n\r\n"))
            {
                let read = socket.read(&mut buffer).await.expect("read chunked body");
                assert!(read > 0, "connection closed before the last chunk");
                received.extend_from_slice(&buffer[..read]);
            }
        } else {
            let length = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .map(|value| value.trim().parse::<usize>().expect("numeric length"))
                .unwrap_or(0);
            while received.len() < header_end + length {
                let read = socket.read(&mut buffer).await.expect("read request body");
                assert!(read > 0, "connection closed before the body");
                received.extend_from_slice(&buffer[..read]);
            }
        }
        received
    }
}
