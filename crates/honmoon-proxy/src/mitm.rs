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
    Buffered, MAX_INSPECT_BODY, StrictDecode, buffer_up_to, decode_strict, detokenizing_body,
    prefixed_body, utf8_prefix,
};
use crate::gateway::{
    GatewayState, InterceptPolicy, PiiMode, SignedBodyMode, authority_port, canonical_host,
};
use crate::signed_body::{
    BODY_DIGEST_HEADERS, REWRITTEN_FRAMING_HEADERS, SignedBodyScheme, authentication_signs_headers,
    body_signature_scheme, signed_headers_among,
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
    fn forwarded_request(
        &self,
        mut request: Request<Body>,
        input: RedactionInput<'_>,
    ) -> RequestOrResponse {
        let RedactionInput {
            scanned,
            decoded,
            content_encoding_present,
            content_encoding,
            pii_spans,
            is_json,
            host,
            summary,
        } = input;
        let Some(redaction) = &self.state.redaction else {
            return request.into();
        };

        // Ask upstreams for text we can safely detokenize on the response path.
        // A server may ignore this, in which case handle_response fails open.
        //
        // Two disjoint exemptions, and the rewrite is skipped when *either*
        // holds. `authentication_signs_headers` covers requests whose headers
        // are demonstrably signed: some SigV4 signers list `accept-encoding` in
        // `SignedHeaders` even when the payload itself is unsigned
        // (`UNSIGNED-PAYLOAD`), and RFC 9421 / draft-cavage signatures cover
        // whichever headers their component or `headers=` list names.
        // `signature_scheme` covers the converse case — a bare hex
        // `x-amz-content-sha256` binds the body without any recognized
        // signature, so we cannot tell whether the scheme that produced it also
        // signs headers, and that request is forwarded verbatim under
        // `--signed-body forward`. Neither predicate implies the other.
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
            return request.into();
        }

        let Some(_raw) = scanned else {
            tracing::warn!(
                domain = %host,
                limit = MAX_INSPECT_BODY,
                "wire redaction bypassed for over-cap request body"
            );
            return request.into();
        };
        if content_encoding_present && content_encoding.is_none() {
            tracing::warn!(
                domain = %host,
                "wire redaction bypassed because Content-Encoding was not valid text"
            );
            return request.into();
        }
        let Some(decoded) = decoded else {
            tracing::warn!(
                domain = %host,
                encoding = ?content_encoding,
                "wire redaction bypassed because request encoding was not fully decodable"
            );
            return request.into();
        };
        // Rewriting a UTF-8 prefix would discard the remaining request bytes.
        // Only a fully decoded, fully valid text body is eligible for rewriting.
        let Ok(text) = std::str::from_utf8(decoded) else {
            tracing::warn!(
                domain = %host,
                "wire redaction bypassed because request body is not valid UTF-8"
            );
            return request.into();
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
            return request.into();
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
                    request.into()
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
                    signed_body_response(scheme)
                }
            };
        }

        let labels = outcome.labels();
        let bytes = hudsucker::hyper::body::Bytes::from(outcome.text);
        let length = bytes.len();

        // SigV4 and its peers sign *headers* even when the payload is out of
        // the signature (`UNSIGNED-PAYLOAD`), and re-framing the rewritten body
        // changes headers a `SignedHeaders` list routinely names — an AWS SDK
        // upload signs `content-length`. Breaking the signature that way earns
        // the same opaque upstream rejection as rewriting a signed body, so it
        // takes the same `--signed-body` decision. Only the headers this
        // rewrite would actually change are asked about: a signed
        // `Content-Encoding` the request never sent, or a signed
        // `Content-Length` the redacted body happens to match, survives it.
        let reframed = reframed_headers(request.headers(), length);
        let broken = signed_headers_among(request.headers(), request.uri(), &reframed);
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
                    request.into()
                }
                SignedBodyMode::Block => {
                    tracing::warn!(
                        domain = %host,
                        headers = %signed,
                        "header-signed request blocked: re-framing the redacted body would \
                         invalidate its signature"
                    );
                    self.state.audit.record(AuditDraft {
                        decision: Decision::Denied,
                        verdict: Verdict::Deny,
                        rule: Some("wire-redaction/signed-headers".to_owned()),
                        facts: summary.clone(),
                        approval_id: None,
                    });
                    signed_headers_response(&signed)
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
        request.into()
    }

    /// Scan a request body for PII. Detect mode audits findings and forwards;
    /// block mode enforces the resulting policy verdict inline.
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
        let (new_body, scanned, body_size) = match content_length {
            Some(len) if len <= MAX_INSPECT_BODY => match body.collect().await {
                Ok(collected) => {
                    let bytes = collected.to_bytes();
                    let size = bytes.len() as i64;
                    (Body::from(Full::new(bytes.clone())), Some(bytes), size)
                }
                // Failing to read the *client's* body is a client-side error.
                Err(_) => return status_response(StatusCode::BAD_REQUEST),
            },
            Some(len) => (body, None, len as i64),
            None => match buffer_up_to(body, MAX_INSPECT_BODY).await {
                Ok(Buffered::Complete(bytes)) => {
                    let size = bytes.len() as i64;
                    (Body::from(Full::new(bytes.clone())), Some(bytes), size)
                }
                // Over the cap — forward the buffered prefix plus the rest of
                // the stream untouched, unscanned (same as an over-cap
                // `Content-Length` body).
                Ok(Buffered::Overflow { prefix, rest }) => (prefixed_body(prefix, rest), None, -1),
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
        let forwarded = Request::from_parts(parts, new_body);

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

/// A `403` explaining that redaction cannot re-frame a request whose signature
/// covers the framing headers the rewrite has to change — the header-signed
/// counterpart of [`signed_body_response`].
fn signed_headers_response(signed: &str) -> RequestOrResponse {
    let reason = format!(
        "honmoon: this request's signature covers {signed}, and wire redaction would rewrite \
         those headers to re-frame the redacted body; the upstream would reject the forwarded \
         request. Remove the sensitive value, or run the gateway with --signed-body forward to \
         send it unredacted.\n"
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

/// Which of [`REWRITTEN_FRAMING_HEADERS`] replacing the body with `new_length`
/// bytes of identity-encoded text would actually change on the wire.
///
/// `Content-Encoding` and `Transfer-Encoding` are only dropped when the request
/// carries them, and `Content-Length` is only re-framed when the redacted body
/// is a different size — a signature over a header the rewrite leaves as it
/// found it is not broken by the rewrite.
fn reframed_headers(headers: &header::HeaderMap, new_length: usize) -> Vec<header::HeaderName> {
    REWRITTEN_FRAMING_HEADERS
        .into_iter()
        .filter(|name| {
            if *name == header::CONTENT_LENGTH {
                declared_content_length(headers) != Some(new_length)
            } else {
                headers.contains_key(name)
            }
        })
        .collect()
}

/// The request's declared `Content-Length`, when it carries exactly one
/// well-formed value. Anything else counts as "not what the rewrite will
/// send", which is the fail-closed reading.
fn declared_content_length(headers: &header::HeaderMap) -> Option<usize> {
    let mut values = headers.get_all(header::CONTENT_LENGTH).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()?.trim().parse().ok()
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
}
