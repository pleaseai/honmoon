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
//!    intercepted) — the host was already authorized at the CONNECT, so only
//!    the body is scanned with [`detect_pii`] and findings are audited.
//!
//! Whether a request is an inner request (shape 3) is decided by the
//! [`TunnelRegistry`] — the client's socket must have an authorized CONNECT to
//! that host — **not** by the URI scheme: a client could send an absolute-form
//! `GET https://…` without CONNECT (or spoof `:authority` over h2), and trusting
//! the scheme would let it skip the host gate. Unrecognized requests are gated
//! like shape 2.
//!
//! Content inspection is **detect-only**: PII findings are surfaced to the audit
//! log but do not block the request. Enforcing content rules is a follow-up.
//!
//! Whether a tunnel is TLS-terminated is decided by
//! [`should_intercept`](HonmoonHandler::should_intercept) from the gateway's
//! [`InterceptPolicy`](crate::gateway::InterceptPolicy).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::Poll;

use honmoon_core::{
    AuditDraft, Decision, Facts, FactsSummary, HttpFacts, Verdict, decide_explained, detect_pii,
};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hudsucker::hyper::body::{Body as HttpBody, Bytes, Frame, SizeHint};
use hudsucker::hyper::{Method, Request, Response, StatusCode, header};
use hudsucker::{Body, HttpContext, HttpHandler, RequestOrResponse};

use crate::approval::{ApprovalDecision, NewApproval};
use crate::gateway::{GatewayState, InterceptPolicy, canonical_host};

/// Max request-body bytes buffered in memory for PII inspection. Bodies larger
/// than this (whether declared by `Content-Length` or discovered while reading
/// an unknown-length body) are streamed through un-buffered and left unscanned,
/// so a large upload can never exhaust memory.
const MAX_INSPECT_BODY: usize = 2 * 1024 * 1024;

/// Backstop cap on tracked tunnels. Entries are overwritten per client socket
/// but never individually removed (hudsucker exposes no close event), so this
/// bounds memory under long-running / hostile traffic.
const MAX_TRACKED_TUNNELS: usize = 65_536;

/// CONNECT-authorized tunnels, keyed by the client socket address.
///
/// hudsucker forces each HTTP/1.x inner request's URI authority to its tunnel's
/// CONNECT authority, so an inner request is recognized by (client addr → host)
/// matching an authorized CONNECT. Anything else claiming `https://` (an
/// absolute-form request without CONNECT, an h2 `:authority` mismatch) is not
/// recognized and gets host-gated like a cleartext request.
#[derive(Default)]
struct TunnelRegistry {
    tunnels: Mutex<HashMap<SocketAddr, String>>,
}

impl TunnelRegistry {
    /// Record that `addr` holds an authorized CONNECT tunnel to `host`.
    fn authorize(&self, addr: SocketAddr, host: String) {
        let mut tunnels = self.tunnels.lock().expect("tunnel registry poisoned");
        if tunnels.len() >= MAX_TRACKED_TUNNELS && !tunnels.contains_key(&addr) {
            // Fail safe: dropping entries only re-gates inner requests (their
            // hosts were already allowed once), it never skips a gate.
            tracing::warn!("tunnel registry full; clearing (inner requests will be re-gated)");
            tunnels.clear();
        }
        tunnels.insert(addr, host);
    }

    /// Does `addr` hold an authorized CONNECT tunnel to `host`?
    fn is_authorized(&self, addr: &SocketAddr, host: &str) -> bool {
        self.tunnels
            .lock()
            .expect("tunnel registry poisoned")
            .get(addr)
            .is_some_and(|h| h == host)
    }
}

/// Frees a pending approval slot (and audits the rejection) if the holding
/// future is dropped before a decision was reached — hudsucker drops the
/// request future when the waiting client disconnects.
struct CancelOnDrop {
    state: GatewayState,
    id: u64,
    rule: Option<String>,
    summary: Option<FactsSummary>,
    armed: bool,
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.state.approvals.cancel(self.id);
        tracing::info!(id = self.id, "client gone while held; approval cancelled");
        self.state.audit.record(AuditDraft {
            decision: Decision::Rejected,
            verdict: Verdict::Pause,
            rule: self.rule.take(),
            facts: self.summary.take().unwrap_or_default(),
            approval_id: Some(self.id),
        });
    }
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
    /// Shared across per-connection clones (all derive from one prototype).
    tunnels: Arc<TunnelRegistry>,
}

impl HonmoonHandler {
    pub fn new(state: GatewayState) -> Self {
        Self {
            state,
            tunnels: Arc::new(TunnelRegistry::default()),
        }
    }

    /// Apply host-level policy (allow / deny / pause) to `host`.
    ///
    /// `audit_allow` records the `Allow` decision — set for the CONNECT gate so
    /// the connection is logged, but not for individual forwarded requests (which
    /// would flood the bounded audit ring).
    async fn host_gate(&self, host: &str, audit_allow: bool) -> Gate {
        let facts = Facts {
            domain: Some(host.to_owned()),
            http: Some(HttpFacts {
                host: host.to_owned(),
                ..Default::default()
            }),
            ..Default::default()
        };
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
            Verdict::Pause => self.hold(host, summary, outcome.rule).await,
        }
    }

    /// Hold a `pause`d request until a human resolves it (or the hold times out).
    /// The client waits the whole time (a CONNECT stays silent until its `200`),
    /// so returning [`Gate::Proceed`] lets it through and [`Gate::Block`] closes it.
    async fn hold(&self, host: &str, summary: FactsSummary, rule: Option<String>) -> Gate {
        let registration = self.state.approvals.register(NewApproval {
            domain: Some(host.to_owned()),
            rule: rule.clone(),
            summary: connect_summary(host, rule.as_deref()),
            ..Default::default()
        });
        let Some((pending, rx)) = registration else {
            // Pending queue is at capacity — fail closed rather than hold.
            tracing::warn!(domain = %host, "approval queue full; rejecting paused request");
            self.state.audit.record(AuditDraft {
                decision: Decision::Rejected,
                verdict: Verdict::Pause,
                rule,
                facts: summary,
                approval_id: None,
            });
            return Gate::Block(Box::new(status_response(StatusCode::SERVICE_UNAVAILABLE)));
        };

        self.state.audit.record(AuditDraft {
            decision: Decision::Paused,
            verdict: Verdict::Pause,
            rule: rule.clone(),
            facts: summary.clone(),
            approval_id: Some(pending.id),
        });
        tracing::info!(id = pending.id, domain = %host, "request held for approval");

        // If the client disconnects mid-hold, hudsucker drops this future and
        // the code after the `await` never runs — the guard then frees the slot
        // so abandoned holds can't saturate the approval queue.
        let mut guard = CancelOnDrop {
            state: self.state.clone(),
            id: pending.id,
            rule: rule.clone(),
            summary: Some(summary.clone()),
            armed: true,
        };
        let decision = match tokio::time::timeout(self.state.pause_timeout, rx).await {
            Ok(Ok(d)) => d,
            // Registry dropped (shutdown) — treat as rejection.
            Ok(Err(_)) => ApprovalDecision::Reject,
            // Timed out waiting for a human — drop the slot and reject.
            Err(_elapsed) => {
                self.state.approvals.cancel(pending.id);
                tracing::info!(id = pending.id, "approval timed out");
                ApprovalDecision::Reject
            }
        };
        guard.armed = false;

        match decision {
            ApprovalDecision::Approve => {
                self.state.audit.record(AuditDraft {
                    decision: Decision::Approved,
                    verdict: Verdict::Pause,
                    rule,
                    facts: summary,
                    approval_id: Some(pending.id),
                });
                Gate::Proceed
            }
            ApprovalDecision::Reject => {
                self.state.audit.record(AuditDraft {
                    decision: Decision::Rejected,
                    verdict: Verdict::Pause,
                    rule,
                    facts: summary,
                    approval_id: Some(pending.id),
                });
                Gate::Block(Box::new(status_response(StatusCode::FORBIDDEN)))
            }
        }
    }

    /// Scan a request body for PII and record any findings. Detect-only: the
    /// (reconstructed) request is always returned to forward.
    async fn inspect_body(&self, req: Request<Body>) -> RequestOrResponse {
        let method = req.method().clone();
        let host = request_host(&req);
        let path = req.uri().path().to_owned();

        let content_length = req
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok());

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

        let pii = scanned
            .as_deref()
            .and_then(|b| std::str::from_utf8(b).ok())
            .and_then(detect_pii);

        // Only record when something was found — every request would otherwise
        // flood the bounded audit ring. (No let-chains: MSRV is 1.85.)
        if let Some(pii) = pii.filter(|p| p.count > 0) {
            let facts = Facts {
                domain: Some(host.clone()),
                http: Some(HttpFacts {
                    method: method.as_str().to_owned(),
                    host: host.clone(),
                    path,
                    body_size,
                }),
                pii: Some(pii.clone()),
                ..Default::default()
            };
            let outcome = decide_explained(&self.state.policy, &facts);
            tracing::info!(
                domain = %host,
                pii_types = ?pii.types,
                pii_count = pii.count,
                would_be = ?outcome.verdict,
                "pii detected (detect-only)"
            );
            self.state.audit.record(AuditDraft {
                // Detect-only: we forwarded (Allowed), but `verdict` carries what
                // policy *would* do so enforcing mode is a drop-in later.
                decision: Decision::Allowed,
                verdict: outcome.verdict,
                rule: outcome.rule,
                facts: FactsSummary::from(&facts),
                approval_id: None,
            });
        }

        Request::from_parts(parts, new_body).into()
    }
}

impl HttpHandler for HonmoonHandler {
    async fn handle_request(&mut self, ctx: &HttpContext, req: Request<Body>) -> RequestOrResponse {
        if req.method() == Method::CONNECT {
            let host = canonical_host(req.uri().authority().map(|a| a.as_str()).unwrap_or(""));
            return match self.host_gate(&host, true).await {
                Gate::Proceed => {
                    self.tunnels.authorize(ctx.client_addr, host);
                    req.into()
                }
                Gate::Block(res) => *res,
            };
        }

        // A decrypted inner request (injected by hudsucker after TLS
        // termination) was already authorized at its CONNECT — inspect only. It
        // is recognized by its client socket's authorized tunnel, *not* by the
        // URI scheme: an absolute-form `https://` request sent without CONNECT
        // must be host-gated like a cleartext `http://` one, or the egress
        // allowlist could be bypassed.
        let host = request_host(&req);
        if !self.tunnels.is_authorized(&ctx.client_addr, &host) {
            if let Gate::Block(res) = self.host_gate(&host, false).await {
                return *res;
            }
        }

        self.inspect_body(req).await
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

/// Result of buffering an unknown-length body up to a cap.
enum Buffered {
    /// The body ended within the cap — fully buffered (trailers dropped, like
    /// the `Content-Length` buffered path).
    Complete(Bytes),
    /// The cap was hit: `prefix` holds the bytes read so far, `rest` the
    /// unread remainder of the stream.
    Overflow { prefix: Bytes, rest: Body },
}

/// Read data frames from `body` until it ends or more than `limit` bytes have
/// been buffered.
async fn buffer_up_to(mut body: Body, limit: usize) -> Result<Buffered, hudsucker::Error> {
    let mut buf: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        if let Some(data) = frame?.data_ref() {
            buf.extend_from_slice(data);
            if buf.len() > limit {
                return Ok(Buffered::Overflow {
                    prefix: Bytes::from(buf),
                    rest: body,
                });
            }
        }
    }
    Ok(Buffered::Complete(Bytes::from(buf)))
}

/// Re-assemble a body from an already-read prefix followed by the unread rest.
fn prefixed_body(prefix: Bytes, rest: Body) -> Body {
    Body::from(BoxBody::new(PrefixedBody {
        prefix: Some(prefix),
        rest,
    }))
}

/// An [`HttpBody`] that yields one prefix chunk, then delegates to `rest`.
struct PrefixedBody {
    prefix: Option<Bytes>,
    rest: Body,
}

impl HttpBody for PrefixedBody {
    type Data = Bytes;
    type Error = hudsucker::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if let Some(prefix) = self.prefix.take() {
            return Poll::Ready(Some(Ok(Frame::data(prefix))));
        }
        Pin::new(&mut self.rest).poll_frame(cx)
    }

    fn size_hint(&self) -> SizeHint {
        let mut hint = self.rest.size_hint();
        let prefix_len = self.prefix.as_ref().map(|p| p.len() as u64).unwrap_or(0);
        hint.set_lower(hint.lower() + prefix_len);
        if let Some(upper) = hint.upper() {
            hint.set_upper(upper + prefix_len);
        }
        hint
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unknown_length_body_within_cap_is_fully_buffered() {
        let body = Body::from(b"small body".to_vec());
        match buffer_up_to(body, MAX_INSPECT_BODY).await.expect("read") {
            Buffered::Complete(bytes) => assert_eq!(&bytes[..], b"small body"),
            Buffered::Overflow { .. } => panic!("small body must not overflow"),
        }
    }

    #[tokio::test]
    async fn oversized_unknown_length_body_streams_through_intact() {
        let big = vec![b'a'; MAX_INSPECT_BODY + 10];
        let body = Body::from(big.clone());
        match buffer_up_to(body, MAX_INSPECT_BODY).await.expect("read") {
            Buffered::Complete(_) => panic!("oversized body must overflow"),
            Buffered::Overflow { prefix, rest } => {
                // Nothing may be lost: prefix + rest must equal the original.
                let rest_bytes = prefixed_body(prefix, rest)
                    .collect()
                    .await
                    .expect("collect reassembled body")
                    .to_bytes();
                assert_eq!(&rest_bytes[..], &big[..]);
            }
        }
    }
}
