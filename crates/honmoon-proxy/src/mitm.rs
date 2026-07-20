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
//! [`TunnelRegistry`] — the client's socket must have an authorized CONNECT to
//! that host — **not** by the URI scheme: a client could send an absolute-form
//! `GET https://…` without CONNECT (or spoof `:authority` over h2), and trusting
//! the scheme would let it skip the host gate. Unrecognized requests are gated
//! like shape 2.
//!
//! Content inspection defaults to **detect-only** for backward compatibility:
//! PII findings and the policy's would-be verdict are audited, then forwarded.
//! In block mode, the same verdict is enforced inline (`deny` returns 403 and
//! `pause` uses the shared approval registry).
//! Request-body buffering and `Content-Encoding` decoding live in
//! [`crate::body`]; the forwarded body is always the original (still-encoded)
//! bytes — only the scanner sees decoded output.
//!
//! Whether a tunnel is TLS-terminated is decided by
//! [`should_intercept`](HonmoonHandler::should_intercept) from the gateway's
//! [`InterceptPolicy`](crate::gateway::InterceptPolicy).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use honmoon_core::{
    AuditDraft, Decision, Facts, FactsSummary, HttpFacts, PiiFacts, Verdict, decide_explained,
    detect_pii,
};
use http_body_util::{BodyExt, Full};
use hudsucker::hyper::{Method, Request, Response, StatusCode, header};
use hudsucker::{Body, HttpContext, HttpHandler, RequestOrResponse};

use crate::approval::{ApprovalDecision, NewApproval};
use crate::body::{
    Buffered, MAX_INSPECT_BODY, buffer_up_to, decode_for_inspection, prefixed_body, utf8_prefix,
};
use crate::gateway::{GatewayState, InterceptPolicy, PiiMode, canonical_host};

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
    async fn hold(
        &self,
        host: &str,
        summary: FactsSummary,
        rule: Option<String>,
        approval_summary: String,
    ) -> Gate {
        let registration = self.state.approvals.register(NewApproval {
            domain: Some(host.to_owned()),
            rule: rule.clone(),
            summary: approval_summary,
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

    /// Scan a request body for PII. Detect mode audits findings and forwards;
    /// block mode enforces the resulting policy verdict inline.
    async fn inspect_body(&self, req: Request<Body>) -> RequestOrResponse {
        let method = req.method().clone();
        let host = request_host(&req);
        let path = req.uri().path().to_owned();

        let content_length = req
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok());

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
        // `Content-Encoding`s (capped) before scanning. Only the scan sees the
        // decoded bytes — the original (still-encoded) body is forwarded.
        let decoded = scanned
            .as_deref()
            .map(|raw| decode_for_inspection(content_encoding.as_deref(), raw));
        let inspected_text = decoded.as_deref().and_then(utf8_prefix);
        let pii = inspected_text.and_then(detect_pii);
        let forwarded = Request::from_parts(parts, new_body);

        // An oversized or non-text body was not inspected. Do not interpret the
        // absence of facts as `pii.count == 0`; retain the host gate's verdict.
        if inspected_text.is_none() {
            return forwarded.into();
        }

        let facts = Facts {
            domain: Some(host.clone()),
            http: Some(HttpFacts {
                method: method.as_str().to_owned(),
                host: host.clone(),
                path: path.clone(),
                body_size,
            }),
            pii: pii.clone(),
            ..Default::default()
        };
        let outcome = decide_explained(&self.state.policy, &facts);
        let summary = FactsSummary::from(&facts);

        if self.state.pii_mode == PiiMode::Detect {
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
                    facts: summary,
                    approval_id: None,
                });
            }
            return forwarded.into();
        }

        match outcome.verdict {
            Verdict::Allow => {
                self.state.audit.record(AuditDraft {
                    decision: Decision::Allowed,
                    verdict: Verdict::Allow,
                    rule: outcome.rule,
                    facts: summary,
                    approval_id: None,
                });
                forwarded.into()
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
                    .hold(&host, summary, outcome.rule, approval_summary)
                    .await
                {
                    Gate::Proceed => forwarded.into(),
                    Gate::Block(response) => *response,
                }
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).expect("gzip write");
        enc.finish().expect("gzip finish")
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

        let RequestOrResponse::Request(forwarded) = handler.inspect_body(req).await else {
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
