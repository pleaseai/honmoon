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
//! 3. **Decrypted inner requests** over a terminated tunnel (`https://`, only
//!    when intercepted) — the host was already authorized at the CONNECT, so only
//!    the body is scanned with [`detect_pii`] and findings are audited.
//!
//! Content inspection is **detect-only**: PII findings are surfaced to the audit
//! log but do not block the request. Enforcing content rules is a follow-up.
//!
//! Whether a tunnel is TLS-terminated is decided by
//! [`should_intercept`](HonmoonHandler::should_intercept) from the gateway's
//! [`InterceptPolicy`](crate::gateway::InterceptPolicy).

use honmoon_core::{
    AuditDraft, Decision, Facts, FactsSummary, HttpFacts, Verdict, decide_explained, detect_pii,
};
use http_body_util::{BodyExt, Full};
use hudsucker::hyper::{Method, Request, Response, StatusCode, header};
use hudsucker::{Body, HttpContext, HttpHandler, RequestOrResponse};

use crate::approval::{ApprovalDecision, NewApproval};
use crate::gateway::{GatewayState, InterceptPolicy, canonical_host};

/// Max request-body bytes buffered in memory for PII inspection. Bodies whose
/// `Content-Length` exceeds this (or that omit it) are streamed through
/// un-buffered and left unscanned, so a large upload can never exhaust memory.
const MAX_INSPECT_BODY: usize = 2 * 1024 * 1024;

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
}

impl HonmoonHandler {
    pub fn new(state: GatewayState) -> Self {
        Self { state }
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
        let host = req
            .uri()
            .host()
            .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
            .unwrap_or_default();
        let path = req.uri().path().to_owned();

        let content_length = req
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok());

        let (parts, body) = req.into_parts();

        // Buffer only small, length-declared bodies; stream the rest through
        // un-inspected so a large upload can't exhaust memory.
        let (new_body, scanned, body_size) = match content_length {
            Some(len) if len <= MAX_INSPECT_BODY => match body.collect().await {
                Ok(collected) => {
                    let bytes = collected.to_bytes();
                    let size = bytes.len() as i64;
                    (Body::from(Full::new(bytes.clone())), Some(bytes), size)
                }
                Err(_) => return status_response(StatusCode::BAD_GATEWAY),
            },
            other => (body, None, other.map(|n| n as i64).unwrap_or(-1)),
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
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        if req.method() == Method::CONNECT {
            let host = canonical_host(req.uri().authority().map(|a| a.as_str()).unwrap_or(""));
            return match self.host_gate(&host, true).await {
                Gate::Proceed => req.into(),
                Gate::Block(res) => *res,
            };
        }

        // A decrypted inner request (`https://`, injected by hudsucker after TLS
        // termination) was already authorized at its CONNECT — inspect only.
        // A cleartext `http://` forward-proxy request skipped CONNECT, so apply
        // the host gate here to keep the egress allowlist enforced.
        if req.uri().scheme_str() != Some("https") {
            let host = req
                .uri()
                .host()
                .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
                .unwrap_or_default();
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
