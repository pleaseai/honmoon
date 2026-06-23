//! HTTP CONNECT egress gateway (Phase 1).
//!
//! Agents point `https_proxy` at this proxy. The client issues
//! `CONNECT host:port`; we evaluate the target host against the [`Policy`] and
//! either reject with `403` or open a raw TCP tunnel to the target.
//!
//! This is a *terminating* CONNECT forward proxy implemented directly on tokio.
//! Deeper HTTP request inspection (TLS termination, method/path/body rules) is a
//! later phase and is where a framework like Pingora earns its keep — see
//! [ADR-0002]. For host-level egress filtering, raw tunneling is simpler and correct.
//!
//! [ADR-0002]: ../../../.please/docs/decisions/0002-phase1-connect-proxy-on-tokio.md

use std::sync::Arc;
use std::time::Duration;

use honmoon_core::{
    AuditDraft, AuditLog, Decision, Facts, FactsSummary, HttpFacts, Policy, Verdict,
    decide_explained,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::approval::{ApprovalDecision, ApprovalRegistry, NewApproval};

const MAX_REQUEST_HEAD: usize = 8 * 1024;
/// Max time to receive the CONNECT request head before giving up (slowloris guard).
const HEAD_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a `pause`d request is held before it is auto-rejected (no approver).
pub const DEFAULT_PAUSE_TIMEOUT: Duration = Duration::from_secs(300);
/// In-memory audit ring size for ephemeral (`honmoon run`) proxies.
const DEFAULT_AUDIT_CAPACITY: usize = 1024;

/// Shared runtime state for the egress proxy.
///
/// The data plane (this crate) and the management API (`honmoon-mgmt`) both hold
/// the same `Arc`s, so a verdict recorded here is visible to the dashboard and an
/// approval resolved there wakes the held connection here.
#[derive(Clone)]
pub struct GatewayState {
    pub policy: Arc<Policy>,
    pub audit: Arc<AuditLog>,
    pub approvals: Arc<ApprovalRegistry>,
    /// How long to hold a `pause`d request before auto-rejecting it.
    pub pause_timeout: Duration,
}

impl GatewayState {
    /// State for a standalone/ephemeral proxy: in-memory audit, fresh approval
    /// registry, default pause timeout.
    pub fn new(policy: Policy) -> Self {
        Self {
            policy: Arc::new(policy),
            audit: Arc::new(AuditLog::new(DEFAULT_AUDIT_CAPACITY)),
            approvals: Arc::new(ApprovalRegistry::new()),
            pause_timeout: DEFAULT_PAUSE_TIMEOUT,
        }
    }
}

/// Bind `addr` and run the egress proxy, blocking forever (until process exit).
pub fn run(policy: Policy, addr: &str) -> ! {
    let listener = std::net::TcpListener::bind(addr).unwrap_or_else(|e| panic!("bind {addr}: {e}"));
    serve_listener(policy, listener)
}

/// Run the egress proxy on an already-bound listener, blocking forever.
///
/// Taking a pre-bound listener lets `honmoon run` hand off a socket it bound
/// itself — no free-port-then-rebind window (no TOCTOU race).
pub fn serve_listener(policy: Policy, listener: std::net::TcpListener) -> ! {
    let state = GatewayState::new(policy);
    serve_listener_with_state(state, listener)
}

/// Like [`serve_listener`], but with caller-provided shared [`GatewayState`] so
/// the management API can observe audit events and resolve held requests.
pub fn serve_listener_with_state(state: GatewayState, listener: std::net::TcpListener) -> ! {
    listener
        .set_nonblocking(true)
        .expect("set listener non-blocking");
    let runtime = tokio::runtime::Runtime::new().expect("build tokio runtime");
    runtime.block_on(serve(state, listener))
}

/// Run the accept loop on an existing tokio runtime (does not return).
///
/// Used when the proxy shares a runtime with the management API server.
pub async fn serve(state: GatewayState, std_listener: std::net::TcpListener) -> ! {
    std_listener
        .set_nonblocking(true)
        .expect("set listener non-blocking");
    let listener = TcpListener::from_std(std_listener).expect("adopt std listener");
    let addr = listener.local_addr().expect("listener addr");
    tracing::info!(%addr, "egress proxy listening");
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle(stream, &state).await {
                        tracing::debug!(%peer, error = %e, "connection ended");
                    }
                });
            }
            Err(e) => tracing::warn!(error = %e, "accept failed"),
        }
    }
}

/// Handle one client connection: parse the CONNECT request, apply policy, tunnel.
async fn handle(mut client: TcpStream, state: &GatewayState) -> std::io::Result<()> {
    let head = match tokio::time::timeout(HEAD_READ_TIMEOUT, read_head(&mut client)).await {
        Ok(result) => result?,
        Err(_elapsed) => return respond(&mut client, 408, "Request Timeout").await,
    };
    // None = EOF before terminator, or head exceeded MAX_REQUEST_HEAD — reject.
    let Some(head) = head else {
        return respond(&mut client, 400, "Bad Request").await;
    };
    let Some((method, target)) = parse_request_line(&head) else {
        return respond(&mut client, 400, "Bad Request").await;
    };

    if method != "CONNECT" {
        // Phase 1 only supports HTTPS egress via CONNECT tunneling.
        return respond(&mut client, 405, "Method Not Allowed").await;
    }

    let host = canonical_host(&target);
    // Over a CONNECT tunnel we only see the host; method/path/body remain unknown
    // until TLS termination (a later phase). Expose the host as `http.host` so
    // host-level CEL rules work today.
    let facts = Facts {
        domain: Some(host.clone()),
        http: Some(HttpFacts {
            host: host.clone(),
            ..Default::default()
        }),
        ..Default::default()
    };

    // Decide, record to the audit log, and — for `pause` — hold pending approval.
    if !authorize(&mut client, state, &facts).await? {
        return Ok(());
    }

    let mut upstream = match TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(%target, error = %e, "upstream connect failed");
            return respond(&mut client, 502, "Bad Gateway").await;
        }
    };

    tracing::debug!(domain = %host, %target, "egress allowed, tunneling");
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

/// Apply policy to `facts`, record the decision to the audit log, and — for a
/// `pause` verdict — hold the connection until a human resolves it.
///
/// Returns `Ok(true)` if the request may proceed to tunnel, `Ok(false)` if it
/// was answered (403) and is finished.
async fn authorize(
    client: &mut TcpStream,
    state: &GatewayState,
    facts: &Facts,
) -> std::io::Result<bool> {
    let outcome = decide_explained(&state.policy, facts);
    let summary = FactsSummary::from(facts);
    match outcome.verdict {
        Verdict::Allow => {
            state.audit.record(AuditDraft {
                decision: Decision::Allowed,
                verdict: Verdict::Allow,
                rule: outcome.rule,
                facts: summary,
                approval_id: None,
            });
            Ok(true)
        }
        Verdict::Deny => {
            tracing::info!(domain = ?facts.domain, rule = ?outcome.rule, "egress denied");
            state.audit.record(AuditDraft {
                decision: Decision::Denied,
                verdict: Verdict::Deny,
                rule: outcome.rule,
                facts: summary,
                approval_id: None,
            });
            respond(client, 403, "Forbidden").await?;
            Ok(false)
        }
        Verdict::Pause => hold_for_approval(client, state, facts, summary, outcome.rule).await,
    }
}

/// Hold a `pause`d request in the approval registry until a human approves or
/// rejects it (or the hold times out → reject). Records both the initial hold
/// and the final resolution to the audit log.
async fn hold_for_approval(
    client: &mut TcpStream,
    state: &GatewayState,
    facts: &Facts,
    summary: FactsSummary,
    rule: Option<String>,
) -> std::io::Result<bool> {
    let (pending, rx) = state.approvals.register(NewApproval {
        endpoint: facts.endpoint.clone(),
        domain: facts.domain.clone(),
        rule: rule.clone(),
        summary: summarize(facts, rule.as_deref()),
    });
    state.audit.record(AuditDraft {
        decision: Decision::Paused,
        verdict: Verdict::Pause,
        rule: rule.clone(),
        facts: summary.clone(),
        approval_id: Some(pending.id),
    });
    tracing::info!(id = pending.id, domain = ?facts.domain, "request held for approval");

    let decision = match tokio::time::timeout(state.pause_timeout, rx).await {
        Ok(Ok(d)) => d,
        // Registry dropped (shutdown) — treat as rejection.
        Ok(Err(_)) => ApprovalDecision::Reject,
        // Timed out waiting for a human — drop the slot and reject.
        Err(_elapsed) => {
            state.approvals.cancel(pending.id);
            tracing::info!(id = pending.id, "approval timed out");
            ApprovalDecision::Reject
        }
    };

    match decision {
        ApprovalDecision::Approve => {
            state.audit.record(AuditDraft {
                decision: Decision::Approved,
                verdict: Verdict::Pause,
                rule,
                facts: summary,
                approval_id: Some(pending.id),
            });
            Ok(true)
        }
        ApprovalDecision::Reject => {
            state.audit.record(AuditDraft {
                decision: Decision::Rejected,
                verdict: Verdict::Pause,
                rule,
                facts: summary,
                approval_id: Some(pending.id),
            });
            respond(client, 403, "Forbidden").await?;
            Ok(false)
        }
    }
}

/// A short human description of a held request, for the approval queue.
fn summarize(facts: &Facts, rule: Option<&str>) -> String {
    let what = if let Some(sql) = &facts.sql {
        format!("SQL {} {}", sql.verb, sql.table).trim().to_string()
    } else if let Some(k8s) = &facts.k8s {
        format!("k8s {} {} in {}", k8s.verb, k8s.resource, k8s.namespace)
    } else if let Some(domain) = &facts.domain {
        format!("CONNECT {domain}")
    } else {
        "request".to_string()
    };
    match rule {
        Some(r) => format!("{what} (rule: {r})"),
        None => what,
    }
}

/// Read the request head up to the blank line, without consuming tunnel bytes.
///
/// Returns `Some(head)` only when terminated by `\r\n\r\n`. Returns `None` if the
/// peer closed before the terminator or the head exceeded `MAX_REQUEST_HEAD`, so
/// the caller rejects partial/oversized heads rather than tunneling on them.
async fn read_head(client: &mut TcpStream) -> std::io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let n = client.read(&mut byte).await?;
        if n == 0 {
            return Ok(None); // EOF before the terminator
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(Some(buf));
        }
        if buf.len() > MAX_REQUEST_HEAD {
            return Ok(None); // oversized — do not proceed
        }
    }
}

/// Parse `METHOD TARGET VERSION` from the first request line.
fn parse_request_line(head: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(head).ok()?;
    let line = text.lines().next()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    Some((method, target))
}

/// Extract the host from a CONNECT `host:port` authority (handles IPv6 `[::1]:443`).
fn host_of(target: &str) -> &str {
    if let Some(rest) = target.strip_prefix('[') {
        // IPv6 literal: [addr]:port
        return rest.split(']').next().unwrap_or(rest);
    }
    target.rsplit_once(':').map(|(h, _)| h).unwrap_or(target)
}

/// Canonicalize the CONNECT host for policy evaluation: strip the port, drop a
/// trailing dot (FQDN root), and lowercase. Without this, `GitHub.com` or
/// `github.com.` could bypass a `github.com` rule.
fn canonical_host(target: &str) -> String {
    host_of(target).trim_end_matches('.').to_ascii_lowercase()
}

async fn respond(client: &mut TcpStream, status: u16, reason: &str) -> std::io::Result<()> {
    let msg =
        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    client.write_all(msg.as_bytes()).await?;
    client.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_line() {
        let (m, t) = parse_request_line(b"CONNECT github.com:443 HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(m, "CONNECT");
        assert_eq!(t, "github.com:443");
    }

    #[test]
    fn host_of_strips_port() {
        assert_eq!(host_of("github.com:443"), "github.com");
        assert_eq!(host_of("[::1]:443"), "::1");
        assert_eq!(host_of("nohost"), "nohost");
    }

    #[test]
    fn canonical_host_lowercases_and_trims_dot() {
        assert_eq!(canonical_host("GitHub.com:443"), "github.com");
        assert_eq!(canonical_host("github.com.:443"), "github.com");
        assert_eq!(canonical_host("API.Example.COM:8443"), "api.example.com");
    }
}
