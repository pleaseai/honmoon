//! HTTP CONNECT egress gateway (Phase 1 + Phase 5 TLS termination).
//!
//! Agents point `https_proxy` at this proxy. The client issues `CONNECT
//! host:port`; the [`HonmoonHandler`] evaluates the target host against the
//! [`Policy`] and either rejects it (`403`), holds it for approval (`pause`), or
//! lets the tunnel proceed.
//!
//! The proxy runs on [`hudsucker`], a MITM HTTP/S proxy (see [ADR-0003]). Tunnels
//! selected by [`InterceptPolicy`] are **TLS-terminated**: honmoon mints a
//! per-host leaf certificate from a local CA (the agent must trust it), decrypts
//! the inner HTTP, scans request bodies for PII, optionally rewrites secrets and
//! Tier-1 PII to deterministic placeholders, then re-encrypts to the real
//! upstream. Known placeholders in identity-encoded responses are restored for
//! the agent. Non-intercepted tunnels are forwarded raw, so host-level egress
//! filtering keeps working without decryption.
//!
//! [ADR-0003]: ../../../.please/docs/decisions/0003-adopt-hudsucker-for-tls-termination.md

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use honmoon_core::{AuditLog, MappingStore, Policy};
use hudsucker::Proxy;
use hudsucker::rustls::crypto::aws_lc_rs;
use tokio::net::TcpListener;

use crate::approval::ApprovalRegistry;
use crate::ca::CaMaterial;
use crate::mitm::HonmoonHandler;

/// How long a `pause`d request is held before it is auto-rejected (no approver).
pub const DEFAULT_PAUSE_TIMEOUT: Duration = Duration::from_secs(300);
/// In-memory audit ring size for ephemeral (`honmoon run`) proxies.
const DEFAULT_AUDIT_CAPACITY: usize = 1024;

/// Which tunnels to TLS-terminate (MITM) for content inspection.
///
/// Host-level policy (allow/deny/pause) is applied on the CONNECT regardless;
/// this only decides whether the tunnel is decrypted to inspect its contents.
#[derive(Clone, Debug, Default)]
pub enum InterceptPolicy {
    /// Never terminate — forward every tunnel raw (host-level filtering only).
    /// The safe default and the Phase 1 behavior.
    #[default]
    None,
    /// Terminate every allowed tunnel (full content inspection).
    All,
    /// Terminate only these canonicalized hosts; forward the rest raw.
    Hosts(HashSet<String>),
}

/// Whether body PII findings only inform audit events or enforce policy verdicts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PiiMode {
    /// Evaluate PII rules for audit visibility, but always forward the request.
    #[default]
    Detect,
    /// Enforce the policy verdict produced from the request and its PII facts.
    Block,
}

/// Wire-level secret redaction: present only when the operator opted in with
/// `--redact-secrets`.
#[derive(Clone)]
pub struct RedactionState {
    /// HMAC salt behind placeholder minting — the same derived salt the
    /// management hook endpoint uses, so hook and wire tokens match.
    pub salt: Arc<Vec<u8>>,
    /// Live placeholder→secret store shared with the management hook endpoint —
    /// one gateway process, one mapping.
    pub mappings: Arc<MappingStore>,
}

impl RedactionState {
    /// Create enabled wire-redaction state with a known-valid HMAC salt.
    pub fn new(salt: Vec<u8>) -> Self {
        // An empty HMAC key makes placeholders reproducible for known secrets;
        // reject that caller programming error before any traffic is handled.
        assert!(!salt.is_empty(), "redaction salt must not be empty");
        Self {
            salt: Arc::new(salt),
            mappings: Arc::new(MappingStore::new()),
        }
    }
}

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
    /// Local CA used to mint per-host leaf certs for TLS termination.
    pub ca: Arc<CaMaterial>,
    /// Which tunnels to TLS-terminate.
    pub intercept: InterceptPolicy,
    /// Whether PII policy verdicts are audit-only or enforced inline.
    pub pii_mode: PiiMode,
    /// Optional wire-level request redaction and response detokenization state.
    pub redaction: Option<RedactionState>,
}

impl GatewayState {
    /// State for a standalone/ephemeral proxy: in-memory audit, fresh approval
    /// registry, default pause timeout, an ephemeral in-memory CA, and no TLS
    /// interception (raw tunneling — host-level filtering only).
    pub fn new(policy: Policy) -> Self {
        Self {
            policy: Arc::new(policy),
            audit: Arc::new(AuditLog::new(DEFAULT_AUDIT_CAPACITY)),
            approvals: Arc::new(ApprovalRegistry::new()),
            pause_timeout: DEFAULT_PAUSE_TIMEOUT,
            ca: Arc::new(CaMaterial::generate().expect("generate ephemeral CA")),
            intercept: InterceptPolicy::None,
            pii_mode: PiiMode::Detect,
            redaction: None,
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

    let authority = state.ca.authority().expect("build CA authority");
    let handler = HonmoonHandler::new(state);

    let proxy = Proxy::builder()
        .with_listener(listener)
        .with_ca(authority)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(handler)
        .build()
        .expect("build proxy");

    tracing::info!(%addr, "egress proxy listening");
    match proxy.start().await {
        Ok(()) => panic!("egress proxy stopped unexpectedly"),
        Err(e) => panic!("egress proxy failed: {e}"),
    }
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
pub(crate) fn canonical_host(target: &str) -> String {
    host_of(target).trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

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
