//! Honmoon management API (Phase 4).
//!
//! A small axum service that runs **in the same process as the data plane** so
//! it can both observe decisions and resolve held requests. It exposes:
//!
//! - `GET  /api/audit?limit=N` — recent audit events, newest first
//! - `GET  /api/approvals`     — requests held pending approval
//! - `POST /api/approvals/:id/approve` / `.../reject` — resolve a held request
//! - `GET  /api/policy`        — the active policy (raw YAML + parsed)
//! - `POST /api/hooks/claude-code` — Claude Code hook verdict transport
//! - `GET  /healthz`
//! - everything else — the embedded React dashboard (SPA fallback)
//!
//! The dashboard is compiled into the binary with [`rust_embed`] from
//! `apps/dashboard/dist`; build it (`bun run --filter @honmoon/dashboard build`)
//! before a release `cargo build`.

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use hmac::{Hmac, Mac};
use honmoon_core::{
    AuditEvent, MappingStore, PathResolution, Policy, claude_code_hook_verdict, is_sensitive_path,
};
use honmoon_proxy::approval::{ApprovalDecision, PendingApproval};
use honmoon_proxy::gateway::GatewayState;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Embedded dashboard assets (built by Vite into `apps/dashboard/dist`).
///
/// In debug builds rust-embed reads these from disk at runtime, so `vite` and
/// `cargo` can iterate independently; release builds embed them in the binary.
#[derive(rust_embed::Embed)]
#[folder = "../../apps/dashboard/dist"]
struct Assets;

/// Shared state for the management API: the gateway runtime state plus the raw
/// policy source (for the dashboard's read-only policy view/editor).
#[derive(Clone)]
pub struct AppState {
    pub gateway: GatewayState,
    pub policy_yaml: Arc<String>,
    /// Stable HMAC salt used by gateway-direct hook redaction.
    pub hook_salt: Arc<Vec<u8>>,
    /// Live reverse mappings introduced by hook and proxy-wire redaction.
    ///
    /// When wire redaction is enabled this is the exact store held by the proxy:
    /// one gateway process, one mapping.
    pub hook_mappings: Arc<MappingStore>,
    /// Optional bearer credential protecting the hook endpoint.
    pub hook_token: Option<Arc<str>>,
}

impl AppState {
    /// Build state with explicit hook salt and optional bearer token.
    ///
    /// There is deliberately no salt-less constructor: the hook salt keys the
    /// HMAC that derives redaction placeholders, so baking in a fixed default
    /// would make placeholders for known secrets precomputable. Callers must
    /// supply a securely sourced salt (see `honmoon-cli`'s `derive_salt_context`).
    pub fn with_hook_config(
        gateway: GatewayState,
        policy_yaml: impl Into<String>,
        hook_salt: Vec<u8>,
        hook_token: Option<String>,
    ) -> Self {
        assert!(!hook_salt.is_empty(), "hook salt must not be empty");
        // Hook and wire redaction share one mapping store, so they must mint the
        // same placeholder for a given secret — which only holds if they key the
        // HMAC with the same salt. The CLI upholds this by deriving one salt for
        // both; enforce it here so a future caller can't silently diverge the two
        // transports and break cache-stable determinism.
        if let Some(redaction) = gateway.redaction.as_ref() {
            assert!(
                redaction.salt.as_slice() == hook_salt.as_slice(),
                "hook salt must match the wire redaction salt so both transports mint identical placeholders"
            );
        }
        let hook_mappings = gateway
            .redaction
            .as_ref()
            .map(|redaction| Arc::clone(&redaction.mappings))
            .unwrap_or_else(|| Arc::new(MappingStore::new()));
        Self {
            gateway,
            policy_yaml: Arc::new(policy_yaml.into()),
            hook_salt: Arc::new(hook_salt),
            hook_mappings,
            hook_token: hook_token.map(Arc::from),
        }
    }
}

/// Build the management API router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/audit", get(list_audit))
        .route("/api/approvals", get(list_approvals))
        .route("/api/approvals/{id}/approve", post(approve))
        .route("/api/approvals/{id}/reject", post(reject))
        .route("/api/hooks/claude-code", post(claude_code_hook))
        .route("/api/policy", get(get_policy))
        .fallback(static_handler)
        .with_state(state)
}

/// Serve the management API on an already-bound listener until the process exits.
pub async fn serve(state: AppState, listener: std::net::TcpListener) -> std::io::Result<()> {
    listener.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(listener)?;
    let addr = listener.local_addr()?;
    tracing::info!(%addr, "management API listening");
    axum::serve(listener, router(state)).await
}

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

/// Evaluate the unwrapped Claude Code hook payload and return its standard
/// verdict JSON. If `hook_token` is configured, callers must send exactly
/// `Authorization: Bearer <token>`.
///
/// Claude Code HTTP hooks fail open on connection errors, timeouts, and non-2xx
/// responses: processing continues without applying a verdict. That is why the
/// plugin defaults to the command transport, which can perform local fallback.
async fn claude_code_hook(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<serde_json::Value>,
) -> Response {
    if !authorized(&state, &headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "missing or invalid bearer token" })),
        )
            .into_response();
    }

    let path_to_resolve = payload
        .get("tool_input")
        .and_then(|input| {
            input
                .get("file_path")
                .or_else(|| input.get("notebook_path"))
        })
        .and_then(serde_json::Value::as_str);
    let agent_cwd = payload.get("cwd").and_then(serde_json::Value::as_str);
    let resolution = resolve_agent_path(path_to_resolve, agent_cwd).await;
    let verdict = claude_code_hook_verdict(&payload, &state.hook_salt, resolution);
    let (output, mapping) = verdict.into_parts();
    state.hook_mappings.record(mapping);
    (StatusCode::OK, Json(output)).into_response()
}

/// Resolve the tool's file path in the **agent's** filesystem context, never
/// against the gateway process's cwd.
///
/// The agent (Claude Code) and the gateway generally run in different
/// directories, so canonicalizing an agent-relative path directly would either
/// fail — silently skipping the symlink-based sensitive-path deny (issue #55) —
/// or, worse, resolve an unrelated same-named file in the gateway's own cwd.
/// Claude Code hook payloads carry the agent's `cwd`, so relative paths are
/// anchored there first. When resolution is still impossible — no usable
/// absolute `cwd`, or the anchored path does not exist on this host (e.g. a
/// gateway that cannot see the agent's filesystem) — the check reports
/// [`PathResolution::Unresolved`], which `PreToolUse` denies conservatively
/// instead of silently evaluating "not sensitive". An *absolute* path that
/// fails to canonicalize keeps command-transport parity: it is the legitimate
/// not-yet-created-file case, and core's literal path check still applies.
///
/// Symlinks resolve off the async executor: `tokio::fs::canonicalize` hands the
/// blocking syscall to the runtime's blocking pool, so concurrent hook requests
/// don't stall the Tokio worker thread. `to_string_lossy` keeps a non-UTF-8
/// path checked (fail toward denying) rather than skipped.
async fn resolve_agent_path(path: Option<&str>, agent_cwd: Option<&str>) -> PathResolution {
    let Some(path) = path else {
        return PathResolution::NotSensitive;
    };
    let sensitivity = |canonical: std::path::PathBuf| {
        if is_sensitive_path(&canonical.to_string_lossy()) {
            PathResolution::Sensitive
        } else {
            PathResolution::NotSensitive
        }
    };
    if std::path::Path::new(path).is_absolute() {
        return match tokio::fs::canonicalize(path).await {
            Ok(canonical) => sensitivity(canonical),
            Err(_) => PathResolution::NotSensitive,
        };
    }
    let Some(cwd) = agent_cwd
        .map(std::path::Path::new)
        .filter(|cwd| cwd.is_absolute())
    else {
        return PathResolution::Unresolved;
    };
    match tokio::fs::canonicalize(cwd.join(path)).await {
        Ok(canonical) => sensitivity(canonical),
        Err(_) => PathResolution::Unresolved,
    }
}

fn authorized(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(expected) = state.hook_token.as_deref() else {
        return true;
    };
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|provided| constant_time_eq(provided.as_bytes(), expected.as_bytes()))
}

/// Constant-time equality for authenticating the caller-supplied bearer token
/// against the configured secret.
///
/// Both inputs are folded through HMAC-SHA256 into a fixed 32-byte digest before
/// comparison, so the comparison length is independent of either input's length
/// — closing even the theoretical leak of the secret's length through absolute
/// timing. `CtOutput`'s `PartialEq` compares the digests in constant time (via
/// `subtle`). The key is a public constant: it only maps inputs to a fixed
/// width for comparison, so it need not be secret.
fn constant_time_eq(provided: &[u8], expected: &[u8]) -> bool {
    const KEY: &[u8] = b"honmoon-bearer-token-comparison";
    let digest = |data: &[u8]| {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(KEY).expect("HMAC accepts a key of any length");
        mac.update(data);
        mac.finalize()
    };
    digest(provided) == digest(expected)
}

#[derive(Debug, Deserialize)]
struct AuditQuery {
    limit: Option<usize>,
}

/// Recent audit events, newest first. `?limit=` caps the count (default 200).
async fn list_audit(
    State(s): State<AppState>,
    Query(q): Query<AuditQuery>,
) -> Json<Vec<AuditEvent>> {
    let limit = q.limit.unwrap_or(200).min(1000);
    Json(s.gateway.audit.recent(limit))
}

async fn list_approvals(State(s): State<AppState>) -> Json<Vec<PendingApproval>> {
    Json(s.gateway.approvals.pending())
}

#[derive(Debug, Serialize)]
struct ResolveResponse {
    resolved: PendingApproval,
}

async fn approve(State(s): State<AppState>, Path(id): Path<u64>) -> Response {
    resolve(&s, id, ApprovalDecision::Approve)
}

async fn reject(State(s): State<AppState>, Path(id): Path<u64>) -> Response {
    resolve(&s, id, ApprovalDecision::Reject)
}

fn resolve(s: &AppState, id: u64, decision: ApprovalDecision) -> Response {
    match s.gateway.approvals.resolve(id, decision) {
        Some(info) => (StatusCode::OK, Json(ResolveResponse { resolved: info })).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "no such pending approval" })),
        )
            .into_response(),
    }
}

#[derive(Debug, Serialize)]
struct PolicyResponse {
    yaml: String,
    parsed: Policy,
}

async fn get_policy(State(s): State<AppState>) -> Json<PolicyResponse> {
    Json(PolicyResponse {
        yaml: (*s.policy_yaml).clone(),
        parsed: (*s.gateway.policy).clone(),
    })
}

/// Serve an embedded dashboard asset, falling back to `index.html` so client-side
/// routing works (SPA). Returns 404 only when the dashboard was not built in.
async fn static_handler(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');

    // Never SPA-fallback an unmatched API path — that would mask routing
    // mistakes (and failed management actions) as a `200 text/html`. Let those
    // 404 honestly.
    if path == "api" || path.starts_with("api/") {
        return (StatusCode::NOT_FOUND, "no such API route").into_response();
    }

    let path = if path.is_empty() { "index.html" } else { path };

    if let Some(asset) = Assets::get(path) {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        return (
            [(header::CONTENT_TYPE, mime.as_ref())],
            asset.data.into_owned(),
        )
            .into_response();
    }

    // SPA fallback: serve index.html for unknown non-asset paths.
    match Assets::get("index.html") {
        Some(asset) => Html(asset.data.into_owned()).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            "dashboard not built — run `bun run --filter @honmoon/dashboard build`",
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::{PathResolution, constant_time_eq, resolve_agent_path};

    #[test]
    fn constant_time_eq_matches_only_identical_secrets() {
        assert!(constant_time_eq(b"s3cr3t-token", b"s3cr3t-token"));
        assert!(constant_time_eq(b"", b""));
        // Same length, one byte differs (`0` vs `o`).
        assert!(!constant_time_eq(b"s3cr3t-t0ken", b"s3cr3t-token"));
        // Shorter and longer provided tokens both fail, even on a matching prefix.
        assert!(!constant_time_eq(b"s3cr3t", b"s3cr3t-token"));
        assert!(!constant_time_eq(b"s3cr3t-token-extra", b"s3cr3t-token"));
        assert!(!constant_time_eq(b"", b"s3cr3t-token"));
    }

    /// Throwaway temp dir under the OS temp root, removed on drop. The `tag`
    /// keeps concurrently-running tests from colliding on the same path (no
    /// `tempfile` dev-dependency in this workspace).
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("honmoon-mgmt-test-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("creating temp dir");
            TempDir(dir)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn missing_path_is_not_sensitive() {
        assert_eq!(
            resolve_agent_path(None, Some("/tmp")).await,
            PathResolution::NotSensitive
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn relative_symlink_resolves_against_agent_cwd() {
        // The issue #55 scenario: an innocuously-named relative symlink pointing
        // at key material. Anchored to the agent's `cwd` from the payload, the
        // gateway resolves it and the sensitive-path deny fires — previously
        // `canonicalize` ran against the gateway's own cwd, failed, and the
        // check was silently skipped.
        let tmp = TempDir::new("relative-symlink");
        std::fs::write(tmp.path().join("server.pem"), b"key material").unwrap();
        std::os::unix::fs::symlink(tmp.path().join("server.pem"), tmp.path().join("config"))
            .unwrap();
        assert_eq!(
            resolve_agent_path(Some("config"), Some(&tmp.path().to_string_lossy())).await,
            PathResolution::Sensitive
        );
    }

    #[tokio::test]
    async fn relative_path_without_agent_cwd_is_unresolved() {
        // No `cwd` in the payload (or a non-absolute one): the gateway must not
        // fall back to its own cwd — a same-named file there could resolve to a
        // false "not sensitive".
        assert_eq!(
            resolve_agent_path(Some("config"), None).await,
            PathResolution::Unresolved
        );
        assert_eq!(
            resolve_agent_path(Some("config"), Some("relative/cwd")).await,
            PathResolution::Unresolved
        );
    }

    #[tokio::test]
    async fn relative_path_missing_on_this_host_is_unresolved() {
        // Anchored but nonexistent here: possibly a gateway that cannot see the
        // agent's filesystem hiding an agent-side symlink — stay conservative.
        let tmp = TempDir::new("missing-relative");
        assert_eq!(
            resolve_agent_path(Some("no-such-file"), Some(&tmp.path().to_string_lossy())).await,
            PathResolution::Unresolved
        );
    }

    #[tokio::test]
    async fn absolute_missing_path_keeps_command_transport_parity() {
        // A not-yet-created file addressed absolutely stays writable: the
        // literal path check in core still applies to the raw string.
        let tmp = TempDir::new("missing-absolute");
        let path = tmp.path().join("new-file.rs");
        assert_eq!(
            resolve_agent_path(Some(&path.to_string_lossy()), None).await,
            PathResolution::NotSensitive
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn absolute_symlink_to_sensitive_target_is_sensitive() {
        let tmp = TempDir::new("absolute-symlink");
        std::fs::write(tmp.path().join("server.pem"), b"key material").unwrap();
        let link = tmp.path().join("config");
        std::os::unix::fs::symlink(tmp.path().join("server.pem"), &link).unwrap();
        assert_eq!(
            resolve_agent_path(Some(&link.to_string_lossy()), None).await,
            PathResolution::Sensitive
        );
    }
}
