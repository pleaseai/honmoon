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

use std::borrow::Cow;
use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use hmac::{Hmac, Mac};
use honmoon_core::{
    AuditEvent, MappingStore, PathResolution, Policy, claude_code_hook_verdict, derive_hook_salt,
    hook_salt_context, is_sensitive_path,
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

/// How the hook endpoint keys placeholder minting.
///
/// The command transport (`honmoon hook`) derives its salt from the payload's
/// `session_id`, so this endpoint must too — otherwise a session that mixes
/// transports mints two different placeholders for one secret and the prompt
/// prefix stops being byte-stable across turns (#98).
#[derive(Clone)]
pub enum HookSalt {
    /// One salt for every request: the operator pinned a salt context
    /// (`--hook-salt-context`, matching `honmoon hook --salt-context`), or a
    /// test pinned raw bytes.
    Fixed(HookKey),
    /// Derived per request from the payload's `session_id`, keyed by the
    /// machine salt — byte-identical to what `honmoon hook` derives for the
    /// same session on the same machine.
    PerSession(HookKey),
}

/// Validated HMAC key material held by a [`HookSalt`].
///
/// A Rust enum variant's fields are always as public as the enum itself, so
/// carrying the bytes inline would let any caller write
/// `HookSalt::Fixed { salt: Arc::new(vec![]) }` and walk straight past the
/// emptiness check the constructors exist to enforce. The bytes live behind
/// this newtype's private field instead: outside this module the only way to
/// obtain one is [`HookSalt::fixed`] or [`HookSalt::per_session`], and pattern
/// matching a variant yields a `HookKey` whose contents stay unreadable — which
/// also keeps `PerSession`'s machine secret off the crate's public surface.
#[derive(Clone)]
pub struct HookKey(Arc<Vec<u8>>);

impl HookKey {
    /// **Panics** on empty bytes: an empty HMAC key makes placeholders for
    /// known secrets precomputable.
    fn new(bytes: Vec<u8>, what: &str) -> Self {
        assert!(!bytes.is_empty(), "{what} must not be empty");
        Self(Arc::new(bytes))
    }

    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl HookSalt {
    /// Pin one salt for every request.
    ///
    /// **Panics** on empty bytes (see [`HookKey`]).
    pub fn fixed(salt: Vec<u8>) -> Self {
        Self::Fixed(HookKey::new(salt, "hook salt"))
    }

    /// Derive each request's salt from its session, keyed by `machine_key` —
    /// the secret persisted at `~/.honmoon/hook-salt` (see `honmoon-cli`'s
    /// `hook::machine_key`).
    ///
    /// **Panics** on an empty key, for the same reason as [`Self::fixed`].
    pub fn per_session(machine_key: Vec<u8>) -> Self {
        Self::PerSession(HookKey::new(machine_key, "hook machine key"))
    }

    /// The salt this payload's placeholders are minted under.
    fn for_payload(&self, payload: &serde_json::Value) -> Cow<'_, [u8]> {
        match self {
            Self::Fixed(salt) => Cow::Borrowed(salt.as_slice()),
            Self::PerSession(machine_key) => Cow::Owned(derive_hook_salt(
                machine_key.as_slice(),
                hook_salt_context(None, payload),
            )),
        }
    }

    /// The one salt every request uses, when there is one.
    fn pinned(&self) -> Option<&[u8]> {
        match self {
            Self::Fixed(salt) => Some(salt.as_slice()),
            Self::PerSession(_) => None,
        }
    }
}

/// Shared state for the management API: the gateway runtime state plus the raw
/// policy source (for the dashboard's read-only policy view/editor).
#[derive(Clone)]
pub struct AppState {
    pub gateway: GatewayState,
    pub policy_yaml: Arc<String>,
    /// How gateway-direct hook redaction keys its HMAC.
    pub hook_salt: HookSalt,
    /// Live reverse mappings introduced by hook and proxy-wire redaction.
    ///
    /// When wire redaction is enabled this is the exact store held by the proxy:
    /// one gateway process, one mapping.
    pub hook_mappings: Arc<MappingStore>,
    /// Optional bearer credential protecting the hook endpoint.
    pub hook_token: Option<Arc<str>>,
}

impl AppState {
    /// Build state with an explicit hook salt source and optional bearer token.
    ///
    /// There is deliberately no salt-less constructor: the hook salt keys the
    /// HMAC that derives redaction placeholders, so baking in a fixed default
    /// would make placeholders for known secrets precomputable. Callers must
    /// supply securely sourced key material (see `honmoon-cli`'s
    /// `hook::machine_key`).
    pub fn with_hook_config(
        gateway: GatewayState,
        policy_yaml: impl Into<String>,
        hook_salt: HookSalt,
        hook_token: Option<String>,
    ) -> Self {
        // Hook and wire redaction share one mapping store, so where both key on
        // one pinned salt they must key on the *same* one; enforce it here so a
        // future caller can't silently diverge them and break cache-stable
        // determinism. Nothing to enforce for a per-session hook salt: wire
        // redaction is process-scoped (the proxy sees connections, not
        // sessions), so it deliberately keys on the gateway's own context while
        // the hook transports key on the session they share. Detokenization is
        // a store lookup, so both mintings restore either way.
        if let (Some(redaction), Some(pinned)) = (gateway.redaction.as_ref(), hook_salt.pinned()) {
            assert!(
                redaction.salt.as_slice() == pinned,
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
            hook_salt,
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
///
/// Placeholder minting is deterministic in `(salt, secret)` and the salt follows
/// the caller's own `session_id`, so anyone who can reach this endpoint can mint
/// the placeholder a named session would produce for a guessed secret and
/// compare it against one observed in that session's transcript. That confirms a
/// guess; it never reveals a secret or the machine key, and the local command
/// transport has always offered the same confirmation to anyone able to run
/// `honmoon hook --salt-context`. Keep the listener on loopback (the
/// `--mgmt-addr` default) and set `--hook-token` before exposing it further.
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
    let salt = state.hook_salt.for_payload(&payload);
    let verdict = claude_code_hook_verdict(&payload, &salt, resolution);
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
/// instead of silently evaluating "not sensitive". An *absolute* path that is
/// genuinely absent (confirmed via `symlink_metadata`) keeps command-transport
/// parity: it is the legitimate not-yet-created-file case, and core's literal
/// path check still applies. An existing dangling symlink, or any other
/// canonicalize failure (a permission-denied or looping component that hides a
/// symlink), is [`PathResolution::Unresolved`] — not silently allowed.
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
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // `canonicalize` also returns `NotFound` for an *existing* dangling
                // symlink (the link is present, its target is not) — a `Write`
                // through it would create the hidden target, so it must not be
                // treated as a new file. `symlink_metadata` does not follow the
                // final component: `NotFound` there means the path genuinely does
                // not exist (the legitimate not-yet-created-file case, command-
                // transport parity — core's literal path check still applies).
                // Anything else means the path exists but could not be verified —
                // stay conservative rather than fail open (issue #55).
                match tokio::fs::symlink_metadata(path).await {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        PathResolution::NotSensitive
                    }
                    _ => PathResolution::Unresolved,
                }
            }
            // Any other error — permission denied, symlink loop, an unreadable
            // path component — means the target could not be verified: deny.
            Err(_) => PathResolution::Unresolved,
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

    #[cfg(unix)]
    #[tokio::test]
    async fn absolute_path_failing_canonicalize_non_notfound_is_unresolved() {
        // A symlink loop makes `canonicalize` fail with an error that is *not*
        // `NotFound`, so the target was never verified — it could hide a
        // sensitive symlink the gateway can't traverse. Only a genuinely
        // missing file (`NotFound`) is the legitimate new-file case; any other
        // error must stay conservative (`Unresolved`, deny) rather than fail
        // open to `NotSensitive` — the absolute-path analogue of issue #55.
        let tmp = TempDir::new("absolute-loop");
        let link = tmp.path().join("loop");
        std::os::unix::fs::symlink(&link, &link).unwrap();
        assert_eq!(
            resolve_agent_path(Some(&link.to_string_lossy()), None).await,
            PathResolution::Unresolved
        );
    }

    #[tokio::test]
    async fn relative_ordinary_path_resolves_against_agent_cwd_not_sensitive() {
        // The common case: an ordinary agent-relative file anchored to the
        // payload `cwd` resolves and is allowed. The fail-closed fix must not
        // deny normal Read/Edit/Write of non-sensitive files.
        let tmp = TempDir::new("relative-ordinary");
        std::fs::write(tmp.path().join("main.rs"), b"fn main() {}").unwrap();
        assert_eq!(
            resolve_agent_path(Some("main.rs"), Some(&tmp.path().to_string_lossy())).await,
            PathResolution::NotSensitive
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn absolute_dangling_symlink_is_not_a_new_file() {
        // A benign-named symlink whose sensitive target does not exist yet:
        // `canonicalize` returns `NotFound` (the target is missing), but the
        // link itself exists, so a `Write` through it would create the hidden
        // sensitive target. It must NOT be treated as a new file — `Unresolved`
        // (deny), distinguished from a genuinely absent path via
        // `symlink_metadata` (Greptile/cubic issue #55 follow-up).
        let tmp = TempDir::new("dangling-symlink");
        let link = tmp.path().join("config");
        std::os::unix::fs::symlink(tmp.path().join("server.pem"), &link).unwrap();
        assert!(
            tokio::fs::canonicalize(&link).await.is_err(),
            "target is missing"
        );
        assert_eq!(
            resolve_agent_path(Some(&link.to_string_lossy()), None).await,
            PathResolution::Unresolved
        );
    }
}
