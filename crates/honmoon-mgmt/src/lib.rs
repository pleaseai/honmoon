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
//! - `GET  /login?token=…` — exchange the management token for a session cookie
//! - `GET  /healthz`
//! - everything else — the embedded React dashboard (SPA fallback)
//!
//! **Every `/api/*` route requires the management token** (#173): the read
//! surface serves every domain the agent contacted, every request path, every
//! SQL table, every PII category, the pending approval queue and the active
//! policy, so it is gated exactly as the hook write endpoint always was. The
//! token is not optional — [`AppState`] holds a `String`, not an `Option`, so
//! there is no unauthenticated mode to configure into. `/healthz` and the
//! dashboard's own static assets stay open: the first carries no data, and the
//! second is the published binary's own bundled code.
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
    /// The credential every `/api/*` route requires, as
    /// `Authorization: Bearer <token>` or the [`SESSION_COOKIE`] a browser
    /// obtains from `GET /login?token=…`.
    ///
    /// Deliberately not an `Option` (#173). An optional token means the crate
    /// still ships an unauthenticated mode, one call site away from being the
    /// defect this gate exists to close — and every test constructing state
    /// without a token would exercise it. Callers that have no token of their
    /// own must generate one (`honmoon-cli`'s `mgmt_token::resolve` persists one
    /// at `~/.honmoon/mgmt-token`), not pass `None`.
    ///
    /// Crate-private on purpose. The empty-token check lives in
    /// [`AppState::with_hook_config`], and a `pub` field would let any caller
    /// skip it with a struct literal — an empty token satisfies *both*
    /// credential arms, since the session cookie is an HMAC under a hardcoded,
    /// public key and `HMAC(key, "")` is computable by anyone. One non-`pub`
    /// field makes the literal unavailable outside this crate, so the
    /// constructor is the only way in.
    pub(crate) mgmt_token: Arc<str>,
}

impl AppState {
    /// Build state with an explicit hook salt source and the management token.
    ///
    /// There is deliberately no salt-less constructor: the hook salt keys the
    /// HMAC that derives redaction placeholders, so baking in a fixed default
    /// would make placeholders for known secrets precomputable. Callers must
    /// supply securely sourced key material (see `honmoon-cli`'s
    /// `hook::machine_key`).
    ///
    /// **Panics** on an empty `mgmt_token`: an empty credential authenticates
    /// every caller, which is the unauthenticated mode this type exists to make
    /// unrepresentable.
    pub fn with_hook_config(
        gateway: GatewayState,
        policy_yaml: impl Into<String>,
        hook_salt: HookSalt,
        mgmt_token: String,
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
        // Trimmed, because the CLI and TypeScript resolvers both reject a
        // whitespace-only token and this assert is the last line of defence for
        // anyone constructing the state another way. A lone space would
        // otherwise authenticate: `GET /login?token=%20` matches it and mints a
        // session cookie good for every `/api/*` route.
        assert!(
            !mgmt_token.trim().is_empty(),
            "management token must not be empty or whitespace-only — such a credential authenticates everyone"
        );
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
            mgmt_token: Arc::from(mgmt_token),
        }
    }
}

/// Build the management API router.
///
/// Every `/api/*` route sits behind one [`require_credential`] layer rather than
/// a per-handler check (#173). A handler that forgets to call the guard is the
/// defect this closes, so the guard is not something a handler can forget: a
/// route added to `api` below is gated by construction. `route_layer` applies
/// only to routes this router *matches*, so an unknown `/api/...` path still
/// falls through to [`static_handler`]'s honest 404 instead of answering 401 and
/// implying the route exists.
pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/audit", get(list_audit))
        .route("/approvals", get(list_approvals))
        .route("/approvals/{id}/approve", post(approve))
        .route("/approvals/{id}/reject", post(reject))
        .route("/hooks/claude-code", post(claude_code_hook))
        .route("/policy", get(get_policy))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_credential,
        ));

    Router::new()
        .route("/healthz", get(healthz))
        .route("/login", get(login))
        .nest("/api", api)
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
/// verdict JSON.
///
/// Authentication is not checked here: this route is mounted under the `/api`
/// router, whose [`require_credential`] layer has already rejected a caller
/// without the management token. Checking again would be the only copy of the
/// rule that a new route could be added without.
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
/// `--mgmt-addr` default) before exposing it further; the management token
/// (`--mgmt-token`) is required on this route either way.
async fn claude_code_hook(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Response {
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

/// Name of the cookie a browser presents instead of a bearer header.
pub const SESSION_COOKIE: &str = "honmoon_session";

/// Which credential authenticated a request, because the two need different
/// treatment on a state-changing route (see [`require_credential`]).
enum Credential {
    /// `Authorization: Bearer <token>` — sent deliberately by the caller, so a
    /// cross-site page cannot cause one (setting the header cross-origin needs a
    /// CORS preflight this service never approves).
    Bearer,
    /// The [`SESSION_COOKIE`] — attached by the browser rather than by the page,
    /// so it is the credential a cross-site request can ride on.
    Session,
}

/// The cookie value that stands in for `token`.
///
/// An HMAC of the token rather than the token itself, for two reasons. It is
/// fixed-width hex, so an operator-chosen `--mgmt-token` containing `;`, a
/// space or `=` — none of which are legal in a cookie value (RFC 6265) — still
/// yields a well-formed cookie without an encoding layer. And it is one-way: a
/// cookie read out of a browser profile grants the same API access, but does not
/// hand back the token itself, which is also `packages/api`'s credential and the
/// value of `--mgmt-token` on any other host sharing it.
///
/// The key is a public constant. It domain-separates this derivation from the
/// hook salt's; unforgeability comes from the token, which is the secret.
fn session_cookie_value(token: &str) -> String {
    const KEY: &[u8] = b"honmoon-mgmt-session-v1";
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(KEY).expect("HMAC accepts a key of any length");
    mac.update(token.as_bytes());
    hex_encode(&mac.finalize().into_bytes())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// The [`SESSION_COOKIE`] value from the request's `Cookie` header(s), if any.
///
/// Hand-parsed rather than pulled in with a cookie crate: a new workspace
/// dependency is ask-gated (`crates/AGENTS.md`), and what is needed here is one
/// name lookup in a `;`-separated list. `get_all` because a client may split its
/// cookies across several headers.
fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == SESSION_COOKIE)
        .map(|(_, value)| value)
}

/// Authenticate a request against the management token, by bearer header or
/// session cookie. `None` means no valid credential was presented.
fn authorized(state: &AppState, headers: &HeaderMap) -> Option<Credential> {
    let expected = state.mgmt_token.as_bytes();
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|provided| constant_time_eq(provided.as_bytes(), expected));
    if bearer {
        return Some(Credential::Bearer);
    }
    let expected_cookie = session_cookie_value(&state.mgmt_token);
    session_cookie(headers)
        .is_some_and(|provided| constant_time_eq(provided.as_bytes(), expected_cookie.as_bytes()))
        .then_some(Credential::Session)
}

/// Whether a request the browser labelled for us came from this service's own
/// origin.
///
/// Only consulted for a cookie-authenticated state-changing request. `SameSite=
/// Strict` already keeps the cookie off a request issued by a *cross-site* page,
/// but "site" is registrable-domain-scoped: a page served by any other port on
/// `127.0.0.1` — which is exactly what a hostile local process can stand up — is
/// same-site and different-origin, so its forged `POST /api/approvals/1/approve`
/// would still carry the cookie. `Sec-Fetch-Site` and `Origin` are set by the
/// browser and unsettable by the page, so they distinguish the two.
///
/// Neither header present means nothing labelled this request as a browser's,
/// and for a *cookie* credential that is itself the warning sign: a cookie is a
/// credential only a browser stores and attaches, and every browser labels a
/// state-changing request with at least one of the two. So this arm refuses. A
/// legitimate non-browser caller is unaffected: it holds the token and sends
/// the bearer, which never reaches this function.
///
/// **What this does not do, stated plainly because the shape invites the wrong
/// conclusion:** every header it reads is set by the browser and unforgeable
/// *by a page*, not unforgeable *by a client*. A caller outside a browser sets
/// whatever it likes, `Sec-Fetch-Site: same-origin` included. So this function
/// defends against the browser-driven attack — a page on a sibling `127.0.0.1`
/// port causing the operator's browser to issue a state-changing request that
/// `SameSite=Strict` permits because different-port is same-site — and it does
/// **not** defend against an attacker who has already harvested the cookie
/// (cookie scope has no port, RFC 6265 §8.5) and is replaying it from `curl`.
/// Such a replay reaches the writes, not only the reads.
///
/// No header check can close that, because the premise of every one of them is
/// a browser on the other end. Closing it means the cookie must not be
/// harvestable (TLS on this listener plus a `__Host-` prefix), or the credential
/// must not be a cookie at all (delivered in the login redirect's fragment,
/// held in origin-scoped `sessionStorage`, sent as a header the browser never
/// attaches on its own). Tracked as issue #188 — do not read this function as
/// making writes safe against a stolen cookie.
fn same_origin(headers: &HeaderMap) -> bool {
    if let Some(site) = headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
    {
        // `none` is a user-initiated navigation (a typed URL or a bookmark),
        // which no page authored.
        return site == "same-origin" || site == "none";
    }
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some(authority) = origin.split_once("://").map(|(_, authority)| authority) else {
        return false;
    };
    // Hostnames are case-insensitive (RFC 9110 §4.2), so a casing difference
    // between the two headers is not a cross-origin signal.
    headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|host| host.eq_ignore_ascii_case(authority))
}

/// The single gate on `/api/*` (#173).
///
/// Rejects a caller with no valid credential, then — for a cookie-authenticated
/// request that is not a safe method — rejects one the browser reports as
/// cross-origin (see [`same_origin`], including the limit of what that check
/// can mean). A bearer caller skips the second check: no page can make a
/// browser attach that header.
async fn require_credential(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let Some(credential) = authorized(&state, request.headers()) else {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            Json(serde_json::json!({
                "error": "missing or invalid management token",
                "hint": "send `Authorization: Bearer <token>`, or open /login?token=<token> in a browser",
            })),
        )
            .into_response();
    };
    // Matched exhaustively on purpose: a new `Credential` variant must not
    // silently inherit `Bearer`'s exemption from the origin check.
    let origin_checked = match credential {
        // No page can make a browser attach `Authorization`, so a bearer is
        // never ambient authority and needs no origin evidence.
        Credential::Bearer => true,
        Credential::Session => request.method().is_safe() || same_origin(request.headers()),
    };
    if !origin_checked {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "cross-origin request rejected; use `Authorization: Bearer <token>`",
            })),
        )
            .into_response();
    }
    next.run(request).await
}

#[derive(Debug, Deserialize)]
struct LoginQuery {
    token: Option<String>,
}

/// Exchange the management token for the [`SESSION_COOKIE`], then redirect to
/// the dashboard.
///
/// This is how the browser gets a credential, and it is deliberately *not* the
/// token templated into the served `index.html` that issue #173 floated. That
/// shape defends against none of the three readers the issue names: any local
/// user, and any page that has rebound DNS to the listener, can simply
/// `GET /` and read the token out of the markup. A cookie cannot be obtained
/// that way — the operator has to present the token once, from the URL honmoon
/// prints at startup — and it is bound by the browser to the `127.0.0.1` origin,
/// so a page at `attacker.com` that has rebound to loopback sends no credential
/// at all.
///
/// The token rides in the query string, which lands in the operator's own
/// browser history. That is the cost of one-click login and it is same-user
/// only: the response is a redirect, so no page ever has this URL as its own
/// address to leak through `Referer`; the dashboard loads no cross-origin
/// subresource; and this service logs neither request lines nor query strings.
async fn login(State(s): State<AppState>, Query(q): Query<LoginQuery>) -> Response {
    let presented = q.token.as_deref().unwrap_or_default();
    if !constant_time_eq(presented.as_bytes(), s.mgmt_token.as_bytes()) {
        return (
            StatusCode::UNAUTHORIZED,
            Html("<h1>Invalid management token</h1><p>Open the dashboard URL honmoon printed at startup, or read the token from <code>~/.honmoon/mgmt-token</code>.</p>"),
        )
            .into_response();
    }
    // `HttpOnly` keeps the value out of `document.cookie`; `SameSite=Strict`
    // keeps it off cross-site requests; no `Secure`, which would stop the
    // cookie being sent over the plain-HTTP loopback listener this serves.
    let cookie = format!(
        "{SESSION_COOKIE}={}; Path=/; HttpOnly; SameSite=Strict",
        session_cookie_value(&s.mgmt_token)
    );
    (
        StatusCode::SEE_OTHER,
        [
            (header::SET_COOKIE, cookie),
            (header::LOCATION, "/".to_string()),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
    )
        .into_response()
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

/// Deny framing of the dashboard shell.
///
/// The shell is served without a credential, but since #173 the browser holds
/// one for this origin. A page on another loopback port is *same-site*, so
/// `SameSite=Strict` does not stop it framing the dashboard and having the
/// framed document — same-origin to itself, and so past the origin check —
/// issue a `POST /api/approvals/{id}/approve` behind a decoy click.
///
/// Only `frame-ancestors` is set: a script/style policy would have to track the
/// bundler's output, and a CSP that breaks the dashboard is worse than none.
const FRAME_ANCESTORS_NONE: &str = "frame-ancestors 'none'";

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
            [
                (header::CONTENT_TYPE, mime.as_ref()),
                (header::X_FRAME_OPTIONS, "DENY"),
                (header::CONTENT_SECURITY_POLICY, FRAME_ANCESTORS_NONE),
            ],
            asset.data.into_owned(),
        )
            .into_response();
    }

    // SPA fallback: serve index.html for unknown non-asset paths.
    match Assets::get("index.html") {
        Some(asset) => (
            [
                (header::X_FRAME_OPTIONS, "DENY"),
                (header::CONTENT_SECURITY_POLICY, FRAME_ANCESTORS_NONE),
            ],
            Html(asset.data.into_owned()),
        )
            .into_response(),
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
