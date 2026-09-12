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
//! - `GET  /login?token=…` — exchange the management token for a session secret
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
    /// `Authorization: Bearer <token>` or the [`SESSION_HEADER`] a browser
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
    /// credential arms, since the session secret is an HMAC under a hardcoded,
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
        // padding-only token and this assert is the last line of defence for
        // anyone constructing the state another way. A lone space would
        // otherwise authenticate: `GET /login?token=%20` matches it and mints a
        // session secret good for every `/api/*` route.
        //
        // The predicate is spelled out to match `mgmt_token.rs`'s
        // `is_token_padding` and `auth.ts`'s `trimToken` exactly: `str::trim`
        // alone would accept a lone U+FEFF that `@honmoon/api` rejects, and
        // reject a lone U+0085 that it accepts. Duplicated rather than shared
        // because lifting it into `honmoon-core` would add a public surface,
        // which `crates/AGENTS.md` gates behind an ask.
        assert!(
            !mgmt_token
                .trim_matches(|c: char| c.is_whitespace() || c == '\u{FEFF}')
                .is_empty(),
            "management token must not be empty or padding-only — such a credential authenticates everyone"
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

/// Name of the header a browser presents its session secret in, instead of a
/// bearer.
///
/// A header the page must set itself, not a cookie, and that substitution is
/// the whole of issue #188. A cookie's scope has no port component (RFC 6265
/// §8.5), so `honmoon_session` on `127.0.0.1` was sent to *every* listener on
/// that host: a second local user who cannot read the `0600` token file could
/// stand one up, provoke the operator's browser into a request
/// (`<img src="http://127.0.0.1:9999/x">`), harvest the cookie and replay it
/// off-browser for the whole management surface — the approval writes that
/// gate egress included. No header check could tell that replay apart, because
/// every header it reads is one the replaying client sets itself.
///
/// The dashboard keeps the value in `sessionStorage`, which is keyed by
/// *origin* — scheme, host **and** port — and attaches it here on each request.
/// So a sibling port is neither sent the secret nor able to read it, and a page
/// that has rebound DNS to this listener holds its own origin's storage, which
/// is empty: the rebinding the cookie defeated by construction stays closed by
/// construction.
///
/// Lowercase because that is the canonical on-the-wire form (HTTP/2 and HTTP/3
/// carry field names lowercased, RFC 9113 §8.2.1) and the form `http` stores.
/// Not for lookup correctness: `HeaderMap::get` normalises a `&str` key, so it
/// finds this header whatever casing either side spells — which is why the
/// dashboard may send `X-Honmoon-Session` and the e2e tests deliberately do.
pub const SESSION_HEADER: &str = "x-honmoon-session";

/// The session secret that stands in for `token`.
///
/// An HMAC of the token rather than the token itself, for two reasons. It is
/// fixed-width hex, so an operator-chosen `--mgmt-token` containing a space, a
/// newline or a non-ASCII character — none of which a header value or a URL
/// fragment carries unencoded — still yields a well-formed credential with no
/// encoding layer. And it is one-way: a secret read out of a browser grants the
/// same API access, but does not hand back the token itself, which is also
/// `packages/api`'s credential and the value of `--mgmt-token` on any other
/// host sharing it.
///
/// The key is a public constant. It domain-separates this derivation from the
/// hook salt's; unforgeability comes from the token, which is the secret.
///
/// Its version is the migration boundary, and `v2` is deliberate. Up to `0.1.0`
/// this same derivation keyed `v1` was minted as the `honmoon_session` cookie —
/// the cookie #188 removes, because a sibling loopback listener can harvest it.
/// A browser upgraded mid-session still holds that cookie, and its value was
/// byte-identical to what [`SESSION_HEADER`] now accepts: a value harvested
/// before the upgrade would have replayed in the new header afterwards and
/// bridged the hole this change closes. Bumping the key retires every
/// previously minted value by construction, which is the only thing that
/// reaches the harvested copy — that copy is already off-browser, where no
/// expiring `Set-Cookie` can follow it. `a_legacy_cookie_derivation_is_not_a_session`
/// pins the refusal; bump the version again for any future change of this shape.
fn session_secret(token: &str) -> String {
    const KEY: &[u8] = b"honmoon-mgmt-session-v2";
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

/// The session secret from the request's [`SESSION_HEADER`], if any.
///
/// Deliberately not `get_all`: a header sent twice is a caller mistake or a
/// smuggling attempt, and `HeaderMap::get` returns the first value rather than
/// trying to reconcile them.
fn presented_session(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
}

/// Whether a request carries the management token, as a bearer header or as the
/// session secret in [`SESSION_HEADER`].
///
/// The two are treated identically, and since #188 that is the design rather
/// than an omission: **neither credential is ambient.** A browser attaches
/// `Authorization` or [`SESSION_HEADER`] only because the page's own script set
/// it, and a cross-origin `fetch` that sets either is held behind a CORS
/// preflight this service never answers. So no page — on a sibling loopback
/// port or rebound from anywhere else — can cause a credentialled request it did
/// not already hold the credential for. The cookie that *did* arrive on its own,
/// and therefore needed an origin check to tell the dashboard's own write from
/// one a sibling-port page provoked, is gone.
///
/// Adding any credential a browser attaches by itself — a cookie, TLS client
/// auth, HTTP auth — reintroduces ambient authority and with it the need for
/// that origin check. Do not add one without it.
///
/// The `Credential` enum that used to make this a compile error (its exhaustive
/// `match` forced a decision about a new variant) is gone with the origin check
/// it selected. What replaces it for the credential that actually existed is a
/// test, not a comment: re-accepting a cookie here fails
/// `no_session_cookie_is_a_credential_so_a_sibling_port_has_nothing_to_harvest`,
/// which presents the genuine session secret as a cookie and requires a 401. A
/// match arm only forced a decision; that test forces the right one. For a
/// credential kind nobody has proposed yet, this paragraph is the whole guard —
/// so land such a change with its own refusal test.
fn authorized(state: &AppState, headers: &HeaderMap) -> bool {
    let expected = state.mgmt_token.as_bytes();
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|provided| constant_time_eq(provided.as_bytes(), expected));
    if bearer {
        return true;
    }
    let expected_session = session_secret(&state.mgmt_token);
    presented_session(headers)
        .is_some_and(|provided| constant_time_eq(provided.as_bytes(), expected_session.as_bytes()))
}

/// The single gate on `/api/*` (#173).
///
/// One check: the caller presents the management token, as a bearer or as the
/// session secret in [`SESSION_HEADER`] (see [`authorized`]).
///
/// Until #188 there was a second — a `Sec-Fetch-Site`/`Origin`-vs-`Host` test on
/// cookie-authenticated writes — because the session credential was a cookie the
/// browser attached by itself, so a page on a sibling `127.0.0.1` port could
/// provoke a write the operator never made. Removing the cookie removed the
/// ambient authority that check existed to police, along with the cookie harvest
/// it could never police (it reads headers an off-browser replay simply sets).
/// Both credentials now have to be set by whoever holds them, so there is no
/// browser-provoked request left to distinguish from a deliberate one. That
/// absence is pinned by
/// `no_session_cookie_is_a_credential_so_a_sibling_port_has_nothing_to_harvest`
/// and by [`authorized`]'s own contract, which says what re-introducing an
/// ambient credential would cost.
async fn require_credential(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if !authorized(&state, request.headers()) {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            Json(serde_json::json!({
                "error": "missing or invalid management token",
                "hint": "send `Authorization: Bearer <token>`, or open /login?token=<token> in a browser",
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

/// Exchange the management token for the session secret, in the fragment of a
/// redirect to the dashboard.
///
/// This is how the browser gets a credential, and it is deliberately *not* the
/// token templated into the served `index.html` that issue #173 floated. That
/// shape defends against none of the three readers the issue names: any local
/// user, and any page that has rebound DNS to the listener, can simply
/// `GET /` and read the token out of the markup. The secret here cannot be
/// obtained that way — the operator has to present the token once, from the URL
/// honmoon prints at startup — and the dashboard keeps it in `sessionStorage`,
/// which is scoped to this exact origin, port included, so neither a sibling
/// loopback listener nor a rebound page can read it.
///
/// **Why the fragment** (#188): a fragment is the one part of a URL a browser
/// never sends to any server. So the secret reaches the page without passing
/// through a proxy log, a `Referer`, or this service's own request line — and
/// without a `Set-Cookie`, which would have handed it to every other listener
/// on `127.0.0.1` (RFC 6265 §8.5). It is fixed-width hex, so it needs no
/// escaping to sit there. The dashboard drops it from the address bar with
/// `history.replaceState` as soon as it has read it (see
/// `apps/dashboard/src/session.ts`), which also keeps it out of a bookmark the
/// operator makes afterwards; until then it is in that one tab's address bar,
/// a same-user exposure the token in the query string above already is.
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
    (
        StatusCode::SEE_OTHER,
        [
            (
                header::LOCATION,
                format!("/#session={}", session_secret(&s.mgmt_token)),
            ),
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

/// The dashboard shell's `Content-Security-Policy`.
///
/// # `frame-ancestors 'none'` — no framing (with `X-Frame-Options: DENY`)
///
/// The shell is served without a credential, but since #173 the browser can
/// hold one for this origin. A page on another loopback port is *same-site*, so
/// nothing else stops it framing the dashboard and clickjacking the framed
/// document into a `POST /api/approvals/{id}/approve` behind a decoy click.
///
/// Since #188 the credential is the dashboard's own script's to attach, which
/// makes this directive the guard against UI redress rather than one layer over
/// an ambient cookie: a framed dashboard that has the secret will send it, and
/// this is what keeps that frame from existing. (A frame in a *fresh* tab gets
/// its own empty `sessionStorage` and so would fail to authenticate anyway —
/// which is a second obstacle in one browser-storage model, not a reason to
/// drop the first.)
///
/// # `script-src`/`connect-src` — bounding a script injection (#195)
///
/// #188 moved the browser credential out of an `HttpOnly` cookie and into
/// `sessionStorage`, which is script-readable by construction — that is what
/// puts it beyond a sibling loopback port's reach, and it is the one property
/// the cookie had that the replacement does not. What a script injection in
/// this origin would cost therefore widened, from "act while the page is open"
/// to "read a credential that replays off-browser until the operator rotates
/// the token". These two directives are what bound that:
///
/// - `script-src 'self'` — only script served by this origin runs, so an
///   injected `<script>` element, an inline event handler and `eval` are all
///   refused. The embedded bundle is loaded from a file, never inlined.
/// - `connect-src 'self'` — a credential that was read has nowhere to go. A
///   script that did run could still drive the management API as the operator,
///   but it could not `fetch` the secret out to a collector.
///
/// `default-src 'none'` makes everything not listed below a refusal rather than
/// an inheritance, so a future asset class (a worker, a frame, a webfont from a
/// CDN) has to be allowed deliberately instead of arriving unexamined.
/// `base-uri 'none'` keeps an injected `<base>` from repointing the shell's own
/// relative asset loads, and `form-action 'none'` keeps a submission from
/// carrying anything off-origin — the dashboard submits no forms.
///
/// **No injection is known here**, which is why this is a bound on blast radius
/// rather than a fix: the bundle is first-party and embedded in this binary, no
/// first-party component renders API data as HTML (the views interpolate values
/// as text, which React escapes), and the one `innerHTML`-class sink —
/// `react-simple-code-editor`'s highlight layer, fed `Prism.highlight` output
/// over operator-authored policy YAML in `PolicyView` — renders Prism-escaped
/// text.
///
/// # What `style-src` and `img-src` are *not*
///
/// Neither bounds anything, and both are listed only because `default-src
/// 'none'` would otherwise break the page they belong to:
///
/// - `style-src` carries `'unsafe-inline'` because `react-simple-code-editor`
///   renders an unconditional `<style>` element (a placeholder fixup and IE
///   hacks) on the Policy view. A style policy with `'unsafe-inline'` in it
///   bounds close to nothing, so it is written down as what it is rather than
///   presented as a control. Pinning the element's hash instead would tie a
///   constant here to a transitive npm package's exact CSS text, which the next
///   dependency bump would break — as a blank Policy view and a console
///   violation, in a build no test here would catch.
/// - `img-src 'self'` exists because a browser probes `/favicon.ico` unasked,
///   and `default-src 'none'` refuses that probe (measured: Chrome makes the
///   request with this directive present and does not without it). No view
///   loads an image.
///
/// Neither weakens `script-src`: `'unsafe-inline'` in one directive does not
/// reach another.
///
/// # Keeping `script-src 'self'` true
///
/// It holds only while the built shell takes all its script from files. The
/// shell Vite emits today has exactly one `<script>`, carrying a `src` — its
/// module-preload polyfill is emitted into the entry chunk rather than into the
/// page — and the demo build adds a second `<script src>` rather than inline
/// code. That is a property of a bundler's output, not something this constant
/// can enforce, so `scripts/check-dashboard-csp.ts` re-checks both built shells
/// in CI: a bundler or dependency change that starts inlining script must break
/// there rather than arrive as a blank dashboard.
const DASHBOARD_CSP: &str = concat!(
    "default-src 'none'; ",
    "script-src 'self'; ",
    "style-src 'self' 'unsafe-inline'; ",
    "img-src 'self'; ",
    "connect-src 'self'; ",
    "base-uri 'none'; ",
    "form-action 'none'; ",
    "frame-ancestors 'none'",
);

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
                (header::CONTENT_SECURITY_POLICY, DASHBOARD_CSP),
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
                (header::CONTENT_SECURITY_POLICY, DASHBOARD_CSP),
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
