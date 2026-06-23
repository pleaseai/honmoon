//! Honmoon management API (Phase 4).
//!
//! A small axum service that runs **in the same process as the data plane** so
//! it can both observe decisions and resolve held requests. It exposes:
//!
//! - `GET  /api/audit?limit=N` — recent audit events, newest first
//! - `GET  /api/approvals`     — requests held pending approval
//! - `POST /api/approvals/:id/approve` / `.../reject` — resolve a held request
//! - `GET  /api/policy`        — the active policy (raw YAML + parsed)
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
use axum::http::{StatusCode, Uri, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use honmoon_core::{AuditEvent, Policy};
use honmoon_proxy::approval::{ApprovalDecision, PendingApproval};
use honmoon_proxy::gateway::GatewayState;
use serde::{Deserialize, Serialize};

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
}

impl AppState {
    pub fn new(gateway: GatewayState, policy_yaml: impl Into<String>) -> Self {
        Self {
            gateway,
            policy_yaml: Arc::new(policy_yaml.into()),
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
