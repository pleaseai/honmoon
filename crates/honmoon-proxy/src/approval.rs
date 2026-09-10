//! Pending-approval registry for the `pause` verdict (Phase 4).
//!
//! When the engine returns [`Verdict::Pause`](honmoon_core::Verdict::Pause) the
//! data plane holds the connection and registers a [`PendingApproval`] here. The
//! management API lists pending approvals and resolves them; resolving signals
//! the waiting connection through a [`oneshot`] channel so it can proceed or close.
//!
//! Single-node and in-process by design: the waiter (a tokio task in the proxy)
//! and the resolver (an axum handler in `honmoon-mgmt`) share one
//! `Arc<ApprovalRegistry>`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use honmoon_core::audit::now_rfc3339;
use honmoon_core::{AuditDraft, Decision, FactsSummary, Verdict};
use serde::Serialize;
use tokio::sync::oneshot;

use crate::gateway::GatewayState;

/// A human's resolution of a held request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalDecision {
    /// Let the held request proceed.
    Approve,
    /// Block the held request.
    Reject,
}

/// A request held awaiting human approval, as surfaced to the dashboard.
#[derive(Debug, Clone, Serialize)]
pub struct PendingApproval {
    pub id: u64,
    /// RFC 3339 time the request was held.
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// The rule whose `pause` verdict held this request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// Human-readable one-liner describing what is being approved.
    pub summary: String,
}

/// The descriptive fields of an approval; `id`/`created_at` are assigned on register.
#[derive(Debug, Clone, Default)]
pub struct NewApproval {
    pub endpoint: Option<String>,
    pub domain: Option<String>,
    pub rule: Option<String>,
    pub summary: String,
}

struct Slot {
    info: PendingApproval,
    tx: oneshot::Sender<ApprovalDecision>,
}

/// Default cap on simultaneously-held requests. Beyond this, new pauses are
/// rejected (fail-closed) instead of growing the queue without bound under
/// pause-heavy or hostile traffic.
pub const DEFAULT_MAX_PENDING: usize = 1024;

/// In-process registry of requests held pending approval.
pub struct ApprovalRegistry {
    slots: Mutex<HashMap<u64, Slot>>,
    next_id: AtomicU64,
    max_pending: usize,
}

impl Default for ApprovalRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ApprovalRegistry {
    pub fn new() -> Self {
        Self::with_max_pending(DEFAULT_MAX_PENDING)
    }

    /// A registry that holds at most `max_pending` requests at once.
    pub fn with_max_pending(max_pending: usize) -> Self {
        Self {
            slots: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            max_pending,
        }
    }

    /// Register a held request. Returns the assigned [`PendingApproval`] (so the
    /// caller can record its id in the audit log) and a receiver that resolves
    /// when the request is approved/rejected — or errors if the registry is
    /// dropped, which the caller should treat as a rejection.
    ///
    /// Returns `None` when the pending queue is already at capacity
    /// ([`max_pending`](Self::with_max_pending)); the caller must then fail
    /// closed (deny the request) rather than hold it.
    pub fn register(
        &self,
        new: NewApproval,
    ) -> Option<(PendingApproval, oneshot::Receiver<ApprovalDecision>)> {
        let mut slots = self.slots.lock().expect("approval registry poisoned");
        // Check the cap and insert under the same lock so concurrent registers
        // can't both slip past a near-full queue.
        if slots.len() >= self.max_pending {
            return None;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let info = PendingApproval {
            id,
            created_at: now_rfc3339(),
            endpoint: new.endpoint,
            domain: new.domain,
            rule: new.rule,
            summary: new.summary,
        };
        let (tx, rx) = oneshot::channel();
        slots.insert(
            id,
            Slot {
                info: info.clone(),
                tx,
            },
        );
        Some((info, rx))
    }

    /// All currently-pending approvals, oldest first.
    pub fn pending(&self) -> Vec<PendingApproval> {
        let slots = self.slots.lock().expect("approval registry poisoned");
        let mut out: Vec<PendingApproval> = slots.values().map(|s| s.info.clone()).collect();
        out.sort_by_key(|p| p.id);
        out
    }

    /// Look up a single pending approval by id.
    pub fn get(&self, id: u64) -> Option<PendingApproval> {
        self.slots
            .lock()
            .expect("approval registry poisoned")
            .get(&id)
            .map(|s| s.info.clone())
    }

    /// Resolve a held request, waking its waiter. Returns the resolved approval
    /// info, or `None` if no such pending id exists (already resolved/expired).
    pub fn resolve(&self, id: u64, decision: ApprovalDecision) -> Option<PendingApproval> {
        let slot = self
            .slots
            .lock()
            .expect("approval registry poisoned")
            .remove(&id)?;
        // If the waiter already gave up (timeout / connection dropped) the send
        // fails; that's fine — the request is no longer held either way.
        let _ = slot.tx.send(decision);
        Some(slot.info)
    }

    /// Drop a held request without a human decision (e.g. the waiter timed out).
    /// Removes the slot so it stops showing as pending.
    pub fn cancel(&self, id: u64) {
        self.slots
            .lock()
            .expect("approval registry poisoned")
            .remove(&id);
    }

    /// Number of currently-pending approvals.
    pub fn len(&self) -> usize {
        self.slots.lock().expect("approval registry poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Frees a pending approval slot (and audits the rejection) if the holding
/// future is dropped before a decision was reached — the caller's future is
/// dropped when the waiting client disconnects.
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

/// How a [`hold`] ended.
pub(crate) enum HoldOutcome {
    /// A human approved it — the request may proceed.
    Approved,
    /// A human rejected it, the hold timed out, or the registry went away.
    Rejected,
    /// The pending queue was at capacity, so the request was never held
    /// (fail-closed: the caller must block it).
    QueueFull,
    /// The client that made the request left before a human decided. Nothing
    /// may be forwarded on its behalf and there is nobody left to answer, so
    /// the caller should end the session rather than refuse the request.
    Abandoned,
}

/// Hold a `pause`d request until a human resolves it (or the hold times out),
/// recording the whole lifecycle (`Paused` → `Approved`/`Rejected`) in the audit
/// log. Transport-agnostic: the HTTP MITM path and the SOCKS5 data path both
/// hold through this one function, and each renders the outcome its own way.
///
/// The client waits for the entire hold, so the caller must not have answered it
/// yet when calling this.
pub(crate) async fn hold(
    state: &GatewayState,
    host: &str,
    summary: FactsSummary,
    rule: Option<String>,
    approval_summary: String,
) -> HoldOutcome {
    // No abandonment signal: the caller's own future is dropped when its client
    // disconnects, and the guard inside `hold_until` frees the slot from there.
    hold_until(
        state,
        host,
        summary,
        rule,
        approval_summary,
        std::future::pending(),
    )
    .await
}

/// [`hold`], plus an explicit signal that the requesting client has gone away.
///
/// A caller whose future keeps being polled while it waits — the PostgreSQL
/// runtime holds mid-stream inside a `select!` that the upstream relay keeps
/// alive — never gets dropped on a disconnect, so the drop guard alone cannot
/// see one. Such a caller passes a future that resolves once its client is
/// gone, and the hold is abandoned instead of running on to `pause_timeout`
/// and possibly being approved for a client that no longer exists (#102).
pub(crate) async fn hold_until(
    state: &GatewayState,
    host: &str,
    summary: FactsSummary,
    rule: Option<String>,
    approval_summary: String,
    abandoned: impl std::future::Future<Output = ()>,
) -> HoldOutcome {
    let registration = state.approvals.register(NewApproval {
        domain: Some(host.to_owned()),
        endpoint: summary.endpoint.clone(),
        rule: rule.clone(),
        summary: approval_summary,
    });
    let Some((pending, rx)) = registration else {
        // Pending queue is at capacity — fail closed rather than hold.
        tracing::warn!(domain = %host, "approval queue full; rejecting paused request");
        state.audit.record(AuditDraft {
            decision: Decision::Rejected,
            verdict: Verdict::Pause,
            rule,
            facts: summary,
            approval_id: None,
        });
        return HoldOutcome::QueueFull;
    };

    state.audit.record(AuditDraft {
        decision: Decision::Paused,
        verdict: Verdict::Pause,
        rule: rule.clone(),
        facts: summary.clone(),
        approval_id: Some(pending.id),
    });
    tracing::info!(id = pending.id, domain = %host, "request held for approval");

    // If the client disconnects mid-hold, the caller's future is dropped and the
    // code after the `await` never runs — the guard then frees the slot so
    // abandoned holds can't saturate the approval queue.
    let mut guard = CancelOnDrop {
        state: state.clone(),
        id: pending.id,
        rule: rule.clone(),
        summary: Some(summary.clone()),
        armed: true,
    };
    let resolved = tokio::select! {
        // Biased towards the decision: a resolution already in hand wins a tie
        // with a client that left at the same moment. Losing that tie would
        // have the guard audit an abandonment over an approval a human really
        // did make, and the slot it would "free" is one `resolve` already took.
        biased;
        resolved = tokio::time::timeout(state.pause_timeout, rx) => resolved,
        // The client is gone. Returning here drops the still-armed guard, which
        // frees the slot and audits the abandonment.
        () = abandoned => return HoldOutcome::Abandoned,
    };
    let decision = match resolved {
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
    guard.armed = false;

    match decision {
        ApprovalDecision::Approve => {
            state.audit.record(AuditDraft {
                decision: Decision::Approved,
                verdict: Verdict::Pause,
                rule,
                facts: summary,
                approval_id: Some(pending.id),
            });
            HoldOutcome::Approved
        }
        ApprovalDecision::Reject => {
            state.audit.record(AuditDraft {
                decision: Decision::Rejected,
                verdict: Verdict::Pause,
                rule,
                facts: summary,
                approval_id: Some(pending.id),
            });
            HoldOutcome::Rejected
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolve_wakes_waiter_with_decision() {
        let reg = ApprovalRegistry::new();
        let (info, rx) = reg
            .register(NewApproval {
                domain: Some("staging.internal".into()),
                summary: "CONNECT staging.internal".into(),
                ..Default::default()
            })
            .expect("capacity available");
        assert_eq!(info.id, 1);
        assert_eq!(reg.len(), 1);

        let resolved = reg.resolve(1, ApprovalDecision::Approve);
        assert!(resolved.is_some());
        assert_eq!(reg.len(), 0, "resolving removes the pending slot");
        assert_eq!(rx.await.unwrap(), ApprovalDecision::Approve);
    }

    #[tokio::test]
    async fn resolve_unknown_id_is_none() {
        let reg = ApprovalRegistry::new();
        assert!(reg.resolve(999, ApprovalDecision::Reject).is_none());
    }

    #[test]
    fn register_rejects_when_at_capacity() {
        let reg = ApprovalRegistry::with_max_pending(1);
        let _first = reg.register(NewApproval::default()).expect("first fits");
        assert!(
            reg.register(NewApproval::default()).is_none(),
            "second register must be refused at capacity"
        );
        // Freeing a slot lets a new request register again.
        reg.cancel(1);
        assert!(reg.register(NewApproval::default()).is_some());
    }

    #[test]
    fn pending_is_sorted_by_id() {
        let reg = ApprovalRegistry::new();
        let (a, _ra) = reg.register(NewApproval::default()).unwrap();
        let (b, _rb) = reg.register(NewApproval::default()).unwrap();
        let pending = reg.pending();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].id, a.id);
        assert_eq!(pending[1].id, b.id);
    }
}
