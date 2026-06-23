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
use serde::Serialize;
use tokio::sync::oneshot;

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
