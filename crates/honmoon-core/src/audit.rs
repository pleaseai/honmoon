//! Structured audit log: every verdict the engine reaches, recorded.
//!
//! [`AuditLog`] is the single-node, in-process record of decisions. It keeps a
//! bounded in-memory ring (so the management API can render recent activity
//! cheaply) and optionally mirrors every event to a JSONL file (the durable
//! local audit log the `@honmoon/api` query layer reads).
//!
//! It is transport-agnostic on purpose — the data plane (`honmoon-proxy`) and
//! the management API (`honmoon-mgmt`) share one `Arc<AuditLog>`.

use std::collections::VecDeque;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::{Facts, HttpFacts, K8sFacts, SqlFacts, Verdict};

/// The final disposition of a request, as recorded in the audit log.
///
/// A `Pause` verdict produces a `Paused` event when the request is held, then a
/// second `Approved`/`Rejected` event (sharing the same `approval_id`) once a
/// human resolves it — so the log is append-only and the full lifecycle is visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// Request was allowed through.
    Allowed,
    /// Request was blocked.
    Denied,
    /// Request was held pending human approval.
    Paused,
    /// A held request was approved by a human and allowed through.
    Approved,
    /// A held request was rejected by a human (or timed out) and blocked.
    Rejected,
}

/// A compact, serializable snapshot of the [`Facts`] a decision was made on.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FactsSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpFacts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sql: Option<SqlFacts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub k8s: Option<K8sFacts>,
}

impl From<&Facts> for FactsSummary {
    fn from(f: &Facts) -> Self {
        Self {
            domain: f.domain.clone(),
            endpoint: f.endpoint.clone(),
            http: f.http.clone(),
            sql: f.sql.clone(),
            k8s: f.k8s.clone(),
        }
    }
}

/// One recorded decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Monotonic per-process event id.
    pub id: u64,
    /// RFC 3339 / ISO 8601 UTC timestamp.
    pub timestamp: String,
    pub decision: Decision,
    /// The policy verdict that drove this event (`pause` for both the hold and
    /// its later resolution).
    pub verdict: Verdict,
    /// Name of the rule that fired, or `None` for an egress-list decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    pub facts: FactsSummary,
    /// Links a `Paused` event to the later `Approved`/`Rejected` event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<u64>,
}

/// What the caller knows at record time; `id`/`timestamp` are assigned by the log.
#[derive(Debug, Clone)]
pub struct AuditDraft {
    pub decision: Decision,
    pub verdict: Verdict,
    pub rule: Option<String>,
    pub facts: FactsSummary,
    pub approval_id: Option<u64>,
}

struct Ring {
    events: VecDeque<AuditEvent>,
    next_id: u64,
}

/// A bounded in-memory audit log with an optional durable JSONL mirror.
pub struct AuditLog {
    ring: Mutex<Ring>,
    capacity: usize,
    /// Optional append-only JSONL sink (one event per line).
    sink: Option<Mutex<std::fs::File>>,
    sink_path: Option<PathBuf>,
}

impl AuditLog {
    /// An in-memory-only log holding up to `capacity` recent events.
    pub fn new(capacity: usize) -> Self {
        Self {
            ring: Mutex::new(Ring {
                events: VecDeque::with_capacity(capacity.min(1024)),
                next_id: 1,
            }),
            capacity,
            sink: None,
            sink_path: None,
        }
    }

    /// Like [`new`](Self::new), additionally appending every event to a JSONL
    /// file at `path` (created if absent). Existing event ids in the file are
    /// not re-read; the in-memory ring starts empty.
    pub fn with_file(capacity: usize, path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        let mut log = Self::new(capacity);
        log.sink = Some(Mutex::new(file));
        log.sink_path = Some(path);
        Ok(log)
    }

    /// Path of the JSONL mirror, if one is configured.
    pub fn sink_path(&self) -> Option<&PathBuf> {
        self.sink_path.as_ref()
    }

    /// Record a decision; returns the stored event (with its assigned id).
    pub fn record(&self, draft: AuditDraft) -> AuditEvent {
        let mut ring = self.ring.lock().expect("audit ring poisoned");
        let id = ring.next_id;
        ring.next_id += 1;
        let event = AuditEvent {
            id,
            timestamp: now_rfc3339(),
            decision: draft.decision,
            verdict: draft.verdict,
            rule: draft.rule,
            facts: draft.facts,
            approval_id: draft.approval_id,
        };

        if let Some(sink) = &self.sink {
            // A sink write failure must not break enforcement — log and carry on.
            if let Err(e) = append_jsonl(sink, &event) {
                tracing::warn!(error = %e, "audit sink write failed");
            }
        }

        ring.events.push_back(event.clone());
        while ring.events.len() > self.capacity {
            ring.events.pop_front();
        }
        event
    }

    /// The most recent events, newest first, capped at `limit`.
    pub fn recent(&self, limit: usize) -> Vec<AuditEvent> {
        let ring = self.ring.lock().expect("audit ring poisoned");
        ring.events.iter().rev().take(limit).cloned().collect()
    }

    /// Total number of events currently held in memory.
    pub fn len(&self) -> usize {
        self.ring.lock().expect("audit ring poisoned").events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn append_jsonl(sink: &Mutex<std::fs::File>, event: &AuditEvent) -> std::io::Result<()> {
    let line = serde_json::to_string(event)?;
    let mut file = sink.lock().expect("audit sink poisoned");
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    file.flush()
}

/// Current UTC time as an RFC 3339 string (shared timestamp source for events
/// and pending-approval records).
pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft(decision: Decision) -> AuditDraft {
        AuditDraft {
            decision,
            verdict: Verdict::Deny,
            rule: Some("r".into()),
            facts: FactsSummary {
                domain: Some("evil.com".into()),
                ..Default::default()
            },
            approval_id: None,
        }
    }

    #[test]
    fn assigns_monotonic_ids_and_orders_newest_first() {
        let log = AuditLog::new(10);
        let a = log.record(draft(Decision::Denied));
        let b = log.record(draft(Decision::Allowed));
        assert_eq!(a.id, 1);
        assert_eq!(b.id, 2);

        let recent = log.recent(10);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].id, 2, "newest first");
        assert_eq!(recent[1].id, 1);
    }

    #[test]
    fn ring_is_bounded_to_capacity() {
        let log = AuditLog::new(3);
        for _ in 0..10 {
            log.record(draft(Decision::Denied));
        }
        assert_eq!(log.len(), 3);
        let recent = log.recent(100);
        assert_eq!(recent.len(), 3);
        // The three newest ids survive (8, 9, 10).
        assert_eq!(recent[0].id, 10);
        assert_eq!(recent[2].id, 8);
    }

    #[test]
    fn jsonl_sink_appends_one_line_per_event() {
        let dir = std::env::temp_dir().join(format!("honmoon-audit-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);

        let log = AuditLog::with_file(10, &path).unwrap();
        log.record(draft(Decision::Denied));
        log.record(draft(Decision::Paused));

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        // Each line round-trips back to an AuditEvent.
        let first: AuditEvent = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first.id, 1);
        assert_eq!(first.decision, Decision::Denied);
        let _ = std::fs::remove_file(&path);
    }
}
