//! Structured audit log: every verdict the engine reaches, recorded.
//!
//! [`AuditLog`] is the single-node, in-process record of decisions. It keeps a
//! bounded in-memory ring (so the management API can render recent activity
//! cheaply) and optionally mirrors every event to a JSONL file (the durable
//! local audit log the `@honmoon/api` query layer reads).
//!
//! It is transport-agnostic on purpose — the data plane (`honmoon-proxy`) and
//! the management API (`honmoon-mgmt`) share one `Arc<AuditLog>`.
//!
//! The **ring** is per process; the **JSONL file** is not. `honmoon hook` runs
//! as its own short-lived process and appends its degradation events to the
//! same path (see [`Decision::Degraded`]), so one file can hold the output of
//! several `AuditLog`s. Ids are therefore process-local and repeat across
//! writers — readers order by `timestamp` (`@honmoon/api`'s `queryAudit` says
//! so) — and only what reached *this* process's ring is visible through
//! `/api/audit`.

use std::collections::VecDeque;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::{Facts, HttpFacts, K8sFacts, PiiFacts, SqlFacts, Verdict};

/// What an audit entry records: the disposition of a request, or — for
/// [`Decision::Degraded`] — a security property the engine is running without.
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
    /// Not a request disposition: the engine is running with a security
    /// property it normally provides switched off, and said so here.
    ///
    /// Honmoon's degradations are deliberately fail-open — a hook that hard-fails
    /// breaks the agent it runs inside — which makes them invisible from the
    /// outside: the degraded path produces the same shape of output as the
    /// working one. This variant is how a fail-open path stops being silent, so
    /// `?decision=degraded` answers "was this transcript redacted under a real
    /// key?" from the log rather than from a stderr line nobody read. The
    /// accompanying `verdict` describes what happened to the traffic (`allow`:
    /// fail-open let it through), not the degradation itself, and [`FactsSummary`]
    /// carries the specifics — see [`RedactionFacts`].
    Degraded,
}

/// Why placeholder minting is or is not keyed by a private secret, recorded on a
/// [`Decision::Degraded`] event.
///
/// Placeholders are `HMAC(salt, secret)`, and the salt is derived from a machine
/// key the transports read from disk. When that key cannot be read or created the
/// transports fall back to a constant compiled into the binary and published in
/// this repository's source: redaction keeps working and placeholders stay
/// byte-stable, but anyone can mint the placeholder a guessed secret would produce
/// and check it against a redacted transcript, so unforgeability is not weakened —
/// it is gone (issue #131). Nothing about the redacted output distinguishes the
/// two paths, which is why the provenance is recorded here instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionFacts {
    /// Where the HMAC key came from.
    pub key_source: RedactionKeySource,
    /// Which transport derived it.
    pub transport: RedactionTransport,
    /// Why the persisted key was unavailable, as the loader reported it.
    pub reason: String,
}

/// Whether placeholder minting was keyed by a private secret.
///
/// A closed two-value domain, so it is an enum rather than a string, matching
/// every other wire-serialized domain in this crate ([`Verdict`],
/// [`Decision`], `PathResolution`): a typo then fails to compile here instead
/// of failing to match on the query side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RedactionKeySource {
    /// The random secret persisted at `~/.honmoon/hook-salt`. Says where the
    /// bytes came from, not whether the file is readable by anyone else
    /// (issue #141).
    Persisted,
    /// A private random secret that never reached disk, so it is unforgeable
    /// but lives and dies with one process: placeholders stop being stable
    /// across turns and across transports (the property issue #20 exists for),
    /// and no other process can reproduce them.
    Unpersisted,
    /// The public constant compiled into the binary. Unforgeability is not
    /// weakened here but absent — see [`Decision::Degraded`].
    Fallback,
}

/// Which transport recorded a [`RedactionFacts`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RedactionTransport {
    /// The `honmoon hook` subprocess, which derives per invocation.
    Hook,
    /// The gateway process — wire redaction and the management hook endpoint,
    /// which share one key read once at startup.
    Gateway,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pii: Option<PiiFacts>,
    /// Set only on a [`Decision::Degraded`] event; never derived from [`Facts`],
    /// which describes a request rather than the engine's own posture.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redaction: Option<RedactionFacts>,
}

impl From<&Facts> for FactsSummary {
    fn from(f: &Facts) -> Self {
        Self {
            domain: f.domain.clone(),
            endpoint: f.endpoint.clone(),
            http: f.http.clone(),
            sql: f.sql.clone(),
            k8s: f.k8s.clone(),
            pii: f.pii.clone(),
            redaction: None,
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
    ///
    /// A sink write failure is logged and swallowed: it must not break
    /// enforcement, and the event still sits in this process's ring, so the
    /// management API can serve it. A caller whose process has neither — no
    /// `tracing` subscriber at that level, and no later reader of its ring —
    /// wants [`record_durable`](Self::record_durable) instead.
    pub fn record(&self, draft: AuditDraft) -> AuditEvent {
        let (event, sink) = self.record_durable(draft);
        if let Err(e) = sink {
            // A sink write failure must not break enforcement — log and carry on.
            tracing::warn!(error = %e, "audit sink write failed");
        }
        event
    }

    /// [`record`](Self::record), additionally handing back whether the durable
    /// JSONL sink took the event (`Ok(())` when there is no sink configured).
    ///
    /// For a short-lived writer the distinction is the whole point: `honmoon
    /// hook` is a fresh process per invocation with no ring anyone will query
    /// and, under a plugin dispatcher, no `RUST_LOG`, so `EnvFilter` drops a
    /// `warn!` before it is written — a swallowed sink failure there would make
    /// a degradation record vanish with no trace at all, which is the one
    /// outcome the degradation record exists to prevent (issue #131).
    pub fn record_durable(&self, draft: AuditDraft) -> (AuditEvent, std::io::Result<()>) {
        // Assign the id and update the ring under the lock, then release it
        // *before* any file I/O. Holding the ring lock across a synchronous
        // sink write would stall the gateway hot path (and serialize all audit
        // operations) behind a slow disk.
        let event = {
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
            ring.events.push_back(event.clone());
            while ring.events.len() > self.capacity {
                ring.events.pop_front();
            }
            event
        };

        // The sink has its own lock (writes stay ordered) and no longer contends
        // with the ring.
        let written = match &self.sink {
            Some(sink) => append_jsonl(sink, &event),
            None => Ok(()),
        };

        (event, written)
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
    // Terminator appended in-buffer, because the sink is no longer single-writer:
    // `honmoon hook` runs as its own short-lived process and appends its own
    // degradation events to the same path (issue #131). Writing the newline
    // separately guaranteed a second syscall, and `O_APPEND` positions each one
    // at EOF independently, so a concurrent appender could land between an event
    // and its terminator and fuse two objects onto a line the reader drops as
    // malformed. One buffer removes that gap for the ordinary case — it is not a
    // hard guarantee: `write_all` loops on a short write, and atomic append is a
    // local-filesystem property NFS does not provide. A reader that must not lose
    // a record should treat a malformed line as a signal, not as noise.
    let mut line = serde_json::to_string(event)?;
    line.push('\n');
    let mut file = sink.lock().expect("audit sink poisoned");
    file.write_all(line.as_bytes())?;
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
    fn concurrent_writers_never_fuse_two_events_onto_one_line() {
        // The sink gained a second writer process (`honmoon hook`), which is why
        // `append_jsonl` emits the terminator in the same buffer as the record.
        // Threads here stand in for those processes: distinct `AuditLog`s over
        // one path, as two processes would have. Every line must still parse —
        // a fused line is one the reader drops, and the record most likely to be
        // lost is the `degraded` one that exists to be seen.
        let dir = std::env::temp_dir().join(format!(
            "honmoon-audit-concurrent-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);

        const WRITERS: usize = 8;
        const PER_WRITER: usize = 40;
        let handles: Vec<_> = (0..WRITERS)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let log = AuditLog::with_file(4, &path).expect("open sink");
                    for _ in 0..PER_WRITER {
                        log.record(draft(Decision::Denied));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("writer panicked");
        }

        let contents = std::fs::read_to_string(&path).expect("read sink");
        let lines: Vec<&str> = contents.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), WRITERS * PER_WRITER, "no record was lost");
        for line in &lines {
            serde_json::from_str::<AuditEvent>(line)
                .unwrap_or_else(|e| panic!("line is not one whole event ({e}): {line}"));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn record_durable_reports_a_healthy_sink_and_an_absent_one_as_success() {
        // The two success arms: a sink that takes the record, and no sink at all
        // (nothing was refused, so it is not a failure). The refusal arm needs a
        // sink that fails *after* a successful open, which is below.
        let dir = std::env::temp_dir().join(format!("honmoon-audit-nosink-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = AuditLog::with_file(4, dir.join("audit.jsonl")).expect("open sink");
        let (_, written) = log.record_durable(draft(Decision::Denied));
        assert!(written.is_ok(), "a healthy sink takes the record");

        let memory_only = AuditLog::new(4);
        let (event, written) = memory_only.record_durable(draft(Decision::Degraded));
        assert!(written.is_ok(), "no sink is not a refusal");
        assert_eq!(event.decision, Decision::Degraded);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `/dev/full` accepts an open and fails every write with `ENOSPC`, which is
    /// the one portable-enough way to get a sink that refuses *after* opening —
    /// the case `record_durable` exists for (issue #131). Linux-only; macOS has
    /// no equivalent, so the assertion runs in CI's Linux job.
    #[cfg(target_os = "linux")]
    #[test]
    fn record_durable_hands_back_a_sink_that_refuses_the_write() {
        let log = AuditLog::with_file(4, "/dev/full").expect("/dev/full opens for append");
        let (event, written) = log.record_durable(draft(Decision::Degraded));
        assert!(
            written.is_err(),
            "a refused write must come back to the caller, not be swallowed"
        );
        assert_eq!(
            log.len(),
            1,
            "the ring still holds it — only the durable copy was lost"
        );
        assert_eq!(event.decision, Decision::Degraded);
    }

    #[test]
    fn a_degraded_event_round_trips_with_its_redaction_facts() {
        // The wire shape the dashboard and `@honmoon/api` read: `redaction` is
        // present only here, and absent — not null — on every other event.
        let log = AuditLog::new(4);
        let event = log.record(AuditDraft {
            decision: Decision::Degraded,
            verdict: Verdict::Allow,
            rule: Some("hook-salt-fallback".into()),
            facts: FactsSummary {
                redaction: Some(RedactionFacts {
                    key_source: RedactionKeySource::Fallback,
                    transport: RedactionTransport::Hook,
                    reason: "unwritable HOME".into(),
                }),
                ..Default::default()
            },
            approval_id: None,
        });
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains(r#""decision":"degraded""#), "{json}");
        assert!(json.contains(r#""key_source":"fallback""#), "{json}");
        assert!(json.contains(r#""transport":"hook""#), "{json}");
        let back: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.facts.redaction, event.facts.redaction);

        // An ordinary decision carries no `redaction` key at all.
        let ordinary = serde_json::to_string(&log.record(draft(Decision::Denied))).unwrap();
        assert!(!ordinary.contains("redaction"), "{ordinary}");
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
