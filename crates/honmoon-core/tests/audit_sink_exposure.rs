//! What `AuditLog::with_file` *reports* about a sink it accepts (issue #161),
//! exercised through the public surface only: the events land in the log's own
//! ring and in the sink, and a consumer sees nothing else.
//!
//! The mode, the owner and the link count are left as found — the assertions on
//! the file's mode here are the same ones the inline suite pins, repeated so this
//! file states the whole contract on its own: report, never correct.

#![cfg(unix)]

use honmoon_core::Verdict;
use honmoon_core::audit::{AuditLog, Decision};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "honmoon-audit-exposure-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

fn mode_of(path: &std::path::Path) -> u32 {
    std::fs::metadata(path)
        .expect("stat sink")
        .permissions()
        .mode()
        & 0o777
}

/// A sink an earlier honmoon created at the umask default, or an operator
/// loosened for a log shipper, keeps that mode — and the open now says so, as a
/// `degraded` event any reader of the log or of `GET /api/audit` sees.
#[test]
fn an_existing_permissive_sink_is_reported_when_opened() {
    let dir = scratch_dir("permissive");
    let path = dir.join("audit.jsonl");
    std::fs::write(&path, "").expect("seed sink");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("loosen sink");

    let log = AuditLog::with_file(4, &path).expect("a permissive sink is still accepted");

    let events = log.recent(10);
    assert_eq!(
        events.len(),
        1,
        "exactly one observation for a loose mode: {events:?}"
    );
    let event = &events[0];
    assert_eq!(event.decision, Decision::Degraded);
    assert_eq!(event.verdict, Verdict::Allow, "nothing was blocked");
    assert_eq!(event.rule.as_deref(), Some("audit-sink-exposed"));

    let contents = std::fs::read_to_string(&path).expect("read sink");
    let lines: Vec<&str> = contents.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "the observation is written to the sink itself"
    );
    assert!(lines[0].contains("\"audit-sink-exposed\""), "{}", lines[0]);
    assert!(
        lines[0].contains("0644"),
        "the reason names the mode: {}",
        lines[0]
    );

    assert_eq!(mode_of(&path), 0o644, "reported, not re-tightened");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `O_NOFOLLOW` constrains symbolic links only. A second directory entry on the
/// sink's inode is the trace a `link(2)` leaves, and the open reports it.
#[test]
fn a_hard_linked_sink_is_reported_when_opened() {
    let dir = scratch_dir("hard-link");
    let path = dir.join("audit.jsonl");
    let alias = dir.join("theirs.jsonl");
    std::fs::write(&path, "").expect("seed sink");
    // Owner-only, so the mode observation stays quiet and the link count is the
    // one thing this open has to say.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("tighten sink");
    std::fs::hard_link(&path, &alias).expect("link the sink under a second name");

    let log = AuditLog::with_file(4, &path).expect("a hard-linked sink is still accepted");

    let events = log.recent(10);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].decision, Decision::Degraded);
    assert_eq!(events[0].rule.as_deref(), Some("audit-sink-hard-linked"));

    let contents = std::fs::read_to_string(&alias).expect("the alias holds the same inode");
    assert!(
        contents.contains("2 directory entries"),
        "the reason counts the names: {contents}"
    );
    assert_eq!(mode_of(&path), 0o600);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The observations are independent, and the open records every one of them:
/// a sink that is both loose and hard-linked reports twice, mode first. Staged
/// through the public entry point because the unit test of the classifier says
/// nothing about whether `with_file` records more than the first draft.
#[test]
fn a_loose_and_hard_linked_sink_is_reported_twice() {
    let dir = scratch_dir("loose-hard-link");
    let path = dir.join("audit.jsonl");
    let alias = dir.join("theirs.jsonl");
    std::fs::write(&path, "").expect("seed sink");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("loosen sink");
    std::fs::hard_link(&path, &alias).expect("link the sink under a second name");

    let log = AuditLog::with_file(4, &path).expect("open sink");

    let events = log.recent(10);
    let rules: Vec<Option<&str>> = events.iter().rev().map(|e| e.rule.as_deref()).collect();
    assert_eq!(
        rules,
        [Some("audit-sink-exposed"), Some("audit-sink-hard-linked")],
        "both observations, in classification order"
    );
    let contents = std::fs::read_to_string(&path).expect("read sink");
    assert_eq!(contents.lines().count(), 2, "{contents}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The common case says nothing: a sink honmoon created itself, owner-only, with
/// one name, opens with an empty ring and an untouched file. An observation on a
/// healthy sink would be noise on every gateway start.
#[test]
fn an_owner_only_sink_is_opened_without_comment() {
    let dir = scratch_dir("quiet");
    let path = dir.join("audit.jsonl");

    let log = AuditLog::with_file(4, &path).expect("open sink");

    assert_eq!(log.len(), 0, "nothing to report: {:?}", log.recent(10));
    let contents = std::fs::read_to_string(&path).expect("read sink");
    assert!(
        contents.is_empty(),
        "a healthy sink is left untouched: {contents}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
