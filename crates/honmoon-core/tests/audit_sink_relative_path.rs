//! The sink walk's trusted root for a *relative* `--audit-log` is the process's
//! own working directory, and that branch cannot be reached from `audit.rs`'s
//! inline suite: exercising it needs `set_current_dir`, which is process-global and
//! would corrupt every test sharing that binary. This file holds exactly one test
//! so the directory change has no neighbours to race with.
//!
//! Both directions are asserted together, because the failure mode of getting the
//! root wrong is not an error — a walk that started at `/` regardless would open
//! `/audit.jsonl`, or refuse a path that works today, and only comparing the two
//! outcomes says which root was used.

use honmoon_core::audit::AuditLog;

#[cfg(unix)]
#[test]
fn a_relative_audit_path_is_walked_from_the_working_directory() {
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!(
        "honmoon-audit-relative-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    // `temp_dir` on macOS is reached through the root-owned `/var -> private/var`
    // symlink, so the walk resolves it before it ever sees this directory; what
    // follows is about the components below it.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777))
        .expect("make the directory one another local user could write");

    let attacker = dir.join("attacker");
    std::fs::create_dir(&attacker).expect("create the attacker's directory");
    std::os::unix::fs::symlink(&attacker, dir.join("logs")).expect("plant symlink");

    std::env::set_current_dir(&dir).expect("enter the scratch dir");

    // A relative path resolves against this directory, not against `/`.
    let log = AuditLog::with_file(4, "audit.jsonl").expect("a relative sink path still opens");
    assert_eq!(
        log.sink_path(),
        Some(&std::path::PathBuf::from("audit.jsonl"))
    );
    assert!(
        dir.join("audit.jsonl").exists(),
        "the sink must be created in the working directory"
    );

    // And the walk that starts there refuses a planted symlink exactly as the
    // absolute one does.
    let Err(err) = AuditLog::with_file(4, "logs/audit.jsonl") else {
        panic!("a symlinked parent on a relative path must be refused too");
    };
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");
    assert!(err.to_string().contains("is a symlink"), "{err}");
    assert!(
        !attacker.join("audit.jsonl").exists(),
        "the refused open must not have created the sink through the link"
    );

    // Leave the working directory somewhere that still exists before removing it.
    std::env::set_current_dir(std::env::temp_dir()).expect("leave the scratch dir");
    let _ = std::fs::remove_dir_all(&dir);
}
