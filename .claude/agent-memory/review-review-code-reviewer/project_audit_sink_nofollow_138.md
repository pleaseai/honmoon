---
name: project-audit-sink-nofollow-138
description: PR #163 (issue #138) audit sink O_NOFOLLOW/O_NONBLOCK hardening — reviewed clean, libc dep judgment call resolved
metadata:
  type: project
---

PR #163 hardens `AuditLog::with_file` (`crates/honmoon-core/src/audit.rs`) via a new
`open_sink()`: `O_NOFOLLOW` (blocks symlink retargeting, CWE-59) + `O_NONBLOCK` (prevents
a FIFO from blocking the `honmoon hook` short-lived process) + post-open `fstat`-based
regular-file check (immune to TOCTOU since it checks the fd, not the path) + `mode(0o600)`
on creation only. Reviewed clean: builds and passes on macOS (verified locally — 12
audit tests + 18 hook tests), clippy/fmt clean, CI's ubuntu job runs
`cargo test --workspace` (catches the `#[cfg(target_os = "linux")]` tests like
`/dev/full` char-device refusal), macOS job is scoped to `-p honmoon-cli` but still
compiles honmoon-core. `#[cfg(unix)]`/`#[cfg(not(unix))]` split on `describe_file_type`
is consistent with `open_sink`'s own inline `#[cfg(unix)]` block.

**Dependency judgment**: `crates/AGENTS.md` lists "adding a new workspace dependency" as
ask-first. `libc = "0.2"` was already declared in root `Cargo.toml`
`[workspace.dependencies]` and already used by `honmoon-cli` before this PR — the PR only
adds `[target.'cfg(unix)'.dependencies] libc.workspace = true` to honmoon-core's own
Cargo.toml, referencing the existing pin. Read this as *not* triggering "ask first": that
rule is about introducing a new external crate to the graph, not wiring an
already-pinned crate to one more workspace member. Only production use is two `O_*`
flag constants passed through `std::fs`'s `OpenOptionsExt::custom_flags` — no syscall goes
through `libc` directly except `libc::mkfifo` in test code. Does not read as violating
"Never: add ... any I/O dependency to honmoon-core" either, on the same reasoning.

**Minor-only finding**: the two call sites (`honmoon-cli/src/main.rs:338`,
`honmoon-cli/src/hook.rs:436`) wrap the io::Error with their own "opening audit log
{path}" / "could not record ... in {path}" context, which duplicates path text already
present in `open_sink`'s own `InvalidInput` message for the post-open type-check case
(char/block device). Cosmetic only, not flagged as more than a low-confidence nitpick —
matches the `with_context` pattern used everywhere else in this codebase.
