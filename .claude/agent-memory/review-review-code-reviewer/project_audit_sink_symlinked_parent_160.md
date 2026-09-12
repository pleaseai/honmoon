---
name: project-audit-sink-symlinked-parent-160
description: 'PR #179 (issue #160) — open_sink now walks the audit path component-by-component with openat/fstatat/readlinkat from a trusted root; reviewed clean (builds, clippy -D warnings, full suite incl. new relative-path test all pass); libc usage escalated from flag-constants-only to actual production syscalls, which changes the premise of the prior ask-first/no-I/O judgment in [[project_audit_sink_nofollow_138]]'
metadata:
  type: project
---

`crates/honmoon-core/src/audit.rs::open_sink_file` (PR #179, closing #160) replaces the single
`O_NOFOLLOW` open (which only guarded the final path component) with a component-by-component
`openat(O_NOFOLLOW | O_DIRECTORY)` walk from a trusted root (`/` for absolute, cwd for relative).
A symlinked directory component is followed only when the directory holding it is writable by
nobody but root/euid (`mode & 0o022 == 0` and `uid == 0 || uid == euid`); the followed target's
components are spliced back into the walk queue (front-pushed in reverse order — verified
correct). Hop budget 40 (matches `SYMLOOP_MAX`). Final component is still refused
unconditionally via `O_NOFOLLOW`, unchanged from #138. A bounded retry (4 attempts) on `ENOENT`
in the leaf `openat` works around a real macOS `openat`+`O_CREAT` race (measured, not
speculative, per the doc comment).

Traced in detail and found sound: component classification (`RootDir`/`CurDir`/`ParentDir`/
`Normal`), the trust predicate reads the *holding directory's* fstat off the descriptor the walk
already pins (no TOCTOU — if the directory is genuinely trusted, an attacker cannot race an entry
into it; if untrusted, the same permission check rejects it regardless of a race), CString/fd
lifetimes in every `unsafe` block, errno captured immediately via `last_os_error()` with no
intervening libc call, and no double-ownership of descriptors. Compiles, `clippy -D warnings`,
and the full `honmoon-core` suite (207 + 1 new relative-path integration test) all pass locally.

**Worth flagging, not blocking:** the `Cargo.toml` comment for `libc.workspace = true` under
`[target.'cfg(unix)'.dependencies]` changed from "`open_sink` makes no syscall through `libc`" (PR
#163, see [[project_audit_sink_nofollow_138]]) to this PR now calling `openat`/`fstatat`/
`readlinkat`/`geteuid` directly in production code. The prior two-reviewer judgment that this
dependency triggers neither the ask-first ("new workspace dependency") nor the never
("I/O dependency to honmoon-core") rule in `crates/AGENTS.md` was reached on the premise that no
production syscall went through libc — that premise is now false. The crate already did file
I/O via `std::fs` for the audit sink pre-#138, so this reads as hardening an already-accepted
capability rather than a new one, but it's a judgment call worth re-confirming explicitly rather
than assuming the earlier sign-off still covers it.
