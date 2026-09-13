---
name: core-io-boundary-rule
description: "After #166 crates/AGENTS.md states honmoon-core opens exactly one file (the audit sink) instead of claiming no I/O — what the 'Still forbidden' list covers, which half tests/crate_boundary.rs enforces, and the second-sink-constructor clause that a capability-shaped rule would have missed"
metadata:
  type: project
---

`crates/AGENTS.md` no longer says `honmoon-core` is "pure logic / no I/O". Since issue #166 it
carries a "What `honmoon-core` may touch" section: the crate opens **exactly one file**, the
audit JSONL sink in `audit.rs`, and still forbids an async runtime, a socket, a network/HTTP
client, an environment read, a config-file lookup, a spawned process, and any *second* file.

**What is actually enforced.** `crates/honmoon-core/tests/crate_boundary.rs` reads
`cargo metadata --no-deps` and asserts the non-dev dependency name set (including
`[target.'cfg(unix)'.dependencies] libc`). That is the dependency-borne half of the rule —
`tokio`, a socket crate, an HTTP client. The std-mediated half (`std::env::var`,
`std::process::Command`, a second `std::fs` open) adds no dependency and fails no test. The
section states that division itself, so it is a documented limit rather than a gap to report.

**The clause a capability list would have missed.** The rule also forbids **a second way to
populate the sink**: a constructor or setter assigning `AuditLog`'s `sink` from a descriptor
`open_sink` did not produce. Such a change adds no dependency, opens no second file, spawns
nothing and reads no environment — it satisfies every capability clause while bypassing
`O_NOFOLLOW`, the component walk, the trusted-directory rule, `O_NONBLOCK`, the regular-file
`fstat` and all three `audit-sink-*` observations at once, in a diff that reads as a layering
refactor. It was added to the written rule and to the `sink` field's own doc comment during
review of PR #206, after a security pass found the capability-shaped list did not reach it.
`with_file` is the only such path; `AuditLog::new` leaves `sink` as `None`, and one test in
`audit.rs` assigns the field directly to build a sink that refuses writes — which is why this is
a rule about production code rather than something Rust privacy enforces on its own.

**The limit of the "invariant of the type" argument.** #166 keeps the open in core because the
hardening enforces an invariant of `AuditLog` rather than a caller convention. That is
descriptor-scoped and the amended doc now says so: the `fstat` results (regular file, mode,
owner, link count) are properties of the object the type holds, but the walk's trust decisions
are not purely that — for a relative path the walk root is the process's working directory, and
`require_link_in_a_trusted_directory` reads the process's effective uid, so one path can be
accepted under one caller and refused under another. A future proposal to move the open to
`honmoon-cli` should be answered on that, not on whether `libc` is an I/O dependency.

**How to apply:** a finding that "honmoon-core violates its no-I/O rule" is answered — the sink
open is a decision; see [[audit-sink-open-hardening]] and [[audit-sink-residual-gaps]] for what
that open does and does not defend. Live findings: a second file, a runtime, a socket, an env
read, or a second path that populates the sink.
