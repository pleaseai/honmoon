---
name: core-io-boundary-166
description: "honmoon-core owns the audit sink open by decision, not by oversight: what crates/AGENTS.md forbids after #166, and the two premises that kept getting argued wrong"
metadata:
  type: project
---

Issue #166 settled whether `honmoon-core` may open the operator-supplied audit sink. It may,
and `crates/AGENTS.md` now says so in a "What `honmoon-core` may touch" section. The old text
("I/O? **None — pure logic**", "Never: add tokio, sockets, or any I/O dependency") had been
false since the JSONL sink existed and was the thing #166 fixed.

**The rule as it now stands.** `honmoon-core` opens exactly one file — the audit JSONL sink in
`audit.rs`. Still forbidden: an async runtime, a socket, a network or HTTP client, reading the
environment or locating a config file, spawning a process, and opening any *second* file. The
sink's precedent grants none of those, and `crates/honmoon-core/tests/crate_boundary.rs` fails
if the build-dependency set moves at all.

**Two premises reviewers keep getting wrong on this question.**

1. *"Moving the open to honmoon-cli would make the crate pure."* It would not. `AuditLog` owns
   the `Mutex<File>` and `append_jsonl` writes and flushes through it on the decision path, so
   the crate does file I/O whether or not it performs the `open`. Any proposal to move the open
   has to be argued on layering alone — it buys no change to what the crate does, only to which
   crate calls `open`.
2. *"`with_file` is `pub` on a published crate, so removing it is breaking."* `with_file` is
   `pub`, but the crate is **not published**: `docs/releasing.md` says the Rust crates are
   workspace-internal and not on crates.io, and only the `honmoon` binary ships. Issue #163 and
   the body of #166 both leaned on this and both were wrong. Do not cite it either way.

**Why the open stays in core** (the argument that does hold): the hardening enforces an
invariant of `AuditLog` itself. `append_jsonl` writes synchronously, so whether the descriptor
is a regular file decides whether a record blocks the process, and whether it was reached
through an untrusted symlink decides who reads the hosts, SQL tables and PII categories the log
carries. `with_sink(capacity, file, path)` cannot express that in its signature — it makes the
hardened path something each caller must remember, which is the shape issue #138 was.

**How to apply:** treat a finding that `honmoon-core` "violates its no-I/O rule" as answered —
point at the Boundaries section rather than reopening it. A finding that the crate gained a
*second* file, a runtime, a socket or an env read is live and the section says so explicitly.
And when weighing any proposal to move the sink open, check both premises above before
accepting the trade-off as stated.
