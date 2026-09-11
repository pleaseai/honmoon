---
name: project-audit-sink-nofollow-138
description: What #138/PR #163 changed in the audit sink open, and the libc-in-honmoon-core dependency judgment two reviewers reached independently
metadata:
  type: project
---

`AuditLog::with_file` (`crates/honmoon-core/src/audit.rs`) routes the operator-supplied
`--audit-log` / `HONMOON_AUDIT_LOG` path through `open_sink()`, which on Unix adds
`O_NOFOLLOW` (refuses a symlink as the final component, CWE-59), `O_NONBLOCK` (so a FIFO
cannot block the short-lived `honmoon hook` process), `mode(0o600)`, and a post-open
`fstat` refusing anything that is not a regular file. `explain_refusal` rewrites the one
misleading errno — `O_NOFOLLOW` reports a refused symlink as `ELOOP`, "Too many levels of
symbolic links", which describes a link cycle.

Two contract details worth keeping straight, both of which a first draft got wrong:

- **`mode(0o600)` is a ceiling, not a guarantee** — it is filtered through the process
  umask (`umask 0200` yields `0400`). The test asserts `mode & 0o077 == 0`, not equality;
  asserting the exact value fails on a machine whose umask is *stricter* than required.
- **It applies on creation only.** An existing sink keeps whatever mode it has, which is
  deliberate and tracked in #161 — see [[audit-sink-residual-gaps]] before accepting that
  issue as covering the adversarial form.

**Dependency judgment (reached independently by the code and security reviewers).**
`crates/AGENTS.md` lists "adding a new workspace dependency" as ask-first and "any I/O
dependency to honmoon-core" as never. `libc = "0.2"` was already in the root
`[workspace.dependencies]` and already used by `honmoon-cli`; the PR only adds
`[target.'cfg(unix)'.dependencies] libc.workspace = true` to honmoon-core, for the two
`O_*` constants `OpenOptionsExt::custom_flags` needs. No production syscall goes through
`libc` (only `libc::mkfifo` in tests), and the I/O stays `std::fs`, which this module
already did before the PR. Read as triggering neither rule: the ask-first rule is about
introducing a new external crate to the graph, not wiring an already-pinned one to one
more member. A bot reviewer (codex) read it the other way and proposed moving the open to
the CLI; that was answered on the PR — moving it would leave the public `with_file`
unhardened, so the next caller reinvents the defect.

**CI platform split, worth knowing before claiming coverage:** `.github/workflows/ci.yml`
runs `cargo test --workspace` on ubuntu only; the macOS job is scoped to
`-p honmoon-cli`. So `honmoon-core`'s `#[cfg(unix)]` tests execute on Linux in CI and on
a developer's machine, never on macOS in CI.
