# AGENTS.md — Rust Data Plane (`crates/`)

The Rust data plane: the performance- and safety-critical components that touch the wire. Four
crates; the dependency chain is `honmoon-cli → honmoon-mgmt → honmoon-proxy → honmoon-core`. This
file covers data-plane specifics; see the root `AGENTS.md` for project-wide commands and conventions.

## Build & Run Commands

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all

# Run / debug the CLI
cargo run -p honmoon-cli -- gateway --config policies/agent.yaml
RUST_LOG=honmoon_proxy=debug cargo run -p honmoon-cli -- gateway --config policies/agent.yaml
```

## The crates

| Crate | Role | I/O? |
|-------|------|------|
| `honmoon-core` | Policy model, `decide_explained()` / `decide_pii_audit_only()` engine (CEL + egress), `audit` log, protocol parsers | **one file — the audit sink** |
| `honmoon-proxy` | tokio CONNECT egress proxy (`gateway.rs`); builds `Facts`, audits decisions, holds `pause`d requests (`approval.rs`); `GatewayState` shared with the management API | tokio sockets |
| `honmoon-mgmt` | axum management API (audit query, approval queue, policy) + embedded dashboard (`rust-embed`) | axum + filesystem (embed) |
| `honmoon-cli` | `honmoon` binary: `run` / `gateway` (proxy + mgmt API) / `join` | process + sockets |

## Testing

Tests are inline (`#[cfg(test)] mod tests`) plus integration tests: `honmoon-proxy/tests/egress.rs`
(CONNECT allow/deny) and `honmoon-mgmt/tests/e2e.rs` (`pause` → approve-over-HTTP → tunnel, and
reject → 403, with audit assertions). The richest unit suites are in `honmoon-core/src/engine.rs`,
`protocols.rs`, and `audit.rs`, and `honmoon-proxy/src/approval.rs`. Write the failing test first;
the existing tests are your templates.

## Code Style

- Edition 2024; `cargo fmt` + `clippy -D warnings` clean (warnings are CI errors).
- Errors: `thiserror` in libraries (`honmoon_core::Error`), `anyhow` in the binary. Unimplemented
  modes `bail!` with an explicit message — they must not fail open.
- Logging via `tracing` (`RUST_LOG`). Workspace deps are pinned centrally in the root `Cargo.toml`.

## Boundaries

- ✅ **Always**: keep `honmoon-core` transport-agnostic; preserve fail-closed (default-deny, a
  broken rule never allows); extract only declared protocol facts.
- ⚠️ **Ask first**: changing `decide()` precedence (rules-then-egress); changing the policy struct
  shape (sync TS + JSON Schema — TD-001); adding a new workspace dependency.
- 🚫 **Never**: give `honmoon-core` an async runtime, a socket, or a network client; decrypt or
  buffer full payloads beyond what a rule needs; weaken tests to pass.

### What `honmoon-core` may touch

The crate is **transport-agnostic, not I/O-free**, and that distinction is the rule. It opens
exactly one file — the audit JSONL sink in `audit.rs`, at an operator-supplied path. Everything
else in the crate takes what it works on as an argument: `Policy::from_yaml` parses a string,
and whoever read the file is the caller.

**Still forbidden**, which is what makes the exception an exception: `tokio` or any async
runtime; a socket or a network client of any kind (`hyper`, `reqwest`, `axum`); reading the
environment or locating a config file; spawning a process; and opening any *second* file. A new
file this crate wants to own is a new decision — the sink's precedent does not grant it.

And one prohibition that is not a capability at all, because the risk here is an *alternative
route* rather than a new power: **a second way to populate the sink.** A constructor or setter
that assigns `AuditLog`'s `sink` from a descriptor `open_sink` did not produce adds no
dependency, opens no second file, spawns nothing and reads no environment — it satisfies every
clause above while bypassing `O_NOFOLLOW`, the walk, the trusted-directory rule, `O_NONBLOCK`,
the regular-file `fstat` and all three `audit-sink-*` events at once, in a diff that reads as a
pure layering refactor. `with_file` is the only such path today and must stay the only one. A
list of forbidden capabilities does not catch this, which is why it is written out separately.

Half of that list is checked and half is not, so do not read it as enforced.
`honmoon-core/tests/crate_boundary.rs` fails if the crate's build-dependency set moves, which
catches the entries that need a new crate to reach — the runtime, the socket, the HTTP client.
It cannot catch the rest: an environment read, a spawned process and a second file all reach
through `std` and the `libc` already present, so nothing in the manifest moves and the test
stays green. Those three are held by review, and the test's own module doc says the same.

**Why the sink open is here** (issue #166, following #163). The hardening around it —
`O_NOFOLLOW`, the component-by-component `openat` walk that refuses an untrusted symlinked
parent, the trusted-directory rule, `O_NONBLOCK`, and the regular-file `fstat` — enforces an
invariant of `AuditLog` itself, not of whoever calls it. `append_jsonl` writes synchronously on
the decision path, a blocking open of a FIFO stalls the short-lived `honmoon hook` process until
the agent times out, and a sink reached through somebody else's symlink publishes every host,
SQL table and PII category honmoon records. The type whose own correctness depends on what the
descriptor is should be the type that establishes it; handing `AuditLog` an already-open `File`
turns that guarantee into a convention each caller has to remember, which is the shape
issue #138 was.

Stated no more strongly than it is true: the invariant is **descriptor-scoped**. What the
`fstat` settles — regular file, mode, owner, link count — is a property of the object
`AuditLog` ends up holding. The walk's trust decisions are not purely that: for a relative path
the walk's root is the process's own working directory, and the trusted-directory rule reads
the process's effective uid, so one path can be accepted under one caller and refused under
another. That part *is* caller context, and it is the strongest form of the case for moving the
open to `honmoon-cli` — the CLI knows its working directory and privilege posture, and a
library does not. It does not carry the decision, because moving the open makes all of the
hardening optional rather than only its context-dependent edge; but it is the part of the
objection that survives, and a future proposal should be answered on it rather than on the
`libc` question.

Moving the open to `honmoon-cli` was the alternative, and it buys less than it appears to:
`AuditLog` would still own the descriptor and still write and flush through it, so the crate
does file I/O either way and this section would read much as it does now. What would change is
only which crate calls `open`. `libc` is here for that open and nothing else: the
directory-relative syscalls `openat`, `fstatat` and `readlinkat`, `geteuid` for the trust rule,
and the flag, errno, file-type and struct definitions those four take. Every descriptor they
return is handed straight to `std::fs::File`, which owns and closes it.

Test code is not held to this: the audit suite builds FIFO fixtures with `libc::mkfifo` and
spawns threads, and nothing it links reaches a shipped binary.

Open tech debt touching this dir: TD-002 (`serde_yaml` deprecated), TD-003 (`run` isolation is
advisory), TD-006 (parsers not on a live socket). See `.please/docs/tracks/tech-debt-tracker.md`.
