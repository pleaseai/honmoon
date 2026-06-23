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
| `honmoon-core` | Policy model, `decide_explained()` engine (CEL + egress), `audit` log, protocol parsers | **None — pure logic** |
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
- 🚫 **Never**: add `tokio`, sockets, or any I/O dependency to `honmoon-core`; decrypt or buffer
  full payloads beyond what a rule needs; weaken tests to pass.

Open tech debt touching this dir: TD-002 (`serde_yaml` deprecated), TD-003 (`run` isolation is
advisory), TD-006 (parsers not on a live socket). See `.please/docs/tracks/tech-debt-tracker.md`.
