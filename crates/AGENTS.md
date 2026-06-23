# AGENTS.md — Rust Data Plane (`crates/`)

The Rust data plane: the performance- and safety-critical components that touch the wire. Three
crates in a strict dependency chain `honmoon-cli → honmoon-proxy → honmoon-core`. This file covers
data-plane specifics; see the root `AGENTS.md` for project-wide commands and conventions.

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
| `honmoon-core` | Policy model (`Policy`/`Egress`/`Rule`/`Verdict`/`Facts`), `decide()` engine (CEL + egress matching), protocol parsers (`protocols.rs`) | **None — pure logic** |
| `honmoon-proxy` | tokio CONNECT egress proxy (`gateway.rs`); builds `Facts`, calls `decide()` | tokio sockets |
| `honmoon-cli` | `honmoon` binary: `run` / `gateway` / `join` | process + sockets |

## Testing

Tests are inline (`#[cfg(test)] mod tests`) plus the integration test
`honmoon-proxy/tests/egress.rs`. The richest suites are in `honmoon-core/src/engine.rs` (decision
precedence, CEL, fail-closed) and `honmoon-core/src/protocols.rs` (parser edge cases). Write the
failing test first; the existing tests are your templates.

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
