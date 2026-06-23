# AGENTS.md — Honmoon

Honmoon is a policy-based firewall gateway for AI agents. Polyglot monorepo: a **Rust data
plane** (`crates/`) and a **TypeScript/Bun control plane + React dashboard** (`packages/`,
`apps/`). Early-stage: Phases 0–3 implemented and tested; Phases 4–7 are roadmap. See
`ARCHITECTURE.md` and `wiki/` for the full picture.

## Build & Run Commands

The toolchain is driven by **mise** (wraps both ecosystems). Rust uses `rust-toolchain.toml`.

```bash
mise trust && mise install      # node 24 + bun; Rust via rustup
mise run install                # cargo fetch && bun install
mise run build                  # cargo build --workspace && bun run build
mise run test                   # cargo test --workspace && bun test
mise run lint                   # cargo clippy -D warnings && bun run lint
mise run check                  # full gate: lint → test (CI parity)

# Run the data-plane CLI
cargo run -p honmoon-cli -- run --policy policies/agent.yaml -- curl https://api.github.com
cargo run -p honmoon-cli -- gateway --config policies/agent.yaml --addr 127.0.0.1:8443
```

## Testing

- **Rust** is the meaningful suite today: inline `#[cfg(test)]` unit tests + the hermetic
  integration test `crates/honmoon-proxy/tests/egress.rs`. Run `cargo test --workspace`.
- **TypeScript**: `bun test` — no TS tests exist yet; CI runs lint/typecheck/build only.
- **TDD is mandatory**: write the failing test first, then implement. Target >80% coverage for
  new code. See `.please/docs/knowledge/workflow.md`.

## Project Structure

| Path | What |
|------|------|
| `crates/honmoon-core/` | Policy model, `decide()` engine, protocol parsers. **Transport-agnostic — no I/O.** |
| `crates/honmoon-proxy/` | tokio CONNECT egress proxy. |
| `crates/honmoon-cli/` | `honmoon` binary (`run` / `gateway` / `join`). |
| `packages/policy/` | TS policy types + JSON Schema (mirror of the Rust model). |
| `packages/cli/`, `packages/api/` | `honmoonctl` + management API (scaffolds). |
| `apps/dashboard/` | React + Vite SPA (scaffold). |
| `policies/` | Example policies. |
| `wiki/` | Generated VitePress documentation site. |
| `.please/docs/` | Knowledge docs, ADRs, tech-debt tracker. |

## Code Style

- **Rust** (edition 2024): `cargo fmt` + `clippy -D warnings` clean. Errors via `thiserror`
  (libraries) / `anyhow` (binary). Keep `honmoon-core` free of networking deps.
- **TypeScript**: Bun runtime, ESM only, `strict: true`, `verbatimModuleSyntax`. Lint via
  `@pleaseai/eslint-config`.

## Git Workflow

Conventional Commits, one commit per task: `feat(core): …`, `fix(proxy): …`, `test(core): …`,
`docs(wiki): …`. Types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert.
Run `mise run check` before committing.

## Boundaries

- ✅ **Always**: keep `honmoon-core` transport-agnostic; preserve fail-closed (default-deny);
  write tests first; mark planned vs implemented honestly in docs.
- ⚠️ **Ask first**: changing the policy *shape* (must update Rust + TS + JSON Schema together —
  TD-001); changing the `decide()` precedence; altering the open-core boundary.
- 🚫 **Never**: add `tokio`/sockets/I/O to `honmoon-core`; weaken or delete tests to make code
  pass; add payload decryption / deep packet inspection beyond declared facts; gate the data
  plane behind a paywall.

See also: `wiki/AGENTS.md` (docs), `crates/AGENTS.md`, `packages/AGENTS.md`,
`apps/dashboard/AGENTS.md`.
