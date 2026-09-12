# AGENTS.md — Honmoon

Honmoon is a policy-based firewall gateway for AI agents. Polyglot monorepo: a **Rust data
plane** (`crates/`) and a **TypeScript/Bun control plane + React dashboard** (`packages/`,
`apps/`). Early-stage: Phases 0–4 implemented and tested (egress proxy, CEL engine, SQL/K8s
parsers, `pause` approval hold, audit log, embedded dashboard); Phases 5–7 are roadmap. See
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
| `crates/honmoon-core/` | Policy model, `decide_explained()` / `decide_pii_audit_only()` engine, `audit` log, protocol parsers. **Transport-agnostic — no I/O.** |
| `crates/honmoon-proxy/` | tokio CONNECT egress proxy + `approval` registry (pause hold). |
| `crates/honmoon-mgmt/` | In-process axum management API + embedded dashboard (`rust-embed`). |
| `crates/honmoon-cli/` | `honmoon` binary (`run` / `gateway` / `join`). |
| `packages/policy/` | TS policy types + runtime decision model + JSON Schema (mirror of the Rust model). |
| `packages/api/` | Durable JSONL audit-query API (Bun). `packages/cli/` `honmoonctl` (stub). |
| `apps/dashboard/` | React + Vite SPA (Overview/Audit/Policies/Approvals), embedded into the binary. |
| `policies/` | Example policies. |
| `wiki/` | Generated VitePress documentation site. |
| `.please/docs/` | Knowledge docs, ADRs, tech-debt tracker. |
| `.claude/agent-memory/` | Per-agent review notes (tracked) + a generated `MEMORY.md` index (not tracked). |

## Agent Memory

Agents record findings as one note per file under `.claude/agent-memory/<agent>/`, and those
notes are committed with the PR that produced them. The `MEMORY.md` beside them is the index
an agent loads to choose a note; it is **generated and git-ignored**, so never edit or commit
it — put the one-line summary in the note's own frontmatter `description:`, which is what the
index line is built from.

```bash
bun scripts/agent-memory-index.ts            # rebuild (also: mise run agent-memory-index)
bun scripts/agent-memory-index.ts --check    # CI gate: every note can supply its line
```

Quote a `description:` that is anything but plain prose. The generator reads the frontmatter
with `Bun.YAML` (issue #168), so the index says what a YAML reader resolves — and a plain scalar
ends at the first ` #`, which makes `description: fixed in PR #155, then do X` resolve to the
summary `fixed in PR`. Rather than publish a summary that stops mid-sentence, the generator
reports the cut and `--check` fails until the value is quoted. The same holds for a description
YAML resolves to something that is not text at all: a flow collection (`[a]`, `{a: b}`) or a
number (`42`, `1e3`, `0644`). A value of `null` or `~` resolves to no value, which reads as a
note with no description. A block no reader can load is reported on its own, against the
frontmatter line the reader gave up on where the block is short enough to locate one (the
search is bounded at 200 lines); so is an indexed key the frontmatter gives twice, which YAML
resolves to the last of them without a word — in any spelling written at the key itself, though
not one an alias defines elsewhere (#205).

Not reasons to quote, since the parser resolves them to the text the index then publishes: a
leading `&`, `*` or `!` (an anchor, an alias, a tag — though an alias naming no anchor is a load
failure), a bare date, and the YAML 1.1 spellings 1.2 leaves as text such as `1_000` or `12:00`.

Hand-appending a shared index made every concurrent PR that recorded a memory for the same
agent collide on one line, and duplicated each claim into a second place that drifted from the
note (issue #129). `mise run install` rebuilds the indexes, and `orca.yaml`'s worktree setup
builds a fresh one — a derived file is not copied between worktrees, because the source
checkout's copy describes whatever branch that checkout is on. A checkout that has done neither
still has every note: it is missing the table of contents, not the memory, until the next rebuild.

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
