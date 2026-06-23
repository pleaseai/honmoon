# AGENTS.md — TypeScript Control Plane (`packages/`)

The TypeScript/Bun control plane: policy types, the control-plane CLI, and the management/audit
API. **Mostly scaffold today** — `@honmoon/policy` types are real and used; the API serves only
`/healthz`; `honmoonctl validate` is a stub. See the root `AGENTS.md` for project-wide setup.

## Build & Run Commands

```bash
bun install
bun run --filter '@honmoon/*' build
bun run lint            # eslint
bun run typecheck       # tsc --noEmit across the workspace
bun --filter @honmoon/api dev    # run the API in watch mode
```

## The packages

| Package | Role | Status |
|---------|------|--------|
| `@honmoon/policy` | Policy TS types (`Verdict`/`Egress`/`Rule`/`Policy`) + JSON Schema | Types real & used; mirror of the Rust model (TD-001) |
| `@honmoon/cli` | `honmoonctl` — policy validate/lint, talks to the gateway API | `validate` is a TODO stub |
| `@honmoon/api` | Management & audit API on `Bun.serve` | Only `GET /healthz`; audit/approvals/policy routes are TODO |

## Testing

`bun test` — **no tests exist yet** in `packages/*`. CI runs lint/typecheck/build only. If you add
real behavior here, add `bun test` coverage and re-enable the test step in CI.

## Code Style

- Bun runtime; ESM only; `strict: true`; `verbatimModuleSyntax`.
- Lint via `@pleaseai/eslint-config`. Keep imports type-only where appropriate
  (`import type { Policy } from '@honmoon/policy'`).

## Boundaries

- ✅ **Always**: keep `@honmoon/policy` in lockstep with the Rust model in `crates/honmoon-core`
  (TD-001); build out `TODO`s against the existing JSON Schema as the contract.
- ⚠️ **Ask first**: changing the policy type shape (must update Rust + JSON Schema too);
  introducing a new runtime dependency or a non-Bun tool.
- 🚫 **Never**: let the TS model silently diverge from the Rust model; reimplement policy
  decisioning here — the data plane (`honmoon-core`) is the single decision authority.
