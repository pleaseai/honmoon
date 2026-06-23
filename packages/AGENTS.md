# AGENTS.md — TypeScript Control Plane (`packages/`)

The TypeScript/Bun control plane: policy types, the control-plane CLI, and the durable audit-query
API. As of Phase 4 `@honmoon/policy` (types + runtime model) and `@honmoon/api` (audit query, with
tests) are real; `honmoonctl validate` remains a stub. Note the **interactive** management API
(audit ring + approvals + dashboard) is the Rust `honmoon-mgmt`, not a TS service. See the root
`AGENTS.md` for project-wide setup.

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
| `@honmoon/policy` | Policy types **+ runtime model** (`AuditEvent`, `PendingApproval`, `Decision`) + JSON Schema | Real & used; mirror of the Rust model (TD-001) |
| `@honmoon/api` | Durable JSONL audit-query API (`/api/audit?limit=&decision=&since=&domain=`, `/api/audit/stats`) on `Bun.serve` | Real & tested (`audit.test.ts`) |
| `@honmoon/cli` | `honmoonctl` — policy validate/lint | `validate` is a TODO stub |

## Testing

`bun test` runs `@honmoon/api`'s `audit.test.ts` (the repo's first TS suite). CI runs
lint/typecheck/build but **not** `bun test` yet — run it locally. Add `bun test` coverage for any
new behavior; keep the pure query functions in `audit.ts` unit-tested.

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
