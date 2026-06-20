# Architecture

> Bird's-eye view of the Honmoon monorepo. Describes structure and intent, not
> implementation detail. For product context see `.please/docs/knowledge/`.

## System Overview

**Purpose**: Honmoon is a policy-based firewall gateway that intercepts an AI agent's
network traffic and applies policy (`allow` / `deny` / `pause`) before requests reach
their destination.

**Primary users**: AI agents (sandboxed clients of the gateway), the developers/security
teams who write policy, and AI coding agents that maintain this repo.

**Core workflow**:

1. An agent's outbound request enters the data plane (process wrapper, gateway, or tunnel).
2. The proxy extracts protocol `Facts` (domain, and later HTTP/SQL/K8s) at the wire level.
3. The policy engine evaluates the facts → a `Verdict`; the request is allowed, blocked, or
   held for human approval, and the decision is recorded to the audit log.

**Key constraints**: Fail closed (default `deny`). The data plane is performance- and
safety-critical (Rust). Auditability is a hard requirement — the traffic-inspecting code
must remain open source.

## Dependency Layers

Dependencies flow downward only. Lower layers must not import upper layers.

```
┌─────────────────────────────────────────────────────────────┐
│  Interface Layer    honmoon-cli (run/gateway/join),           │
│                     @honmoon/api (Bun.serve), @honmoon/cli,   │
│                     @honmoon/dashboard (React SPA)            │
├─────────────────────────────────────────────────────────────┤
│  Application Layer  honmoon-proxy (CONNECT egress proxy +     │
│                     parsers), api handlers                    │
├─────────────────────────────────────────────────────────────┤
│  Domain Layer       honmoon-core (Policy/Verdict/Facts/CEL),  │
│                     @honmoon/policy (types + JSON Schema)     │
├─────────────────────────────────────────────────────────────┤
│  Infrastructure     tokio sockets, rust-embed, Bun,           │
│                     (Phase 2+) Pingora/TLS, (planned) D1/DO   │
└─────────────────────────────────────────────────────────────┘
```

**Invariant**: `honmoon-core` is transport-agnostic — it has no `tokio` or networking
dependency. The proxy feeds it `Facts` and consumes a `Verdict`.

## Entry Points

For understanding the data plane (the firewall itself):

- `crates/honmoon-cli/src/main.rs` — CLI dispatch for `run` / `gateway` / `join`. Start here.
- `crates/honmoon-proxy/src/lib.rs` — `evaluate()` and domain matching; where requests meet policy.
- `crates/honmoon-core/src/lib.rs` — the policy model (`Policy`, `Egress`, `Rule`, `Verdict`, `Facts`).

For understanding the control plane and UI:

- `packages/api/src/index.ts` — management & audit API (`Bun.serve`).
- `packages/policy/src/index.ts` + `schema/policy.schema.json` — policy types and validation.
- `apps/dashboard/src/App.tsx` — dashboard SPA shell.

For understanding policy authoring:

- `policies/agent.yaml` — example policy (egress allow/deny + CEL protocol rules).

## Module Reference

| Module | Purpose | Key Files | Depends On | Depended By |
|--------|---------|-----------|------------|-------------|
| `crates/honmoon-core/` | Policy model, YAML parse, CEL eval (planned) | `src/lib.rs` | `serde`, `serde_yaml`, `thiserror` | `honmoon-proxy`, `honmoon-cli` |
| `crates/honmoon-proxy/` | CONNECT egress proxy (`gateway`) + `evaluate()`; SQL/K8s parsers later | `src/gateway.rs`, `src/lib.rs` | `honmoon-core`, `tokio`, `tracing` | `honmoon-cli` |
| `crates/honmoon-cli/` | `honmoon` binary — run/gateway/join | `src/main.rs` | `honmoon-core`, `honmoon-proxy`, `clap` | — (binary) |
| `packages/policy/` | TS policy types + JSON Schema | `src/index.ts`, `schema/` | — | `@honmoon/cli`, `@honmoon/api`, `@honmoon/dashboard` |
| `packages/cli/` | `honmoonctl` control-plane CLI | `src/index.ts` | `@honmoon/policy` | — (binary) |
| `packages/api/` | Management & audit API (Bun.serve) | `src/index.ts` | `@honmoon/policy` | `@honmoon/dashboard` |
| `apps/dashboard/` | React SPA (audit/policy/approvals) | `src/App.tsx`, `vite.config.ts` | `@honmoon/policy` | embedded in data plane |

## Architecture Invariants

**Fail closed**: The default egress verdict is `deny`. Absence of a matching allow/deny entry
must never silently allow a request. Violating this turns the firewall into a no-op.

**Data plane stays open source**: Any component that inspects traffic or credentials
(`crates/*`) must remain Apache-2.0 (or equivalent OSS). Monetization happens in the
control/cloud plane only. Gating the data plane breaks the trust that drives adoption.

**`honmoon-core` is transport-agnostic**: Do NOT add `tokio`, sockets, or any I/O
dependency to `honmoon-core`. It is pure policy logic so it can be embedded anywhere and
unit-tested without a runtime. Transport/proxy code stays in `honmoon-proxy` / `honmoon-cli`.

**Dual policy model stays in sync**: The Rust model (`honmoon-core`) and the TS model
(`@honmoon/policy`) describe the same policy. Changes to one must update the other (tracked as
TD-001). The JSON Schema is the intended future single source of truth.

**No decryption surprises**: Extract only declared protocol `Facts` at the wire level. Do NOT
add deep packet inspection that decrypts payloads beyond what policy needs and documents.

## Cross-Cutting Concerns

**Error handling**: Rust libraries use `thiserror` (`honmoon_core::Error`); the binary uses
`anyhow`. Unimplemented modes currently `bail!` with an explicit message rather than failing open.

**Logging**: Rust uses `tracing` + `tracing-subscriber` (controlled by `RUST_LOG` env filter).
TS uses console/Bun logging for now.

**Testing**: Rust unit tests live inline (`#[cfg(test)]`) — `cargo test --workspace`. TS uses
`bun test`. Target >80% coverage for new code (see `.please/docs/knowledge/workflow.md`).

**Configuration**: Policy is YAML (`policies/*.yaml`), validated by
`packages/policy/schema/policy.schema.json`. Workspace deps are pinned centrally in the root
`Cargo.toml` (`[workspace.dependencies]`); JS workspaces are declared in the root `package.json`.

## Quality Notes

**Well-tested**: `honmoon-core` (policy parsing), `honmoon-proxy` (domain matching, CONNECT
parsing + hermetic egress integration test in `tests/egress.rs`). Safe to extend.

**Fragile / incomplete**: `honmoon run` does not yet sandbox the child's network namespace —
it only sets proxy env vars, so a child that ignores them escapes the policy. `honmoon join`
is a stub (`bail!`). TLS termination / HTTP body inspection and SQL/K8s parsing are unbuilt.
The dashboard and API are scaffolds.

**Technical debt**: TD-001 (duplicated Rust/TS policy model), TD-002 (`serde_yaml` deprecated).
Tracked in `.please/docs/tracks/tech-debt-tracker.md`.

---

_Last updated: 2026-06-20_

_Key ADRs:_

- _[ADR-0002](.please/docs/decisions/0002-phase1-connect-proxy-on-tokio.md): Phase 1 CONNECT egress proxy on raw tokio; defer Pingora to the TLS-inspection phase._
- _[ADR-0001](.please/docs/decisions/0001-adopt-pingora-http-data-plane.md): Adopt Pingora (superseded by 0002)._
- _Candidates not yet recorded: CEL over HCL, Rust data plane + Bun control plane, open-core boundary._
