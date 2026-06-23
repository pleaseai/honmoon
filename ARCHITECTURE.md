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
│                     @honmoon/api (audit query, Bun.serve),    │
│                     @honmoon/cli, @honmoon/dashboard (React)  │
├─────────────────────────────────────────────────────────────┤
│  Application Layer  honmoon-proxy (CONNECT egress proxy +     │
│                     approval registry + parsers),             │
│                     honmoon-mgmt (axum management API +        │
│                     embedded dashboard)                       │
├─────────────────────────────────────────────────────────────┤
│  Domain Layer       honmoon-core (Policy/Verdict/Facts/CEL +  │
│                     audit log), @honmoon/policy (types+Schema)│
├─────────────────────────────────────────────────────────────┤
│  Infrastructure     tokio sockets, axum, rust-embed, Bun,     │
│                     (Phase 2+) Pingora/TLS, (planned) D1/DO   │
└─────────────────────────────────────────────────────────────┘
```

**Invariant**: `honmoon-core` is transport-agnostic — it has no `tokio` or networking
dependency. The proxy feeds it `Facts` and consumes a `Verdict`.

## Entry Points

For understanding the data plane (the firewall itself):

- `crates/honmoon-cli/src/main.rs` — CLI dispatch for `run` / `gateway` / `join`. `gateway` runs the proxy + management API on one runtime. Start here.
- `crates/honmoon-proxy/src/gateway.rs` — the CONNECT proxy; where requests meet policy via `decide_explained()`, get audited, and (for `pause`) held.
- `crates/honmoon-proxy/src/approval.rs` — `ApprovalRegistry`: holds `pause`d requests and wakes them on resolve.
- `crates/honmoon-mgmt/src/lib.rs` — axum management API (audit query, approval queue, policy) + the embedded dashboard (`rust-embed`).
- `crates/honmoon-core/src/engine.rs` — `decide()` / `decide_explained()`: CEL rule evaluation + egress matching.
- `crates/honmoon-core/src/audit.rs` — `AuditLog` (bounded in-memory ring + optional JSONL sink), `AuditEvent`, `Decision`.
- `crates/honmoon-core/src/protocols.rs` — wire parsers (`parse_postgres_query`, `parse_sql`, `parse_k8s_request`) → SQL/K8s facts.
- `crates/honmoon-core/src/lib.rs` — the policy model (`Policy`, `Egress`, `Rule`, `Verdict`, `Facts`, `HttpFacts`, `SqlFacts`, `K8sFacts`).

For understanding the control plane and UI:

- `packages/api/src/audit.ts` — durable JSONL audit-log query layer; `src/index.ts` serves it (`Bun.serve`).
- `packages/policy/src/index.ts` + `schema/policy.schema.json` — policy types (incl. the `AuditEvent`/`PendingApproval` runtime model) and validation.
- `apps/dashboard/src/App.tsx` — dashboard SPA shell; `src/api.ts` talks to the management API; views in `src/components/`.

For understanding policy authoring:

- `policies/agent.yaml` — example policy (egress allow/deny + CEL protocol rules).

## Module Reference

| Module | Purpose | Key Files | Depends On | Depended By |
|--------|---------|-----------|------------|-------------|
| `crates/honmoon-core/` | Policy model + decision `engine` (`decide()`/`decide_explained()`): CEL rules + egress matching; `audit` (AuditLog/AuditEvent); `protocols` (PostgreSQL/K8s parsers) | `src/lib.rs`, `src/engine.rs`, `src/audit.rs`, `src/protocols.rs` | `serde`, `serde_json`, `serde_yaml`, `thiserror`, `time`, `cel-interpreter` | `honmoon-proxy`, `honmoon-mgmt`, `honmoon-cli` |
| `crates/honmoon-proxy/` | CONNECT egress proxy (`gateway`); builds `Facts`, audits decisions, holds `pause`d requests (`approval`); `GatewayState` shared with the management API | `src/gateway.rs`, `src/approval.rs` | `honmoon-core`, `tokio`, `tracing` | `honmoon-mgmt`, `honmoon-cli` |
| `crates/honmoon-mgmt/` | axum management API (audit query, approval queue, policy) + embedded dashboard (`rust-embed`) | `src/lib.rs`, `build.rs` | `honmoon-core`, `honmoon-proxy`, `axum`, `rust-embed`, `tokio` | `honmoon-cli` |
| `crates/honmoon-cli/` | `honmoon` binary — run/gateway/join; `gateway` runs proxy + management API | `src/main.rs` | `honmoon-core`, `honmoon-proxy`, `honmoon-mgmt`, `tokio`, `clap` | — (binary) |
| `packages/policy/` | TS policy types + runtime decision model + JSON Schema | `src/index.ts`, `schema/` | — | `@honmoon/cli`, `@honmoon/api`, `@honmoon/dashboard` |
| `packages/cli/` | `honmoonctl` control-plane CLI | `src/index.ts` | `@honmoon/policy` | — (binary) |
| `packages/api/` | Durable JSONL audit-log query API (Bun.serve) | `src/index.ts`, `src/audit.ts` | `@honmoon/policy` | — |
| `apps/dashboard/` | React SPA (overview/audit/policy/approvals) | `src/App.tsx`, `src/components/`, `vite.config.ts` | `@honmoon/policy` | embedded in `honmoon-mgmt` |

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

**Well-tested**: `honmoon-core` (policy parsing, audit log), `honmoon-proxy` (domain matching,
CONNECT parsing, approval registry + hermetic egress test in `tests/egress.rs`), `honmoon-mgmt`
(pause→approve/deny→tunnel/403 end-to-end in `tests/e2e.rs`), `@honmoon/api` (audit query). Safe to extend.

**Fragile / incomplete**: `honmoon run` does not yet sandbox the child's network namespace —
it only sets proxy env vars, so a child that ignores them escapes the policy. `honmoon join`
is a stub (`bail!`). SQL/K8s **parsing** exists and is tested in `honmoon-core::protocols`, but is
not yet fed by a live inline TCP relay (TD-006); over CONNECT only `http.host`-based `pause` rules
fire today. TLS termination / HTTP body inspection are unbuilt. The dashboard's policy editor is
read-only (live hot-reload is Phase 5). `@honmoon/api` query is read-only; interactive approvals
are served by the in-process management API (`honmoon-mgmt`), which must share the data plane's runtime.

**Technical debt**: TD-001 (duplicated Rust/TS policy model), TD-002 (`serde_yaml` deprecated).
Tracked in `.please/docs/tracks/tech-debt-tracker.md`.

---

_Last updated: 2026-06-23_

_Key ADRs:_

- _[ADR-0002](.please/docs/decisions/0002-phase1-connect-proxy-on-tokio.md): Phase 1 CONNECT egress proxy on raw tokio; defer Pingora to the TLS-inspection phase._
- _[ADR-0001](.please/docs/decisions/0001-adopt-pingora-http-data-plane.md): Adopt Pingora (superseded by 0002)._
- _Candidates not yet recorded: CEL over HCL, Rust data plane + Bun control plane, open-core boundary._
