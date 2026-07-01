# Honmoon

[![CI](https://github.com/pleaseai/honmoon/actions/workflows/ci.yml/badge.svg)](https://github.com/pleaseai/honmoon/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/pleaseai/honmoon/branch/master/graph/badge.svg)](https://codecov.io/gh/pleaseai/honmoon)
[![CodSpeed](https://img.shields.io/endpoint?url=https://codspeed.io/badge.json)](https://app.codspeed.io/pleaseai/honmoon?utm_source=badge)

> A **policy-based firewall gateway** guarding the boundary between AI agents and production systems.

Honmoon is a security gateway that intercepts an AI agent's network traffic (e.g. Claude Code,
automated workflows) and applies policy **before** requests reach their destination.

It unifies two layers of protection:

1. **Egress domain filtering** — restrict outbound HTTP/HTTPS traffic with a domain allowlist/denylist
   (the [gh-aw-firewall](https://github.com/github/gh-aw-firewall) approach)
2. **Protocol-aware policy engine** — parse protocols such as SQL, Kubernetes, and HTTP at the wire
   level to apply fine-grained rules (`deny` / `approve`) (the [clawpatrol](https://github.com/denoland/clawpatrol) approach)

## The name

**Honmoon** (혼문, 魂門) borrows from Korean lore popularized by *KPop Demon Hunters*: a
protective barrier woven to seal the human world off from the demon world. The metaphor fits —
Honmoon is the barrier you raise between your AI agents and production systems, letting only what
your policy permits cross over.

---

## Why

AI agents run shell commands, call APIs, and access databases. That power is also a risk —
a single bad inference can trigger unintended data exfiltration, destructive queries (`DROP TABLE`),
unauthorized Kubernetes resource deletion, or tokens sent to a private endpoint.

Honmoon runs the agent inside an **isolated network boundary** and inspects, allows, blocks, or holds
every outbound connection according to declarative policy.

```
┌─────────────┐      ┌──────────────────────┐      ┌─────────────────┐
│  AI Agent   │─────▶│   Honmoon Gateway    │─────▶│  External World │
│ (sandboxed) │      │  policy engine + CEL │      │ APIs / DB / K8s │
└─────────────┘      └──────────┬───────────┘      └─────────────────┘
                                │
                          allow / deny / pause(approval)
                                │
                          audit log ──▶ dashboard
```

---

## Features

- **Declarative policy** — domain allow/deny in YAML, validated by JSON Schema
- **CEL conditions** — fine-grained rules over protocol facts (SQL verb/table, K8s resource/namespace, HTTP method/path)
- **Three verdicts** — `allow` · `deny` · `pause` (wait for human approval)
- **Protocol-aware parsing** — extract protocol facts at the wire level without decryption
- **Flexible isolation modes** — process wrapper / gateway / tunnel join
- **Audit log & dashboard** — record every verdict, with an approval workflow UI
- **API credential isolation (optional)** — a sidecar that keeps LLM API keys away from the agent process

---

## Architecture

Honmoon is a monorepo that separates languages by responsibility.

| Layer | Language | Responsibility |
|-------|----------|----------------|
| **Data plane** | Rust | Wire-level proxy, protocol parsers, TLS (rustls), CEL evaluation — performance & safety critical |
| **Control plane** | TypeScript (Bun) | `honmoon` CLI, policy compiler/validation, management & audit API |
| **Dashboard** | React + Vite + Tailwind (Bun) | Audit log viewer, policy editor, approval workflow UI — embedded into the Rust binary |
| **Egress backend (optional)** | Squid (Docker) | Alternate backend when a battle-tested HTTP proxy + SSL Bump is required |

> The TypeScript side (control plane + dashboard) standardizes on **Bun** as runtime and package manager.
> The dashboard is built with **Vite** and statically embedded into the data-plane binary via `rust-embed`,
> served directly by the management API. (Mirrors [clawpatrol](https://github.com/denoland/clawpatrol)'s React dashboard setup.)

### Operating modes

| Mode | Command | Description |
|------|---------|-------------|
| **Process Wrapper** | `honmoon run -- <command>` | Isolate a single process in a network namespace (Linux netns / macOS NetworkExtension) |
| **Gateway** | `honmoon gateway` | Central proxy that loads policy and accepts client connections |
| **Join** | `honmoon join` | Route all host traffic to the gateway through a tunnel |

---

## Monorepo layout

```
honmoon-mono/
├── crates/                  # Rust — data plane
│   ├── honmoon-core/        # policy engine, CEL evaluator, facts model, audit log
│   ├── honmoon-proxy/       # wire-level proxy, protocol parsers, approval registry
│   ├── honmoon-mgmt/        # management API (axum) + embedded dashboard (rust-embed)
│   └── honmoon-cli/         # `honmoon` binary (run / gateway / join)
├── packages/                # TypeScript (Bun) — control plane
│   ├── policy/              # policy schema, JSON Schema, runtime decision model
│   ├── cli/                 # Bun-distributable wrapper CLI
│   └── api/                 # durable JSONL audit-log query API
├── apps/
│   └── dashboard/           # React + Vite + Tailwind SPA (Bun) — embedded into Rust
├── deploy/
│   └── squid/               # optional Squid egress backend (Docker Compose)
├── policies/                # example policies
└── docs/                    # design docs, policy reference
```

---

## Policy examples

A simple egress allowlist (the common case):

```yaml
# policies/agent.yaml
version: 1
egress:
  default: deny
  allow:
    - github.com
    - '*.githubusercontent.com'
    - api.anthropic.com
  deny:
    - '*.internal.corp'
```

Protocol-aware rules using CEL:

```yaml
rules:
  - name: k8s-no-secret-delete
    endpoint: k8s-prod
    condition: "k8s.resource == 'secrets' && k8s.verb == 'delete'"
    verdict: deny

  - name: sql-no-prod-drop
    endpoint: postgres-prod
    condition: "sql.verb == 'DROP' || sql.verb == 'TRUNCATE'"
    verdict: pause # requires human approval

  - name: http-block-large-upload
    endpoint: '*'
    condition: "http.method == 'POST' && http.body_size > 10485760"
    verdict: deny
```

---

## Usage (target interface)

```bash
# Run a single command in isolation — only allowed domains are reachable
honmoon run --policy policies/agent.yaml -- curl https://api.github.com

# Run the gateway: egress proxy on :8443, management API + dashboard on :8444
honmoon gateway --config policies/agent.yaml --audit-log honmoon-audit.jsonl
#   proxy:     http://127.0.0.1:8443   (point https_proxy here)
#   dashboard: http://127.0.0.1:8444   (audit log, approval queue, policy)

# Join a gateway from a client (routes all host traffic)
honmoon join --gateway honmoon.internal:8443
```

When a request hits a `pause` rule the gateway holds the connection and surfaces it
on the dashboard's **approval queue**; approving it lets the request through, denying
it returns `403`. Every verdict is recorded in the audit log.

---

## Development

> ⚠️ Early design stage. The following describes the target workflow.

**Prerequisites**
- Rust (stable)
- Bun 1.x
- (optional) Docker 20.10+ & Compose v2

```bash
# Rust data plane
cargo build --workspace
cargo test --workspace

# TypeScript control plane + dashboard
bun install
bun run build        # build dashboard (Vite) + control plane
bun test

# Dashboard dev server (HMR) — proxies /api to a local gateway on :8444
cd apps/dashboard && bun run dev
```

> The dashboard is embedded into the `honmoon` binary via `rust-embed`, so build it
> (`bun run --filter @honmoon/dashboard build`) **before** a release `cargo build`.
> A bare `cargo build` without a dashboard build still succeeds — `honmoon-mgmt`'s
> `build.rs` drops in a placeholder so the binary always links.

---

## Roadmap

Full phased roadmap (OSS / paid boundary, exit criteria): [`docs/roadmap.md`](./docs/roadmap.md).

- [x] Scaffold the Rust data plane (`crates/`)
- [x] **Phase 1** — HTTP egress MVP: terminating CONNECT proxy + domain allowlist ([ADR-0002](./.please/docs/decisions/0002-phase1-connect-proxy-on-tokio.md))
- [x] **Phase 2** — CEL evaluator + HTTP facts
- [x] **Phase 3** — SQL / Kubernetes protocol parsers
- [x] **Phase 4** — `pause` approval workflow + audit log + dashboard
- [ ] **Phase 5** — content-aware PII / DLP: body inspection + Korean-first PII detection ([benchmark goals](./docs/pii-benchmark-goals.md))
- [ ] **Phase 6** — isolation modes (`run` / `gateway` / `join`)
- [ ] **Phase 7** — team control plane (paid)
- [ ] **Phase 8** — hosted SaaS & intelligence (paid)

---

## Reference projects

Honmoon unifies the approaches of two projects:

- [github/gh-aw-firewall](https://github.com/github/gh-aw-firewall) — Squid-based egress domain filtering
- [denoland/clawpatrol](https://github.com/denoland/clawpatrol) — wire-level, protocol-aware policy gateway

---

## License

TBD
