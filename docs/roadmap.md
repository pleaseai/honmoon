# Honmoon Roadmap

> Status: Draft (v0.1) · Last updated: 2026-06-20
>
> A phased path from the current scaffold to a production-grade, open-core firewall
> gateway. Phases are roughly sequential but later OSS phases can overlap. The
> **OSS / Paid** column marks the open-core boundary (see [`business-model.md`](./business-model.md)).

## Where we are

Greenfield monorepo, scaffolded and building:

- Cargo workspace (`honmoon-core`, `honmoon-proxy`, `honmoon-cli`) — builds, 4 tests pass.
- Bun workspace (`@honmoon/policy`, `@honmoon/cli`, `@honmoon/api`) + React/Vite/Tailwind dashboard.
- Policy model (YAML + JSON Schema), example policy, `evaluate()` with domain matching.
- `honmoon run/gateway/join` are CLI stubs (`bail!`).
- Decided: Pingora for the HTTP data plane ([ADR-0001](../.please/docs/decisions/0001-adopt-pingora-http-data-plane.md)).

---

## Phase 0 — Foundations ✅ (done)

| Item | Status |
|------|--------|
| Monorepo scaffold (Cargo + Bun + dashboard) | ✅ |
| Policy model + JSON Schema + example policy | ✅ |
| Knowledge docs, ARCHITECTURE.md, business model | ✅ |
| ADR-0001 (Pingora) | ✅ |

---

## Phase 1 — HTTP egress MVP `OSS`

The first vertical slice: `honmoon run` actually enforces a domain allowlist.

- [ ] Pingora `ProxyHttp` service in `honmoon-proxy` (forward proxy, `CONNECT` opt-in)
- [ ] `request_filter` → build `Facts{domain}` from SNI/Host → `evaluate()` → allow/deny (4xx)
- [ ] `honmoon run --policy p.yaml -- <cmd>`: set `https_proxy`/`http_proxy` for the child, exec
- [ ] BoringSSL TLS backend wired; graceful start/stop
- [ ] Integration test: allowed domain succeeds, denied domain blocked

**Exit criteria**: `honmoon run --policy policies/agent.yaml -- curl https://github.com` succeeds
while a non-allowlisted host is blocked, proven by an automated test.

---

## Phase 2 — Policy engine: CEL + facts `OSS`

- [ ] Integrate a CEL evaluator (`cel-interpreter` or equivalent) in `honmoon-core`
- [ ] `Rule` evaluation: match `endpoint`, evaluate `condition` over `Facts`, return `verdict`
- [ ] HTTP facts (`http.method`, `http.path`, `http.host`, `http.body_size`)
- [ ] Rule ordering / precedence semantics documented
- [ ] Keep Rust `honmoon-core` and TS `@honmoon/policy` in sync (resolve TD-001 direction)

**Exit criteria**: the CEL rules in `policies/agent.yaml` evaluate correctly against synthetic facts.

---

## Phase 3 — Protocol awareness (SQL / K8s) `OSS`

The moat: wire-level protocol parsing beyond HTTP.

- [ ] Generic TCP relay path on raw `tokio` (non-HTTP), endpoint routing
- [ ] PostgreSQL wire parser → `sql.verb`, `sql.table`
- [ ] Kubernetes API facts → `k8s.resource`, `k8s.verb`, `k8s.namespace`
- [ ] Per-endpoint policy binding (`endpoint: postgres-prod`, `k8s-prod`)

**Exit criteria**: a `DROP`/`TRUNCATE` against `postgres-prod` and a `delete secrets` against
`k8s-prod` are caught by policy.

---

## Phase 4 — Verdicts, audit & dashboard `OSS`

- [ ] `pause` verdict: hold a request pending approval (local, single-node)
- [ ] Local audit log (every verdict, structured) + query API in `@honmoon/api`
- [ ] Dashboard: audit log viewer, policy editor (Prism), approval queue
- [ ] Embed built dashboard into the Rust binary via `rust-embed`; served by the management API

**Exit criteria**: a `pause` rule surfaces in the dashboard and can be approved/denied; the
decision is recorded in the audit log.

---

## Phase 5 — Isolation modes `OSS`

- [ ] `honmoon gateway` — standalone central proxy loading policy, accepting clients
- [ ] `honmoon run` hardened isolation (Linux netns / macOS NetworkExtension)
- [ ] `honmoon join` — route host traffic to a gateway via tunnel (WireGuard)
- [ ] Policy hot-reload via Pingora graceful reload

**Exit criteria**: all three modes work end-to-end on Linux; documented setup.

---

## Phase 6 — Team / control plane `Paid`

The open-core boundary. Monetization begins where single-node becomes fleet.

- [ ] Centralized policy management across multiple nodes/agents
- [ ] RBAC / SSO / SAML
- [ ] Approval routing + Slack notifications
- [ ] Long-term audit retention & search; compliance/exfil reports
- [ ] `packages/enterprise/` under a commercial license (BSL/FSL)

---

## Phase 7 — Hosted SaaS & intelligence `Paid`

- [ ] Hosted management plane (`apps/cloud/`), multi-tenant
- [ ] Managed allowlists + threat-intel feeds
- [ ] API-credential isolation sidecar (Anthropic/OpenAI/Gemini) with rate limiting
- [ ] SLA / support tiers

---

## Cross-cutting (ongoing)

- **Licensing**: move core to Apache-2.0; add `LICENSE.enterprise` (BSL/FSL) when Phase 6 lands.
- **Tech debt**: TD-001 (dual policy model → generate from JSON Schema), TD-002 (`serde_yaml`).
- **CI/CD**: set up `cargo test`/`clippy`/`fmt` + `bun test`/`lint` gates once a remote exists.
- **Optional Squid backend**: `deploy/squid/` as an alternate HTTP egress backend.
- **Cloudflare target**: a Workers deployment can host the egress filter + control plane only;
  the wire-level core requires a host/container.

---

## Platform reality check

Not every layer runs everywhere — record this so scope stays honest:

| Capability | Self-host (host/container) | Cloudflare Workers |
|------------|----------------------------|--------------------|
| HTTP egress filter + control plane | ✅ | ✅ (explicit proxy only) |
| Wire-level SQL/K8s, `run`/`join`, TLS MITM | ✅ | ❌ (needs OS networking) |
