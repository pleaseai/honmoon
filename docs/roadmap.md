# Honmoon Roadmap

> Status: Draft (v0.3) · Last updated: 2026-07-13
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
- Decided: Pingora for the HTTP data plane ([ADR-0001](../.please/docs/decisions/0001-adopt-pingora-http-data-plane.md)) —
  since superseded: the data plane runs on raw tokio ([ADR-0002](../.please/docs/decisions/0002-phase1-connect-proxy-on-tokio.md))
  and hudsucker for TLS termination ([ADR-0003](../.please/docs/decisions/0003-adopt-hudsucker-for-tls-termination.md)).

---

## Phase 0 — Foundations ✅ (done)

| Item | Status |
|------|--------|
| Monorepo scaffold (Cargo + Bun + dashboard) | ✅ |
| Policy model + JSON Schema + example policy | ✅ |
| Knowledge docs, ARCHITECTURE.md, business model | ✅ |
| ADR-0001 (Pingora — superseded by ADR-0002/0003) | ✅ |

---

## Phase 1 — HTTP egress MVP `OSS` ✅ (done)

The first vertical slice: `honmoon run` actually enforces a domain allowlist.

- [x] Terminating `CONNECT` forward proxy in `honmoon-proxy::gateway` (raw tokio — see [ADR-0002](../.please/docs/decisions/0002-phase1-connect-proxy-on-tokio.md))
- [x] Read CONNECT host → `Facts{domain}` → `evaluate()` → allow tunnels / deny `403` / non-CONNECT `405`
- [x] `honmoon run --policy p.yaml -- <cmd>`: ephemeral proxy, set `https_proxy`/`http_proxy` for the child, exec, propagate exit code
- [x] `honmoon gateway --config p.yaml --addr ...` runs the proxy standalone
- [x] Hermetic integration test: allowed host tunnels to a local upstream, denied host blocked with 403
- [x] (done in Phase 5) TLS termination — needed for body/HTTP-level rules; delivered with hudsucker ([ADR-0003](../.please/docs/decisions/0003-adopt-hudsucker-for-tls-termination.md))

**Exit criteria**: ✅ proven by `crates/honmoon-proxy/tests/egress.rs` — an allowed host tunnels
through to an in-process upstream (`200`), a denied host is blocked (`403`), hermetically over loopback.
(The literal `curl https://github.com` smoke works too but is network-dependent; the automated test is hermetic.)

---

## Phase 2 — Policy engine: CEL + facts `OSS` ✅ (done)

- [x] Integrate `cel-interpreter` in `honmoon-core`
- [x] `decide()`: rules in order — match `endpoint`, evaluate `condition` over `Facts`, return `verdict`; else egress lists
- [x] HTTP facts (`http.method`, `http.path`, `http.host`, `http.body_size`) exposed to CEL as `http`
- [x] Rule ordering / precedence documented (first matching rule wins; deny>allow>default for egress)
- [x] Consolidated the policy engine in `honmoon-core` (domain matching moved out of `honmoon-proxy`)
- [ ] (carried) Keep Rust `honmoon-core` and TS `@honmoon/policy` in sync — TD-001

**Exit criteria**: ✅ CEL rules evaluate correctly against synthetic facts — see `crates/honmoon-core/src/engine.rs` tests (`cel_rule_matches_http_fact`, `rule_endpoint_must_match`, `unknown_fact_reference_does_not_match`).
Note: real `http.method`/`path`/`body_size` need TLS termination (later phase); over CONNECT only `http.host` is populated.

---

## Phase 3 — Protocol awareness (SQL / K8s) `OSS` ✅ (done)

The moat: wire-level protocol parsing beyond HTTP — in `honmoon-core::protocols`.

- [x] PostgreSQL simple-query (`'Q'`) wire parser → `sql.verb`, `sql.table` (`parse_postgres_query`)
- [x] SQL verb/table heuristic over a statement (`parse_sql`) — DROP/TRUNCATE/DELETE/UPDATE/INSERT/SELECT
- [x] Kubernetes API facts → `k8s.resource`, `k8s.verb`, `k8s.namespace` (`parse_k8s_request`; core + grouped APIs, list vs get)
- [x] `sql`/`k8s` facts wired into the CEL engine; per-endpoint policy binding via `Rule::endpoint`
- [ ] (carried) Live inline TCP relay that feeds the parsers from real traffic — needs endpoint listener config + (for K8s) TLS termination; see TD-006

**Exit criteria**: ✅ a `DROP`/`TRUNCATE` against `postgres-prod` and a `delete secrets` against
`k8s-prod` are caught by policy — proven end-to-end (raw packet/request → parser → `decide()`) by
`engine.rs::protocol_facts_drive_policy_end_to_end` and against the shipped `policies/agent.yaml` by
`shipped_example_policy_fires`.
Note: parsing is engine-complete and tested; wiring it onto a live socket is the data-plane follow-up (TD-006).

---

## Phase 4 — Verdicts, audit & dashboard `OSS` ✅ (done)

- [x] `pause` verdict: hold a request pending approval (local, single-node) — the data
  plane registers held requests in `honmoon-proxy::approval::ApprovalRegistry`, awaits a
  `oneshot` resolution (auto-rejects after `--pause-timeout`), and tunnels or `403`s
- [x] Local audit log (every verdict, structured) — `honmoon-core::audit::AuditLog`
  (bounded in-memory ring + optional JSONL sink via `--audit-log`) + query API: the
  in-process management API serves the live ring; `@honmoon/api` queries the durable JSONL
  log (`/api/audit` with `limit`/`decision`/`since`/`domain`, `/api/audit/stats`)
- [x] Dashboard (`apps/dashboard`): Overview, audit log viewer, Prism policy editor, and
  approval queue with approve/deny — live-polling the management API
- [x] Embed built dashboard into the Rust binary via `rust-embed` (`honmoon-mgmt`); the
  management API serves it. `honmoon gateway` runs the proxy + management API on one
  runtime sharing audit/approval state (`--mgmt-addr`, default `127.0.0.1:8444`)

**Exit criteria**: ✅ proven by `crates/honmoon-mgmt/tests/e2e.rs` — a `pause` rule holds a
live CONNECT, the held request appears on the management API's approval queue, approving it
(over HTTP) lets the tunnel through (`200`) while rejecting blocks it (`403`), and every step
(`paused` → `approved`/`rejected`) is recorded in the audit log.
Note: over CONNECT only `http.host`-based pause rules fire today; SQL/K8s `pause` needs the
live inline relay + TLS termination (TD-006).

---

## Phase 5 — Content-aware PII / DLP `OSS`

Close the exfiltration gap: inspect *what* leaves, not just where / which protocol. Korean-first
PII detection over request bodies, surfaced as CEL facts. Detection is OSS; fleet-wide DLP
management and compliance reporting are Paid (Phase 7).

> **Prerequisite — TLS termination / body access** (✅ done, [ADR-0003](../.please/docs/decisions/0003-adopt-hudsucker-for-tls-termination.md)). Over a
> raw CONNECT tunnel only `http.host` is visible; PII detection needs the decrypted body. The data
> plane now terminates TLS (hudsucker MITM, opt-in local CA) and scans decrypted bodies
> (detect-only), which also unblocks body-level SQL/K8s facts (TD-006).

- [x] TLS termination in the data plane (**hudsucker**, not Pingora — [ADR-0003](../.please/docs/decisions/0003-adopt-hudsucker-for-tls-termination.md)) so request bodies reach the engine. Detect-only: decrypted bodies are scanned and findings audited (`--tls-intercept`, opt-in local CA). Proven by `crates/honmoon-proxy/tests/mitm.rs`.
- [x] Tier-1 deterministic PII detector in `honmoon-core::pii` (Rust regex + checksum/Luhn):
  RRN, FRN, business reg. no., card (Luhn), email, IPv4, phone. (passport / driver / account /
  vehicle deferred — loose-format / keyword-anchored, precision risk)
- [ ] Tier-2 format / dictionary detectors (postal code, medical IDs, DOB / age, …)
- [x] Expose `pii.types` / `pii.count` / `pii.max_severity` as CEL facts; wire to `allow`/`deny`/`pause`
  (`Facts.pii`, registered in `engine::eval_condition`, carried in the audit `FactsSummary`)
- [ ] Detect (audit-only) vs block (enforcing) modes — precision-first block, recall-first audit.
  Detect-only over terminated TLS is live ([ADR-0003](../.please/docs/decisions/0003-adopt-hudsucker-for-tls-termination.md)); enforcing (deny/pause on `pii`) is the fast follow.
- [ ] (optional) NER assist layer for PERSON / ADDRESS, kept **off** the inline path (audit / async)
- [ ] Benchmark harness ([`pii-benchmark-goals.md`](./pii-benchmark-goals.md)) — `pii_scan` bridge +
  `score.ts` measurement loop in place (Tier-1 F1 1.000 on `honmoon-synth`, §9.1); CI regression gate TODO

**Exit criteria**: a request body carrying a valid-checksum RRN to a non-allowlisted host is
caught by policy (`deny`/`pause`), measured against the targets in
[`pii-benchmark-goals.md`](./pii-benchmark-goals.md) — Tier-1 F1 ≥ 0.98, payload-surface micro-F1
≥ 0.80, rule-layer p99 ≤ 2 ms/doc.
Note: fleet-wide DLP policy management and compliance / exfil reporting are Paid (Phase 7).

---

## Phase 6 — Isolation modes `OSS`

- [ ] `honmoon gateway` — standalone central proxy loading policy, accepting clients
- [ ] `honmoon run` hardened isolation (Linux netns / macOS NetworkExtension)
- [ ] `honmoon join` — route host traffic to a gateway via tunnel (WireGuard)
- [ ] Policy hot-reload (graceful reload without dropping tunnels)

**Exit criteria**: all three modes work end-to-end on Linux; documented setup.

---

## Agent-side integrations — Claude Code plugin `OSS`

> Can run in parallel with Phases 5–6; builds on the Phase 5 detectors and the secret
> tokenization primitive.

The proxy is the enforcement backstop: every request — including the full conversation
history agent clients resend each turn — crosses the wire through honmoon, so the model
never sees a raw secret. What the proxy *cannot* reach is what the client persists locally
before sending: Claude Code stores raw prompts and raw `Read` output in its session
transcript (`~/.claude/projects/**/*.jsonl`), which then feeds `/resume`, compaction,
subagents, and backups/sync. Client-side hooks close that gap by redacting *before* content
enters the transcript — the plugin doubles as lightweight onboarding (no local CA trust
needed).

- [ ] Claude Code plugin with redaction hooks (#19): `PostToolUse` on `Read` replaces the
  tool result via `updatedToolOutput` (redacted in both model context and transcript);
  `UserPromptSubmit` blocks prompts carrying secrets (hooks cannot rewrite a prompt — block
  + actionable reason); `PreToolUse` denies reads of known-sensitive paths (`.env*`, key files)
- [ ] `honmoon hook` CLI subcommand: hook JSON on stdin → Tier-1 detectors + reversible
  secret tokenization from `honmoon-core` → hook JSON verdict, so the plugin is a thin
  shell around the same engine the proxy uses
- [ ] Cache-stable determinism on the proxy path (#20): identical secret → identical token
  across turns, so redacting the resent history preserves the provider prompt-cache prefix
- [ ] (nice-to-have) Share the tokenization mapping store between plugin and co-running
  proxy so tokens stay consistent across layers (relates to #16)

**Exit criteria**: reading a file with a valid-checksum RRN or an API key lands redacted in
both the model context and the session transcript JSONL; a prompt carrying a secret is
blocked with actionable feedback; same multi-turn body redacted twice is byte-identical (#20).

---

## Phase 7 — Team / control plane `Paid`

The open-core boundary. Monetization begins where single-node becomes fleet.

- [ ] Centralized policy management across multiple nodes/agents
- [ ] RBAC / SSO / SAML
- [ ] Approval routing + Slack notifications
- [ ] Long-term audit retention & search; compliance/exfil reports (incl. PII/DLP findings from Phase 5)
- [ ] `packages/enterprise/` under a commercial license (BSL/FSL)

---

## Phase 8 — Hosted SaaS & intelligence `Paid`

- [ ] Hosted management plane (`apps/cloud/`), multi-tenant
- [ ] Managed allowlists + threat-intel feeds
- [ ] API-credential isolation sidecar (Anthropic/OpenAI/Gemini) with rate limiting
- [ ] SLA / support tiers

---

## Cross-cutting (ongoing)

- **Licensing**: move core to Apache-2.0; add `LICENSE.enterprise` (BSL/FSL) when Phase 7 lands.
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
