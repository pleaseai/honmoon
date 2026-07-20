# Tech Stack

> Technology choices with rationale. Mirrors the monorepo layout.

## Overview

Honmoon is a monorepo that separates languages by responsibility.

| Layer | Language / Tool | Why |
|-------|-----------------|-----|
| Data plane | **Rust** (edition 2024) | Wire-level proxy, protocol parsers, TLS, CEL eval — performance & memory safety critical. Single-binary deploy. The egress proxy runs on **hudsucker** (MITM HTTP/S on hyper + rustls + rcgen) for TLS termination + content inspection ([ADR-0003](../decisions/0003-adopt-hudsucker-for-tls-termination.md)); Pingora was evaluated and rejected ([ADR-0002](../decisions/0002-phase1-connect-proxy-on-tokio.md)). |
| Control plane | **TypeScript on Bun** | CLI, policy compiler/validation, management & audit API. Fast iteration, ESM, native HTTP server. |
| Dashboard | **React 19 + Vite 8 + Tailwind 4** | SPA embedded into the Rust binary via `rust-embed`. Mirrors clawpatrol for component reuse. |
| Egress backend (optional) | **Squid (Docker)** | Battle-tested HTTP proxy + SSL Bump as an alternate backend. |

## Rust crates (`crates/`)

- `honmoon-core` — policy model (`Policy`/`Egress`/`Rule`/`Verdict`/`Facts` + `HttpFacts`/`SqlFacts`/`K8sFacts`), YAML parsing, the decision `engine` (`decide()`: CEL + egress matching), `protocols` (PostgreSQL `'Q'` + SQL + Kubernetes API parsers), and `secret_tokenizer` (reversible secret↔placeholder tokenization: HMAC-SHA256 keyed placeholders, aho-corasick leftmost-longest matching, boundary-safe streaming detokenizer). Transport-agnostic.
  - deps: `serde`, `serde_yaml` (⚠️ deprecated, see TD-002), `thiserror`, `tracing`, `cel-interpreter`, `aho-corasick`, `hmac`, `sha2`
- `honmoon-proxy` — egress proxy on **hudsucker** (`gateway` + `mitm` handler + `ca`) enforcing the
  host allowlist and, when `--tls-intercept` is set, terminating TLS to scan request bodies.
  `--pii-mode detect` audits body-policy verdicts (default); `--pii-mode block` enforces them inline.
  - deps: `honmoon-core`, `tokio`, `hudsucker`, `http-body-util`, `serde`, `thiserror`, `tracing`
  - Host-level allowlist applies to every tunnel (intercepted or raw); TLS termination (MITM) uses a
    local rcgen CA agents must trust. See [ADR-0003](../decisions/0003-adopt-hudsucker-for-tls-termination.md).
- `honmoon-cli` — `honmoon` binary (`run` / `gateway` / `join`).
  - deps: `honmoon-core`, `honmoon-proxy`, `tokio`, `clap`, `anyhow`, `tracing`, `tracing-subscriber`

Workspace deps are pinned centrally in the root `Cargo.toml` `[workspace.dependencies]`.

## TypeScript packages (`packages/`, `apps/`)

- `@honmoon/policy` — policy TS types + JSON Schema (`schema/policy.schema.json`). Mirror of the Rust model.
- `@honmoon/cli` — `honmoonctl` control-plane CLI (policy validate/lint, talks to gateway API).
- `@honmoon/api` — management & audit API on `Bun.serve` (`/healthz`, → `/api/audit`, `/api/approvals`, `/api/policy`).
- `@honmoon/dashboard` — React SPA. Charts via `@observablehq/plot`, policy editor via `prismjs` + `react-simple-code-editor`.

## Policy format

- **YAML** for the common case (egress allow/deny), validated by **JSON Schema**.
- **CEL** expressions for protocol-aware conditional rules. Chosen over HCL because CEL has
  Rust/TS/Go implementations → portable across data and control planes.

## Tooling

- Rust: `cargo` workspace, `rust-toolchain.toml` (stable + rustfmt + clippy).
- JS: **Bun 1.x** as runtime + package manager (workspaces: `packages/*`, `apps/*`). Vite for the dashboard bundle.
- Versions present: cargo 1.94, bun 1.3.x, node 24 (bun preferred).

## Licensing direction

- Core: **Apache-2.0** (current scaffold pins MIT — to be changed).
- Enterprise/cloud: **BSL/FSL**. See [`docs/business-model.md`](../../../docs/business-model.md).
