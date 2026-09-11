# Honmoon

[![CI](https://github.com/pleaseai/honmoon/actions/workflows/ci.yml/badge.svg)](https://github.com/pleaseai/honmoon/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/pleaseai/honmoon/branch/main/graph/badge.svg)](https://codecov.io/gh/pleaseai/honmoon)
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
| **Process Wrapper** | `honmoon run -- <command>` | Isolate a single process so the proxy is its only route out (Linux and macOS; advisory elsewhere) |
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

Protocol-aware rules using CEL, bound to named endpoints:

```yaml
# Named targets, matched on the exact (host, port) a client dials.
endpoints:
  k8s-prod: {host: k8s.internal, port: 6443, protocol: kubernetes}
  postgres-prod: {host: db.internal, port: 5432, protocol: postgres}

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
# Run a single command in isolation — only allowed domains are reachable.
# `run` binds two ephemeral loopback listeners and points the child at both:
#   http_proxy / https_proxy (and uppercase) → the CONNECT proxy
#   all_proxy  / ALL_PROXY                   → socks5h://127.0.0.1:<port>
honmoon run --policy policies/agent.yaml -- curl https://api.github.com

# Run the gateway: egress proxy on :8443, SOCKS5 on :1080, dashboard on :8444
honmoon gateway --config policies/agent.yaml --audit-log honmoon-audit.jsonl
# Intercept TLS and enforce PII policy verdicts (detect-only is the default mode)
honmoon gateway --config policies/agent.yaml --tls-intercept --pii-mode block
#   proxy:     http://127.0.0.1:8443   (point https_proxy here)
#   socks5:    127.0.0.1:1080          (point ALL_PROXY here; --socks-addr)
#   dashboard: http://127.0.0.1:8444   (audit log, approval queue, policy)

# Join a gateway from a client (routes all host traffic)
honmoon join --gateway honmoon.internal:8443
```

### SOCKS5 and inline PostgreSQL inspection

`honmoon gateway` also binds a SOCKS5 listener (`--socks-addr`, default `127.0.0.1:1080`) beside
the HTTP proxy. It is the transport for everything that speaks neither HTTP nor TLS, and its
handshake carries the destination `host:port` that selects an endpoint from the policy. A
connection to a host declared `protocol: postgres` is **inspected inline**: every `Q` (simple
query) and `P` (Parse) frame is parsed into `sql.verb` / `sql.table` and gets its own verdict, so
a `DROP TABLE` is refused with SQLSTATE `42501` naming the rule and never reaches the database,
while the session stays open. Any other destination is a raw tunnel gated on `domain` exactly like
a CONNECT. `honmoon run` binds the same SOCKS5 listener on an ephemeral port and exports it to the
child as `ALL_PROXY`, so inline PostgreSQL inspection works under both modes. PostgreSQL
inspection requires the client to dial **through SOCKS5**
(`ALL_PROXY=socks5h://127.0.0.1:1080`) — `psql` does not speak SOCKS5 natively, so wrap it in a
SOCKS-aware launcher such as `proxychains4`, and use `sslmode=prefer`/`disable`, since inline
inspection needs plaintext between the client and honmoon. See
[ADR-0007](.please/docs/decisions/0007-inline-postgresql-runtime-semantics.md).

That raw tunnel is a **second egress path with no body inspection**: a client that dials an
`https://` host through it gets the `domain` gate and nothing else — no TLS interception, no PII
scan, no redaction, no `http.*` rule. Keep `egress.default: deny` so only allow-listed hosts can
use it, or pass `--socks-addr off` to run the CONNECT proxy alone.

### Wire redaction fail modes

`--redact-secrets` (with `--tls-intercept`) rewrites intercepted request bodies before the
upstream leg. Where it cannot rewrite safely it **fails open** — the original bytes are forwarded
unredacted and a `warn` is logged: bodies over the 2 MiB inspection cap, non-UTF-8/binary bodies,
bodies whose declared `Content-Encoding` cannot be decoded, and partial uploads carrying
`Content-Range`. Compressed responses are not detokenized (the proxy asks upstreams for `identity`
— except when the request's authentication signs headers or binds the body, since `Accept-Encoding`
may itself be signed; those responses may arrive compressed and are then left as they are).

**Signed requests are the exception that fails closed when redaction would change what the
signature covers.** When a request's authentication covers its payload — AWS SigV4 whose canonical
request hashed the payload, RFC 9421 message signatures or draft-cavage signatures over a body
digest — honmoon holds no signing credentials and cannot re-sign the rewritten body, so the
upstream would reject it with an opaque signature error. The same applies when the signature
covers a header that rewriting the body has to re-frame: replacing the payload rewrites
`Content-Length` and drops `Content-Encoding`/`Transfer-Encoding`, and an AWS SDK upload lists
`content-length` in `SignedHeaders` even when `UNSIGNED-PAYLOAD` leaves the body itself
redactable. By default such a request is refused locally with `403`, an `X-Honmoon-Reason:
signed-body-redaction` header (`signed-header-redaction` for the header case), and an
explanation:

```bash
# Default: refuse a body-signed request whose body would be redacted
honmoon gateway --config policies/agent.yaml --tls-intercept --redact-secrets

# Opt out: forward the original bytes unredacted (fail open) instead
honmoon gateway --config policies/agent.yaml --tls-intercept --redact-secrets \
  --signed-body forward
```

Bearer tokens, Basic auth, and API keys authenticate the caller rather than the bytes, so requests
carrying them are redacted normally — as are SigV4 uploads that declare
`x-amz-content-sha256: UNSIGNED-PAYLOAD` and whose `SignedHeaders` list leaves the framing headers
alone. A presigned URL is in the same group unless it also declares a *signed* payload — a real
SHA-256, or a `STREAMING-AWS4-…` per-chunk marker, in the `x-amz-content-sha256` header (or, when it
sends none, in the `X-Amz-Content-Sha256` query parameter presigning hoists that header into): on
its own its signature covers the request and the headers it names, not the uploaded bytes. So is a
bare payload hash with no AWS authentication on the request — that is an integrity check, not a
signature. The covered list is parsed rather than assumed, and only headers the rewrite would actually
change count. A signed request with nothing to redact is always forwarded untouched. See [ADR-0006](.please/docs/decisions/0006-signed-body-requests-under-wire-redaction.md).

### What `honmoon run` enforces, and what it costs

On **Linux and macOS**, the wrapped command is left with no network route that avoids the proxy.
A child that ignores the proxy variables does not slip past policy — it reaches nothing over the
network. (Unix sockets on the filesystem are the documented exception — see below.)

The two platforms reach that from opposite directions, and the difference shows up in the limits:

| | Linux | macOS |
|---|-------|-------|
| Mechanism | a new user + network namespace holding nothing but loopback, with both proxies bridged in over one Unix socket each | a Seatbelt profile under `sandbox-exec` denying every socket but honmoon's two loopback ports |
| The child's loopback | private to the namespace | shared with the host |
| Needs | unprivileged user namespaces enabled | nothing — `sandbox-exec` ships with macOS |

Consequences worth knowing before you hit them:

- **Two proxies, and the child is pointed at both.** `run` binds a CONNECT proxy and a SOCKS5
  listener on separate ephemeral loopback ports. `http_proxy` / `https_proxy` (and their uppercase
  spellings) name the first; `all_proxy` / `ALL_PROXY` name the second, as
  `socks5h://127.0.0.1:<port>`. The `h` keeps DNS on honmoon's side, which is what puts the
  hostname into the SOCKS5 handshake where it selects an `endpoints:` entry — so a
  `protocol: postgres` endpoint is inspected statement by statement under `run` exactly as it is
  under `gateway`.
- **A client that honours neither variable reaches nothing, by design.** Anything that reads
  neither `HTTP_PROXY` nor `ALL_PROXY` — a binary with its own dialler, a tool with a hardcoded
  socket — cannot connect at all under `run`. That is the deliberate fail-closed default of
  [ADR-0005](.please/docs/decisions/0005-empty-namespace-and-bridged-proxy-sockets.md), not a bug
  to work around: the child is not asked to cooperate, it is left with no other route.

  `psql` is the example worth naming, because it looks like a counterexample and is not. It
  honours neither variable — it speaks no SOCKS5 natively and no HTTP at all — so under `run` it
  connects to nothing. Reaching a `postgres` endpoint means putting something SOCKS-aware between
  `psql` and the tunnel: a wrapper that intercepts the connect (`proxychains-ng` and similar), or
  a local forwarder that terminates a plain TCP port and dials out over SOCKS5. honmoon does not
  ship, bundle or support either; which one fits is yours to decide. Also pass
  `sslmode=prefer`/`disable`, since inline inspection needs plaintext between the client and
  honmoon.
- **Names are resolved by the proxy, not by the child.** There is no DNS inside the sandbox on
  either platform. A proxied client does not need it — it hands the proxy a hostname — but a tool
  that resolves before it proxies will fail.
- **Elsewhere it is advisory, and says so.** On a platform with no implementation, on a Linux host
  whose kernel refuses unprivileged user namespaces, or on a macOS host where the Seatbelt profile
  no longer compiles, `run` sets the proxy variables and prints a warning on stderr naming the
  bypass. It never claims enforcement it does not have.

The boundary is honest about privilege too: this confines an **unprivileged** child. A child that
can become root, already holds `CAP_SYS_ADMIN`, or has passwordless `sudo` can leave the sandbox —
use `honmoon join` where that matters. Neither platform touches the filesystem, so Unix sockets that
live there — `/var/run/docker.sock` and friends — stay reachable, and anything a local daemon behind
one will do on the child's behalf is still a way out. Keep those sockets away from the uid you run
under. For the same reason, do not hand honmoon a connected network socket as its own stdin, stdout
or stderr and expect the child not to reach that peer: the child needs those three descriptors, so
it inherits them, and a socket keeps its binding across both mechanisms.

Two macOS-only caveats, recorded here rather than discovered later. A command that **daemonizes**
leaves descendants behind, and `run` returns when its direct child exits — closing both proxy ports
while those descendants still carry a profile whose exceptions name them. Those ports are then free
for any local process to bind, and that process is an off-policy relay for them (the window covers
the SOCKS5 port as well as the CONNECT one). Linux does not
have this: an empty namespace stays empty whoever else is on the host, while Seatbelt leaves the
child on the *host* loopback. Holding the port for the whole process group would close it and stop
`run` returning when the command does; that is an ADR-0005 amendment, tracked under TD-003. And
`sandbox-exec` is formally deprecated by Apple. It is what Claude Code ships on today, so it is serviceable, but if Apple
removes it the fallback is a `NETransparentProxyProvider` system extension — signing, notarization
and all.

When a request hits a `pause` rule the gateway holds the connection and surfaces it
on the dashboard's **approval queue**; approving it lets the request through, denying
it returns `403`. Every verdict is recorded in the audit log.

---

## Installation

Prebuilt `honmoon` binaries are published for every release on the
[Releases page](https://github.com/pleaseai/honmoon/releases). Supported targets:

| Target | Platform |
| --- | --- |
| `x86_64-unknown-linux-gnu` | Linux, x86-64 |
| `aarch64-unknown-linux-gnu` | Linux, arm64 |
| `aarch64-apple-darwin` | macOS, Apple silicon |

Each archive contains the `honmoon` binary plus `LICENSE` and `README.md`.

**Linux (x86-64)**

```bash
# Latest version: https://github.com/pleaseai/honmoon/releases/latest
VERSION=0.1.0
curl -fsSL "https://github.com/pleaseai/honmoon/releases/download/v${VERSION}/honmoon-${VERSION}-x86_64-unknown-linux-gnu.tar.gz" \
  | tar -xz honmoon
sudo install -m 755 honmoon /usr/local/bin/honmoon
```

**macOS (Apple silicon)**

```bash
# Latest version: https://github.com/pleaseai/honmoon/releases/latest
VERSION=0.1.0
curl -fsSL "https://github.com/pleaseai/honmoon/releases/download/v${VERSION}/honmoon-${VERSION}-aarch64-apple-darwin.tar.gz" \
  | tar -xz honmoon
sudo install -m 755 honmoon /usr/local/bin/honmoon
```

Every release also ships a `SHA256SUMS` covering all three archives. To verify a download
before unpacking it, fetch the archive and `SHA256SUMS` into the same directory, then run
`sha256sum --ignore-missing -c SHA256SUMS` on Linux, or
`shasum -a 256 --ignore-missing -c SHA256SUMS` on macOS.

**Build from source** — see [Development](#development) below. Cutting a release is
documented in [`docs/releasing.md`](./docs/releasing.md).

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

Honmoon's open-source core is licensed under the [Apache License 2.0](./LICENSE).
Enterprise components under `packages/enterprise/` (planned for Phase 7) will be
separately licensed under the BSL or FSL, as described in the
[open-core business model](./docs/business-model.md).
