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
| **Policy check** | `honmoon policy validate <file>` | Load a policy the way the gateway does and exit — no listener, no files written |

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
#
# The management API requires a bearer token on every /api route. With no
# --mgmt-token, honmoon mints one at ~/.honmoon/mgmt-token (0600) and prints a
# one-click dashboard login URL on startup:
#   honmoon: dashboard: http://127.0.0.1:8444/login?token=<generated>
# Minting is Unix-only; on Windows set --mgmt-token or HONMOON_MGMT_TOKEN.

# Join a gateway from a client (routes all host traffic)
honmoon join --gateway honmoon.internal:8443

# Check a policy without starting anything: exit 0 if the gateway would load it,
# non-zero with the loader's diagnosis on stderr if it would not (every rule
# whose condition does not compile; the first offender for its other checks).
# Binds no listener and writes nothing — notably it never resolves the
# management token, so unlike `gateway` it cannot create ~/.honmoon/mgmt-token.
honmoon policy validate policies/agent.yaml
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

One further case is *partial* rather than fail-open: in an `application/json` body, PII in an
**unquoted numeric value** is skipped by the rewrite so the output stays valid JSON. The rest of
the body is redacted, that value reaches the upstream verbatim, and a `warn` names how many spans
were skipped. Unlike the header-shaped fields below it was scanned — it counts toward `pii.count`,
it is audited, and `--pii-mode block` can deny on it.

A further case is *quiet*: the redaction floor is MEDIUM (`DEFAULT_MIN_PII_SEVERITY`), so a finding
below it — a bare IPv4 address is the standing example — is detected and deliberately left in
place. When it is a body's only finding, nothing is rewritten and **no redaction `warn` is
logged**, because nothing failed. Lower the floor if you want those redacted.

**Those are the cases where honmoon tries to rewrite and cannot, or chooses not to. They are not
the only way content reaches the upstream unredacted, and this list does not claim to be
exhaustive.** Inspection covers request **bodies** only: header and
trailer values are never scanned for PII or secrets and never redacted — including a secret placed
in a chunked trailer (`Trailer: X-Note` followed by `0\r\nX-Note: <secret>`). Unlike the *loud*
redaction cases above, no `warn` is logged about their contents: header-shaped fields were never in
scope, so there is nothing to fail — the scan is not failing open, it never applied. Two of those
warns are triggered by a header — `Content-Range`'s presence, an unparseable
`Content-Encoding` — but each reports a skipped *body* rewrite, not an unscanned header value.

**`pii.count` stays `0`, and that cuts both ways.** No rule that requires a *positive* finding can
fire on trailer content — `pii.count > 0`, or a `pii.types` match — so such a rule never denies,
pauses, or audits it. But the engine always binds `pii` with its empty default precisely so that
absence conditions work, so an **absence** rule does fire, and treats the request as clean: a
`pii.count == 0 -> allow` rule allows a request whose trailer carries a secret, and a matching
`deny`/`pause` records an audit like any other verdict. Write content rules against positive
findings, and do not read `pii.count == 0` as "no secrets in this request".

Whether a trailer then *reaches* the upstream is a separate question, and not one this contract
answers. On a pass-through request it is replayed, subject to its *name* and to framing. On framing,
honmoon now does the work rather than leaving it to the upstream leg: HTTP/1.1 carries a trailer
section only under chunked framing and only for the fields a `Trailer` header names, and HTTP/2
requires neither, so honmoon writes `Transfer-Encoding: chunked` and a `Trailer` header naming the
surviving fields (issue #136). hyper reconciles the two per-protocol — an HTTP/1.1 leg drops the
`Content-Length`, an HTTP/2 leg drops the `Transfer-Encoding` — so honmoon does not need to know
which one it will get. Limits — in each of these the **re-frame** is skipped and the request still
goes forward exactly as the client framed it, losing the trailer section rather than the request
(fail open, not the `403` the signed-body path returns): the re-frame is skipped when the request's
signature covers one of
those headers *that this re-frame would actually touch* — `Content-Length` and `Transfer-Encoding`
only when the request is not already chunked, `Trailer` only when a field is undeclared — since
re-framing would then break the signature the request was forwarded to preserve (a `warn` names the
covered headers and the trailers that will therefore be lost); it is skipped again when the
request carries a `Content-Length` hyper cannot resolve to a single length, because the HTTP/1.1
leg only drops a length it could parse and honmoon would otherwise be the one putting both
framings on one wire; and it
needs the trailer field names, which honmoon only holds for a body it buffered, so an over-cap body
still depends on the client's own framing (issue #177). On names, honmoon refuses to forward a trailer whose
field name could change how the recipient **frames, routes, or authenticates** the request — the
hazard RFC 9110 §6.5.1 describes, and which RFC 7230 §4.1.2 stated outright: a recipient must
ignore such a field, "since processing them as if they were present in the header section might
bypass external security filters". Concretely: `Transfer-Encoding`, `Content-Length`, `Host`,
`Authorization`, `Proxy-Authorization`, `WWW-Authenticate`, `Proxy-Authenticate`, `Cookie`,
`Set-Cookie`, `Content-Encoding`, `Content-Type`, `Content-Range`, `Trailer`, `Cache-Control`,
`Max-Forwards`, `TE`, plus the connection-specific names RFC 9113 §8.2.2 bars from an HTTP/2
message (`Connection`, `Keep-Alive`, `Proxy-Connection`, `Upgrade`) and any field the request's own
`Connection` header nominates. Each drop logs a `warn` naming the fields and the destination.

Conditionals (`If-*`), `Range`, `Expect`, `Pragma` and the `Accept*` family are **not** dropped,
though a trailer section may not carry them either: they change what the recipient returns, not how
it frames, routes or authorizes, so refusing them would buy no security while widening honmoon's
interference with byte fidelity. This is a decision about names, never about values — nothing in it
inspects what a trailer carries. It applies on every request-forwarding path and regardless of the
upstream protocol, so a client cannot launder a framing token past honmoon by having the upstream
leg negotiate HTTP/2 (issue #134). Response trailers are not filtered. When redaction rewrites the body, the replacement carries no
trailer frame and the client's trailers are dropped instead (deliberately: a digest over the
original bytes is stale either way; the stale `Trailer:` header that drop leaves behind is
issue #135). The same rewrite strips the body-digest headers (`Digest`, `Content-Digest`,
`Content-MD5`, `Repr-Digest`) and re-frames `Content-Length`/`Content-Encoding`/
`Transfer-Encoding`, and carries the client's other headers through — with one exception that is
not the rewrite's: whenever `--redact-secrets` is on, the proxy replaces `Accept-Encoding` with
`identity` on every forwarded request, unless the request's authentication signs headers or binds
the body (the detokenization note above). **None of those cases scans a header or trailer value** —
which is the only part this contract covers. The rewrite is of course *driven* by body inspection;
what never happens is a detector running over a header or a trailer.

This whole section is about **intercepted** requests. Traffic that takes the raw tunnel — SOCKS5
to a non-PostgreSQL destination, or CONNECT without `--tls-intercept` — is gated on `domain` and
inspected not at all, bodies included (see "SOCKS5 and inline PostgreSQL inspection" above).

**There is no content-level lever for this surface.** `egress.default: deny` narrows *which hosts*
an agent can reach and is worth keeping, but it scans nothing: an allow-listed destination — the
API the agent exists to call — still receives header and trailer content unexamined, which is
where an exfiltration attempt would send it. Treat header-shaped fields as uncontrolled rather
than as covered by the body scan. See
[ADR-0009](.please/docs/decisions/0009-body-only-inspection-contract.md).

**Signed requests are the exception that fails closed when redaction would change what the
signature covers.** When a request's authentication covers its payload — AWS SigV4 whose canonical
request hashed the payload, RFC 9421 message signatures or draft-cavage signatures over a body
digest — honmoon holds no signing credentials and cannot re-sign the rewritten body, so the
upstream would reject it with an opaque signature error. The same applies when the signature
covers a header that replacing the payload has to change: the rewrite re-frames `Content-Length`,
drops `Content-Encoding`/`Transfer-Encoding`, and strips the stale body digests
(`Content-MD5`, `Digest`, `Content-Digest`, `Repr-Digest`). An AWS SDK upload lists
`content-length` in `SignedHeaders` even when `UNSIGNED-PAYLOAD` leaves the body itself redactable,
and an S3 upload may list `content-md5` the same way. By default such a request is refused locally with `403`, an `X-Honmoon-Reason:
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
`x-amz-content-sha256: UNSIGNED-PAYLOAD` and whose `SignedHeaders` list leaves alone every header
the rewrite would change. A presigned URL is in the same group unless it also declares a *signed* payload — a real
SHA-256, or a `STREAMING-AWS4-…` per-chunk marker, in the `x-amz-content-sha256` header (or, when it
sends none, in the `X-Amz-Content-Sha256` query parameter presigning hoists that header into): on
its own its signature covers the request and the headers it names, not the uploaded bytes. So is a
bare payload hash with no AWS authentication on the request — that is an integrity check, not a
signature. The covered list is parsed rather than assumed, and only headers the rewrite would actually
change count. A signed request with nothing to redact is forwarded with its body unchanged and its
headers unchanged **except** for the two framing decisions that are not the rewrite's, both
described in the trailer paragraph above and both applied before any of this is consulted: a
trailer whose field name a trailer section must not carry is dropped by the #134 filter
(`Content-Digest` is not on that list), and a request carrying a trailer section gains the
`Transfer-Encoding: chunked` and `Trailer` headers an HTTP/1.1 leg needs to carry it — which is
what lets a signed `Content-Digest` trailer survive that leg, and which is skipped for exactly the
requests whose signature covers those headers. See [ADR-0006](.please/docs/decisions/0006-signed-body-requests-under-wire-redaction.md).

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
