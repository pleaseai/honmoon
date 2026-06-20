# ADR-0001: Adopt Pingora for the HTTP/HTTPS data plane

## Status

Accepted

## Context

Honmoon's data plane (`crates/honmoon-proxy`) needs to act as an egress proxy for AI agents:
terminate or tunnel agent connections, extract request facts, evaluate them against a policy,
and allow / deny / hold each request. The first MVP targets **HTTP/HTTPS egress filtering**
via an explicit forward proxy (agents set `https_proxy`), mirroring gh-aw-firewall's Squid
approach but in Rust.

We can either hand-roll this on raw `tokio` + `hyper`/`h2`, or build on an existing Rust proxy
framework. Hand-rolling means owning connection pooling, HTTP/1.1 + HTTP/2 handling, TLS,
graceful reloads, and observability — significant, security-sensitive plumbing.

[Pingora](https://github.com/cloudflare/pingora) is Cloudflare's open-source (Apache-2.0) Rust
proxy framework that powers their production proxy fleet (it replaced nginx). It is `tokio`-based
and provides exactly the seams we need.

## Decision

Adopt **Pingora** as the framework for Honmoon's HTTP/HTTPS data plane, inside
`crates/honmoon-proxy` and wired up by `crates/honmoon-cli` (gateway mode).

- Use Pingora's `ProxyHttp` trait. Policy evaluation runs in **`request_filter`**:
  `honmoon-proxy` builds `Facts`, calls `honmoon_core` evaluation, and returns a verdict —
  `deny` → 4xx, `pause` → hold for approval, `allow` → continue.
- Enable forward-proxy mode via `HttpServerOptions.allow_connect_method_proxying = true` so
  agents using `https_proxy` are handled through HTTP `CONNECT` tunneling. (Disabled by default
  in Pingora ≥0.8.0 for safety; we opt in.)
- Use `upstream_peer` for destination selection and `response_filter` / `logging` for audit.
- Rely on Pingora for connection pooling, HTTP/2, graceful zero-downtime reload (→ policy
  hot-reload), and observability.

**Scope boundary**: Pingora is used only for HTTP(S). It is **not** used for SQL/Kubernetes
wire-level protocol parsing (Pingora's `ProxyHttp` is L7 HTTP-only); those stay on raw `tokio`.
Pingora must not leak into `honmoon-core`, which remains transport-agnostic.

## Consequences

### Positive

- We inherit a battle-tested, production-grade proxy core instead of building it.
- `request_filter` is a clean, well-defined seam for policy enforcement.
- Native HTTP `CONNECT` forward-proxy support matches the egress scenario directly.
- Graceful reload enables policy hot-reload without dropping connections.
- Apache-2.0 license is compatible with our open-core data-plane stance.

### Negative

- Heavier dependency tree and a framework-shaped API to learn.
- Pingora is HTTP-centric; non-HTTP protocol awareness (SQL/K8s) gains nothing from it and
  must be built separately on raw `tokio` (or Pingora's lower-level L4 connectors).
- **TLS backend**: Pingora selects one TLS backend at compile time. Its `rustls` backend
  (added 0.4.0) is **experimental**; the stable backends are OpenSSL / BoringSSL. This
  conflicts with the prior `tech-stack.md` note that assumed `rustls`. Decision: start on
  **BoringSSL** (Pingora's well-trodden default) and revisit `rustls` as it matures. Revisit
  if BoringSSL build/distribution friction outweighs the benefit.

### Neutral

- `tech-stack.md` and `ARCHITECTURE.md` are updated to list Pingora as a `honmoon-proxy`
  dependency and to reflect the BoringSSL TLS backend.
- HTTPS body inspection (for body-based HTTP rules) still requires TLS MITM / cert generation,
  which is out of scope for the CONNECT-tunnel MVP (domain/SNI-level filtering only).

## Alternatives Considered

- **Hand-rolled `tokio` + `hyper`/`h2`**: maximum control and a lighter dependency, but we would
  reimplement connection pooling, HTTP/2, graceful reload, and TLS — security-sensitive surface
  better delegated to a proven framework.
- **`pingora` for everything incl. SQL/K8s relay via L4 connectors**: possible, but the
  `ProxyHttp` hooks (the main value) don't apply to non-HTTP protocols, so there is little gain
  over raw `tokio` for those.
- **Squid (as in gh-aw-firewall)**: kept as an *optional* external HTTP egress backend, not the
  core. A Rust data plane gives us protocol-aware policy (the moat) that Squid cannot.

---

_Date: 2026-06-20_
_Related: `ARCHITECTURE.md` (data plane), `.please/docs/knowledge/tech-stack.md`_
