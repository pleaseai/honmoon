# ADR-0002: Phase 1 CONNECT egress proxy on raw tokio; defer Pingora

## Status

Accepted

(Supersedes the implementation choice in [ADR-0001](0001-adopt-pingora-http-data-plane.md). The
TLS-terminating framework this ADR deferred is chosen in
[ADR-0003](0003-adopt-hudsucker-for-tls-termination.md): hudsucker, not Pingora.)

## Context

ADR-0001 chose Pingora for the HTTP/HTTPS egress data plane, on the premise (from
documentation/Q&A) that Pingora's `allow_connect_method_proxying` makes it a
terminating HTTP `CONNECT` forward proxy suitable for agent egress.

While implementing Phase 1 we verified this against the actual Pingora 0.8.1 source and a
working prototype, and found:

- Pingora's `HttpProxy` is **reverse-proxy oriented**. Its downstream HTTP/1 parser rejects
  absolute-form request targets (plain-HTTP forward proxying) as `InvalidHTTPHeader`.
- `allow_connect_method_proxying` enables **forwarding a CONNECT to an upstream proxy
  (proxy chaining)**, not terminating the CONNECT and opening a raw TCP tunnel to an
  arbitrary target. Our prototype produced `Downstream InvalidHTTPHeader: invalid uri
  host:port` for exactly the egress case we need.
- A terminating CONNECT forward proxy (read `CONNECT host:port`, reply `200`, then shuffle
  bytes) is a small, well-understood piece — and at the host/SNI level it needs no HTTP
  request modeling at all.

The Pingora value (request hooks, caching, HTTP/2, graceful reload) materializes when we
**terminate TLS and inspect HTTP** (method/path/body rules) — which Phase 1 does not do.

## Decision

For **Phase 1** (host-level egress allowlist over HTTPS), implement a terminating
`CONNECT` forward proxy **directly on tokio** in `honmoon-proxy::gateway`:

1. Read the `CONNECT host:port` request head.
2. Evaluate the target host against the [`Policy`] via `evaluate()`.
3. `Allow` → reply `200 Connection Established` and `tokio::io::copy_bidirectional`; otherwise
   reply `403`. Non-CONNECT methods get `405`.

**Defer Pingora** (and its dependency) to the phase that terminates TLS and inspects HTTP
requests (roadmap Phase 2+, where MITM / request-level facts are introduced). Re-introduce
the `pingora` dependency then, not before (YAGNI).

## Consequences

### Positive

- Phase 1 ships a correct, hermetic, dependency-light egress proxy (~130 LOC, no C/TLS build).
- Full control over the CONNECT tunnel semantics; trivially unit/integration testable on loopback.
- Avoids carrying a heavy framework dependency before any feature uses it.

### Negative

- We will revisit framework choice at the HTTP-inspection phase; Pingora is not yet proven
  in-tree for that use case either (only its forward-proxy premise was disproven).
- Two potential code paths long-term (tokio tunnel for CONNECT pass-through, framework for
  inspected HTTP). Acceptable: they serve different policy depths.

### Neutral

- `ARCHITECTURE.md` and `tech-stack.md` updated: `honmoon-proxy` depends on `tokio` (no
  `pingora`) for now; Pingora is listed as a deferred/Phase 2 candidate.

## Alternatives Considered

- **Force Pingora into a terminating CONNECT proxy**: would require hijacking the session's
  raw stream outside the `ProxyHttp` happy path — undocumented, fragile, and no payoff at the
  host-allowlist level.
- **Keep Pingora dependency now, use tokio for the tunnel**: carries a heavy unused dependency
  (build time, supply-chain surface) against YAGNI.

---

_Date: 2026-06-20_
_Related: [ADR-0001](0001-adopt-pingora-http-data-plane.md), `crates/honmoon-proxy/src/gateway.rs`, `docs/roadmap.md`_
