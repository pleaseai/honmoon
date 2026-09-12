---
name: mitm-tunnel-authorization-model
description: How honmoon-proxy mitm.rs decides a request is an already-authorized tunnel inner request (shape 3) — recognition rides the hudsucker handler clone lineage, and host+port are both load-bearing for h2
metadata:
  type: project
---

Shape-3 recognition in `crates/honmoon-proxy/src/mitm.rs` rides the **hudsucker handler
clone lineage**, not a shared registry: `HonmoonHandler.tunnel: Option<AuthorizedTunnel>`
is set by `authorize_tunnel` only on the per-request clone that handled an allowed
CONNECT, and read by `tunnel_authorizes(host, port)`. The registry keyed by client
`SocketAddr` (`TunnelRegistry`) was removed in the #100 fix (PR #111).

**Why:** the old registry never evicted entries, so a later connection reusing the source
port inherited a dead tunnel's authorization and skipped the egress host gate.

**How to apply** when reviewing anything touching `handle_request`:
- The lineage that makes this work is hudsucker 0.24.1 internals, verified in
  `~/.cargo/registry/src/*/hudsucker-0.24.1/src/proxy/`: `mod.rs` builds a fresh
  `InternalProxy` (fresh handler clone) *per request*; `internal.rs::proxy(mut self, req)`
  calls `handle_request` on `&mut self.http_handler` and then moves that same `self` into
  `process_connect`, whose spawned task serves every inner request via
  `serve_stream`'s `self.clone().proxy(req)`. The dependency is a caret `hudsucker = "0.24"`
  with no compile-time guard — re-verify these two files on any hudsucker bump.
- Losing the `tunnel` only re-gates a request (fail-safe). Only *sharing* it across
  connections/streams is fail-open.
- Both host **and** port must be compared. HTTP/1.x inner requests get their authority
  overwritten with the CONNECT authority by `serve_stream`, but **h2 inner requests keep
  the client's `:authority`**, and hudsucker re-issues every request at the request URI
  (it does not pipe bytes down the tunnel) — so an h2 `:authority`/port mismatch must fall
  through to `host_gate`, or a tunnel to `:443` lends its authorization to `:6443`.

Related: [[detect-mode-pii-attribution]]
