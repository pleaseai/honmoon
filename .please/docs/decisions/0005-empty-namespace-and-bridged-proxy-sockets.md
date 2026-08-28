# ADR-0005: Confine `honmoon run` with an empty namespace and bridged proxy sockets

## Status

Accepted. **Supersedes [ADR-0004](0004-unprivileged-userns-tun-for-honmoon-run.md)**, which chose a
TUN device driven by a userspace TCP/IP stack. That mechanism is more code, more dependencies, and
weaker enforcement than the one adopted here.

## Context

Two problems were being worked separately and turn out to have one answer.

**TD-003 / #36** — `honmoon run` sets `http_proxy` and hopes. A child that ignores it is never
evaluated.

**TD-006 / #39** — the PostgreSQL and Kubernetes parsers in `honmoon-core::protocols` have no live
data source. `honmoon-proxy::gateway` speaks HTTP `CONNECT` and nothing else, and `psql` does not
speak `CONNECT`, so no PostgreSQL connection can reach the PostgreSQL parser under any
configuration of the current data plane.

ADR-0004 answered the first by building a network for the child (TUN inside a namespace, userspace
stack outside, `tun2proxy` forwarding TCP to the CONNECT proxy) and left the second open, noting
that a proxy-shaped transport caps `run` at TCP-over-CONNECT.

### What `anthropic-experimental/sandbox-runtime` does instead

`srt` (Apache-2.0, the sandbox behind Claude Code) enforces the same property with less machinery.
Read from `src/sandbox/linux-sandbox-utils.ts:583-601`:

> Linux network sandboxing uses `bwrap --unshare-net` which creates a completely isolated
> [namespace] … Host side: Run socat bridges that listen on Unix sockets and forward to host proxy
> servers … Sandbox side: Bind the Unix sockets into the isolated namespace and run socat listeners
> — HTTP listener on port 3128 → HTTP Unix socket → host HTTP proxy; SOCKS listener on port 1080 →
> SOCKS Unix socket → host SOCKS5 proxy.

The namespace is not given a network. It is given **no network at all**, plus a Unix socket on its
filesystem that bridges to proxies on the host. There is no TUN, no userspace TCP/IP stack, no
routing table to get right, and no DNS to intercept — a child that ignores the proxy environment
does not escape, it simply reaches nothing. Their own comment states the honest boundary: "Linux's
`--unshare-net` provides only all-or-nothing network isolation. Domain filtering happens at the
host proxy level, not the sandbox boundary." That is exactly honmoon's shape, because honmoon *is*
the host proxy doing the filtering.

macOS gets the same property from a different primitive: "The Seatbelt profile allows communication
only to a specific localhost port. The proxies listen on this port." `sandbox-exec` ships with the
OS. No system extension, no entitlement, no signing, no notarization, no app bundle.

And the second proxy is the answer to #39. `srt` runs **an HTTP proxy and a SOCKS5 proxy**, because
HTTP proxying cannot carry `ssh` or `git+ssh`. SOCKS5 carries arbitrary TCP *and the client
declares the destination host and port in the handshake* — which is precisely the "which endpoint
is this flow for?" signal that clawpatrol reconstructs at L3 with destination-IP indexes and DNS
virtual IPs. At L3 you must infer the intended service. Over SOCKS5 the client tells you.

## Decision

**Confine the child by removing its network, and expose honmoon's proxies through a bridge the
namespace can reach.**

1. **Linux**: spawn the child into new user + network + mount namespaces. The network namespace is
   left empty apart from loopback. A honmoon-owned listener inside the namespace bridges to the
   proxies over a Unix socket; the child's proxy environment points at it.
2. **macOS**: generate a Seatbelt profile permitting outbound network only to the proxy's localhost
   port, and spawn the child under `sandbox-exec`.
3. **Add a SOCKS5 listener to `honmoon-proxy`** beside the existing CONNECT proxy. It is the
   transport for every non-HTTP protocol, and its handshake carries the destination host:port that
   selects the endpoint and its protocol runtime — no destination-IP index, no DNS interception, no
   VIP allocation.
4. **Protocol runtime stays separate from transport.** A runtime receives a connection whose
   intended endpoint is already known, parses frames into `Facts`, calls `decide()`, and forwards,
   closes, or holds for approval. SOCKS5 is the first dispatch source; an L3 dispatch can be added
   for `join` (#37) later without touching the runtimes.

Adopt the *technique*, not the package: `srt` is TypeScript and needs `bubblewrap` and Node, while
`honmoon run` is a single Rust binary. Honmoon performs the namespace and Seatbelt work itself and
bridges in-process rather than shelling out to `socat`. `srt` is Apache-2.0, so its profile
generation is available to study and port with attribution.

## Consequences

- Substantially less code than ADR-0004: no TUN, no `tun2proxy`, no userspace TCP/IP stack, no
  route or DNS configuration inside the namespace. The dependency list is `nix`-level syscalls.
- **Stronger**, not merely simpler. ADR-0004 built a working network and relied on it having one
  exit. Here there is no network to reason about, so the failure mode is a child that cannot
  connect rather than a child that found another route.
- **macOS stops being expensive.** #69 was scoped as a Swift `NETransparentProxyProvider` in a
  signed, notarized app bundle, and it dragged the release workflow (#63) from "ship a binary" to
  "ship a signed app". Seatbelt removes all of that. #69 should be rewritten, not merely re-scoped.
  Caveat: `sandbox-exec` is formally deprecated by Apple and emits a warning, though Claude Code
  ships on it today.
- **#39 gets a transport that exists.** A SOCKS5 listener is ordinary async Rust, testable
  hermetically over loopback with no namespace and no privileges — so the PostgreSQL runtime can be
  built and tested on macOS before any isolation work lands.
- Compatibility becomes the visible cost, and it is a real one. Inside the sandbox a client that
  honors neither `HTTP_PROXY` nor `ALL_PROXY` **fails closed**: it reaches nothing. `psql` does not
  speak SOCKS5 natively. This is the correct default for a firewall, but it will surface as
  "honmoon broke my tool", and needs to be documented as a deliberate choice rather than discovered.
- The all-or-nothing boundary means every allow/deny decision happens in honmoon's proxies, never
  at the sandbox edge. A bug that makes a proxy fail open is a total bypass, so the proxies carry
  the whole weight.
- The ADR-0004 limits still hold and are not restated here: this is best-effort confinement of an
  **unprivileged** child. Root, `CAP_SYS_ADMIN`, or passwordless `sudo` defeats it, and confining
  egress does nothing about data the child already reads.
