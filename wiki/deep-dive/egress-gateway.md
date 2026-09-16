---
title: Egress Gateway (Data Plane)
description: The hudsucker egress proxy — the host gate, TLS termination, audit recording, and the pause approval hold.
---

# Egress Gateway (Data Plane)

The egress gateway is the part of Honmoon that owns the agent's egress socket. An agent points
`https_proxy` at it, and only policy-allowed hosts are reachable. Since **Phase 5** it runs on
[hudsucker](https://github.com/omjadas/hudsucker), a MITM HTTP/S proxy library, rather than the
hand-rolled tokio `CONNECT` proxy of Phase 1 ([ADR-0003](https://github.com/pleaseai/honmoon/blob/main/.please/docs/decisions/0003-adopt-hudsucker-for-tls-termination.md)).

That split is the thing to hold on to when reading the code. **hudsucker owns the connection
lifecycle** — the accept loop, head parsing, the `CONNECT` upgrade, TLS termination, and the
upstream leg. **Honmoon owns the decisions**, supplied as an `HttpHandler`
([gateway.rs:251-278](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/gateway.rs#L251-L278), [mitm.rs:927-1046](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L927-L1046)).
So `gateway.rs` holds the shared state and the four entry points, and every per-request decision —
the host gate, the body scan, the approval hold — lives in `mitm.rs`.

The gateway records its refusals and its holds to the audit log, and a `pause` verdict holds the
request pending human approval ([mitm.rs:296-336](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L296-L336), [approval.rs:235-260](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/approval.rs#L235-L260)). It does **not**
record every allow. The `CONNECT` that opens a connection is logged, and so is a request whose body
scan found PII, but an ordinary forwarded request is deliberately quiet: recording each one would
flood the bounded audit ring and cycle out the refusals that matter
([mitm.rs:853-867](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L853-L867)).

::: tip This is not the only egress path
A `CONNECT` proxy carries HTTP and TLS. A PostgreSQL or Redis client speaks neither, so a **SOCKS5
listener** runs beside this one and puts an ordinary destination through the same allow / deny /
pause gate ([socks.rs:1-29](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/socks.rs#L1-L29)). Two differences are worth carrying
across. It gates on `Facts{domain, endpoint}` and no `http.host`, because a SOCKS5 handshake
states a host and a port and nothing else ([socks.rs:351-358](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/socks.rs#L351-L358)) — so an
`http.host` rule that holds over a raw tunnel here does not fire there. And the
uninspectable-endpoint refusal is the mirror of this listener's: a `kubernetes` endpoint is refused
there, a `postgres` one here. That refusal runs *before* the gate on both, so such a destination
never reaches allow / deny / pause at all — a `pause` on it is recorded as a refusal keeping the
rule that matched, and is never held for an approval nobody could act on
([socks.rs:175-178](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/socks.rs#L175-L178), [socks.rs:419-456](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/socks.rs#L419-L456)).
`honmoon run` always starts it; `honmoon gateway` does too unless `--socks-addr off` declines it.
See [Quick Start](/getting-started/quick-start).
:::

## At a glance

`honmoon-proxy::gateway` — shared state and the entry points:

| Element | Role | Source |
|---------|------|--------|
| `GatewayState` | Shared `Arc`s: policy + `AuditLog` + `ApprovalRegistry` + CA + pause timeout + intercept/PII/redaction settings | [gateway.rs:154-174](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/gateway.rs#L154-L174) |
| `InterceptPolicy` | Which tunnels to TLS-terminate: `None` (the default), `All`, or a host set | [gateway.rs:76-90](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/gateway.rs#L76-L90) |
| `PiiMode` | Whether body PII findings only inform audit (`Detect`) or enforce the verdict (`Block`) | [gateway.rs:92-100](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/gateway.rs#L92-L100) |
| `RedactionState` | Wire-level secret redaction: HMAC salt, placeholder store, signed-body policy | [gateway.rs:117-132](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/gateway.rs#L117-L132) |
| `run(policy, addr)` | Bind `addr`, serve forever | [gateway.rs:194-198](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/gateway.rs#L194-L198) |
| `serve_listener(policy, listener)` | Serve a pre-bound listener (no TOCTOU) | [gateway.rs:200-207](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/gateway.rs#L200-L207) |
| `serve_listener_with_state` | The same, with caller-provided shared state | [gateway.rs:209-214](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/gateway.rs#L209-L214) |
| `serve(state, listener)` | Build the hudsucker `Proxy` around `HonmoonHandler` and start it | [gateway.rs:251-278](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/gateway.rs#L251-L278) |
| `host_of` / `authority_port` / `canonical_host` | Authority parsing and host canonicalization | [gateway.rs:280-310](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/gateway.rs#L280-L310) |

`honmoon-proxy::mitm` — the request path. This is where the Phase 1 control logic was **ported**,
not rewritten ([ADR-0003:42-64](https://github.com/pleaseai/honmoon/blob/main/.please/docs/decisions/0003-adopt-hudsucker-for-tls-termination.md#L42-L64)):

| Element | Role | Source |
|---------|------|--------|
| `HonmoonHandler` | The `HttpHandler` hudsucker drives; cloned per connection and per request | [mitm.rs:160-172](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L160-L172) |
| `handle_request` | Every request, in all three shapes: `CONNECT`, cleartext, decrypted inner | [mitm.rs:928-973](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L928-L973) |
| `host_gate` | Decide + audit; routes `pause` to the hold. The old `authorize` | [mitm.rs:296-336](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L296-L336) |
| `hold` | Render the hold's outcome as `Gate::Proceed` / `403` / `503`. The old `hold_for_approval` | [mitm.rs:338-363](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L338-L363) |
| `AuthorizedTunnel` | What this handler clone's connection earned at its `CONNECT` | [mitm.rs:71-91](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L71-L91) |
| `uninspectable_endpoint` / `refuse_uninspectable_connect` | Refuse a `CONNECT` to an endpoint this listener could only tunnel uninspected | [mitm.rs:217-294](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L217-L294) |
| `inspect_body` | Buffer, decode, scan for PII, decide, forward or block | [mitm.rs:614-924](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L614-L924) |
| `handle_response` | Restore known placeholders in identity-encoded responses | [mitm.rs:975-1034](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L975-L1034) |
| `should_intercept` | Apply `InterceptPolicy` to one tunnel | [mitm.rs:1036-1045](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L1036-L1045) |
| `status_response` | The empty `Content-Length: 0`, `Connection: close` refusal — what the host gate, a content `deny` and a full approval queue return | [mitm.rs:1601-1610](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L1601-L1610) |
| The reason-carrying refusals | A refusal the operator can act on carries a `text/plain` explanation and an `x-honmoon-reason` header instead of an empty body, and names the flag to change | [mitm.rs:65](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L65), [mitm.rs:1240-1261](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L1240-L1261), [mitm.rs:1551-1599](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L1551-L1599) |

::: warning Names that moved
Anything you read elsewhere about `gateway::handle`, `gateway::authorize`,
`gateway::hold_for_approval` or `gateway::read_head` is describing the Phase 1 proxy. `handle` has
no successor by that name — the per-request entry point is `HonmoonHandler::handle_request`;
`authorize` is now `host_gate`; `hold_for_approval` is now `hold` over
[approval.rs:235-260](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/approval.rs#L235-L260); and `read_head` is gone
entirely, because hudsucker parses the head.
:::

## How the data plane got here

The original plan ([ADR-0001](https://github.com/pleaseai/honmoon/blob/main/.please/docs/decisions/0001-adopt-pingora-http-data-plane.md))
was Cloudflare's Pingora. During Phase 1 that premise was tested against Pingora 0.8.1 and
**disproven** for this use case
([ADR-0002](https://github.com/pleaseai/honmoon/blob/main/.please/docs/decisions/0002-phase1-connect-proxy-on-tokio.md)):

| Finding | Consequence |
|---------|-------------|
| Pingora's `HttpProxy` is reverse-proxy oriented; rejects absolute-form targets | Not a forward proxy |
| `allow_connect_method_proxying` does proxy **chaining**, not terminating tunnels | Wrong CONNECT semantics |
| A terminating CONNECT proxy at host/SNI level needs no HTTP modeling | ~130 LOC suffices |

Phase 1 therefore shipped on raw tokio and **deferred** the framework question to the phase that
terminates TLS and inspects HTTP requests (YAGNI)
([ADR-0002:33-45](https://github.com/pleaseai/honmoon/blob/main/.please/docs/decisions/0002-phase1-connect-proxy-on-tokio.md#L33-L45)).

Phase 5 is that phase, and it answered with **hudsucker** rather than Pingora: hudsucker already
ships and tests the security-critical parts — CA management, per-host leaf caching, the TLS
acceptor, HTTP/2, selective bypass — and its `HttpHandler` maps onto Honmoon's policy engine
directly ([ADR-0003:42-64](https://github.com/pleaseai/honmoon/blob/main/.please/docs/decisions/0003-adopt-hudsucker-for-tls-termination.md#L42-L64)).
The hand-rolled accept loop, head reader and tunnel copy went with it.

## Request handling

`serve` hands hudsucker a bound listener, a CA authority, one `HonmoonHandler` and a server
builder, then starts the proxy; the accept loop and the task-per-connection are hudsucker's
([gateway.rs:251-278](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/gateway.rs#L251-L278)). Every request reaches
`handle_request`, in one of three shapes
([mitm.rs:1-36](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L1-L36)):

1. **The `CONNECT` request** — host-level policy runs here, for every tunnel, intercepted or not.
2. **Cleartext `http://` forward-proxy requests** — host-gated too, so the allowlist cannot be
   bypassed by skipping `CONNECT`. Bodies are scanned as well.
3. **Decrypted inner requests** over a terminated tunnel — already authorized at the `CONNECT`, so
   only the body is inspected.

The PII scanner on shapes 2 and 3 is not given every body. **Size**: buffering stops at
`MAX_INSPECT_BODY` — 2 MiB, whether declared by `Content-Length`, discovered while reading, or
reached by decompression — and a body past it is forwarded unscanned rather than buffered
([body.rs:56-61](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/body.rs#L56-L61)). **Text**: `detect_spans` is given only what decodes as UTF-8,
so a body carrying an interior non-UTF-8 byte is left unscanned as well; only a *trailing* truncated
sequence is tolerated, and there it is the valid prefix that gets scanned
([mitm.rs:761-763](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L761-L763), [body.rs:163-169](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/body.rs#L163-L169)).

An unscanned body is not an ungoverned request — and it is not a *clean* one either. A
**positive-finding** condition cannot be satisfied on it: the summary is absent, so `pii.count > 0`
and a `pii.types` match never hold. An **absence** condition still matches, because the engine
always binds `pii` with its empty default, so `pii.count == 0 -> allow` reads an unscanned body as
clean — the stated contract, not an oversight
([engine.rs:422-425](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/engine.rs#L422-L425), [mitm.rs:624-629](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L624-L629)). The rest of
the policy is untouched either way: `decide_explained` still runs on the request's other facts, and
a `domain`, `endpoint`, `k8s.*` or `http.*` rule (method, path, `body_size`) still denies or pauses
it ([mitm.rs:773-793](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L773-L793)).

One of those facts is weaker than it looks, and a size threshold is the rule most likely to be
written against an unscanned body. `http.body_size` is the declared `Content-Length` when an
over-cap body declared one — so `http.body_size > 2097152` does deny there — but a body that
overflowed the cap *while being read* never had its size learned, and carries the sentinel `-1`
instead, which no `>` threshold matches ([mitm.rs:693-729](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L693-L729)). A client that
omits `Content-Length` and streams is therefore outside a size rule, not caught by it.

Which shape a request is in is decided by the `AuthorizedTunnel` the handler clone carries — the
connection it arrived on must have made an authorized `CONNECT` to exactly that `host:port` — and
**not** by the URI scheme. A client can send an absolute-form `GET https://…` without `CONNECT`, or
spoof `:authority` over h2, and trusting the scheme would let it skip the gate
([mitm.rs:71-120](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L71-L120), [mitm.rs:928-973](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L928-L973)).

```mermaid
sequenceDiagram
  autonumber
  participant C as Client (agent)
  participant HS as hudsucker
  participant H as HonmoonHandler
  participant Core as decide_explained
  participant Audit as AuditLog
  participant U as Upstream
  C->>HS: TCP connect + request head
  HS->>H: handle_request(req)
  alt method == CONNECT
    H->>H: canonical_host + authority_port
    alt endpoint declares protocol postgres
      H->>Core: decide_explained — the entry still names the rule that matched
      H->>Audit: record(Denied, policy verdict kept)
      H-->>C: 403 — refused, never tunnelled uninspected
    else every other endpoint
      H->>Core: host_gate → Facts{domain, endpoint, http.host}
      alt verdict == Allow
        H->>Audit: record(Allowed)
        H->>H: authorize_tunnel(host, port)
        H-->>HS: forward the CONNECT
        HS-->>C: 200 Connection Established
        HS->>H: should_intercept? → terminate TLS, or tunnel raw
      else verdict == Deny
        H->>Audit: record(Denied)
        H-->>C: 403 Forbidden
      else verdict == Pause
        Note over H,C: held — see the approval hold below
      end
    end
  else any other request
    H->>H: request_host + request_port
    opt not this tunnel's destination
      H->>Core: host_gate → Gate::Block or Gate::Proceed (Allow not audited)
    end
    alt Gate::Block
      H-->>C: 403, or 503 from a full approval queue
    else tunnel authorizes it, or Gate::Proceed
      H->>H: inspect_body — buffer, decode, scan, decide
      H->>H: pii_mode — detect (the default) holds a PII-caused verdict back
      alt enforced verdict == Allow
        H->>U: forward (redacted when --redact-secrets)
      else enforced verdict == Deny
        H->>Audit: record(Denied)
        H-->>C: 403 Forbidden
      else enforced verdict == Pause
        Note over H,C: held — forwarded on approve, 403 on reject or timeout
      end
    end
  end
```
<!-- Sources: crates/honmoon-proxy/src/mitm.rs:928-973 (handle_request), mitm.rs:296-336 (host_gate), mitm.rs:217-294 (the uninspectable-endpoint refusal), mitm.rs:614-924 (inspect_body), mitm.rs:796-815 (the pii_mode filter), mitm.rs:1036-1045 (should_intercept), crates/honmoon-proxy/src/gateway.rs:251-278 (serve) -->

## What the proxy still guards itself

These are honmoon's own, in honmoon's own code:

| Guard | Mechanism | Source |
|-------|-----------|--------|
| Host canonicalization | `GitHub.com:443` / `github.com.` → `github.com`, so a rule can't be bypassed by case or FQDN root | [gateway.rs:305-310](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/gateway.rs#L305-L310) |
| IPv6 authority | `host_of` handles `[::1]:443` | [gateway.rs:280-287](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/gateway.rs#L280-L287) |
| Port confusion | An unbracketed authority with several colons is a bare IPv6 address, not `host:port` — reading `::1` as port 1 would let a client claim any endpoint's port | [gateway.rs:289-303](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/gateway.rs#L289-L303) |
| Spoofed `Host` port | The `Host` header is only consulted when the URI carries no authority of its own | [mitm.rs:1655-1679](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L1655-L1679) |
| Scheme is not authorization | An inner request is recognized by the tunnel the clone inherited, never by `https://` | [mitm.rs:928-973](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L928-L973) |
| Authorization can't outlive its connection | `AuthorizedTunnel` lives on the handler clone, not in a registry keyed by client address | [mitm.rs:71-91](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L71-L91) |
| Body memory | Bodies over 2 MiB — declared or streamed — are forwarded unscanned rather than buffered | [body.rs:56-61](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/body.rs#L56-L61) |
| Uninspectable tunnels | A `CONNECT` to a `protocol: postgres` endpoint is refused, not tunnelled past the `sql.*` rules it exists to enforce | [mitm.rs:217-294](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L217-L294) |
| Bounded approval queue | 1024 simultaneous holds, then fail closed | [approval.rs:64-74](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/approval.rs#L64-L74) |
| No TOCTOU on bind | `serve_listener` adopts a pre-bound socket | [gateway.rs:200-207](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/gateway.rs#L200-L207) |
| Head read | A request head that never completes — and a keep-alive connection idling between heads — is dropped after `HEAD_READ_TIMEOUT` (30s), because hudsucker installs no `Timer` and hyper's own default does not arm without one | [gateway.rs:216-249](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/gateway.rs#L216-L249) |

### Guards the Phase 1 proxy had, and where each stands now

The hand-rolled proxy read the request head itself, under a `HEAD_READ_TIMEOUT` and a
`MAX_REQUEST_HEAD` cap. hudsucker parses the head today, so neither is honmoon's to enforce by
reading bytes — but that did not make both of them hudsucker's either.

- **Slowloris.** <span class="status-done">restored</span> hyper's `header_read_timeout` has a 30s
  default, and it arms only when a `Timer` is installed. Nothing in the dependency chain installs
  one: given no server builder, hudsucker makes its own and sets only `title_case_headers` and
  `preserve_header_case` — the crate calls `.timer(…)` nowhere
  ([hudsucker mod.rs:117-124](https://github.com/omjadas/hudsucker/blob/v0.24.1/src/proxy/mod.rs#L117-L124)); that builder's `http1` half starts
  from `http1::Builder::new()`
  ([hyper-util auto/mod.rs:90-95](https://github.com/hyperium/hyper-util/blob/v0.1.20/src/server/conn/auto/mod.rs#L90-L95)), whose
  `h1_header_read_timeout` is `Dur::Default(Some(30s))`
  ([hyper http1.rs:249](https://github.com/hyperium/hyper/blob/v1.10.1/src/server/conn/http1.rs#L249)); and a `Dur::Default` checked against
  `Time::Empty` warns and returns `None` instead of arming
  ([hyper time.rs:70-78](https://github.com/hyperium/hyper/blob/v1.10.1/src/common/time.rs#L70-L78)). Each link is cited at the version this
  workspace builds (`Cargo.lock`: hudsucker 0.24.1, hyper-util 0.1.20, hyper 1.10.1), because the
  claim crosses two dependencies. That warning is also why nobody noticed: hyper routes it through
  its own `warn!` macro, which compiles to nothing unless hyper's `tracing` feature is on
  ([hyper trace.rs:5-20](https://github.com/hyperium/hyper/blob/v1.10.1/src/trace.rs#L5-L20)), and this workspace does not enable it — so the
  guard failed to arm and said so to no one.

  honmoon now supplies its own server builder, which installs `TokioTimer` and sets
  `header_read_timeout` ([gateway.rs:216-249](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/gateway.rs#L216-L249)). **The bound is hyper's own 30s
  default, and it governs two waits, not one** — hyper re-arms the timer on every head read
  ([hyper conn.rs:219-240](https://github.com/hyperium/hyper/blob/v1.10.1/src/proto/h1/conn.rs#L219-L240)), so a keep-alive connection idling
  between one response and the next request head is bounded by the same constant as a head that
  never completes. Both are the same exposure — a socket that pins a task and a descriptor while
  saying nothing — but the second is why the value is not the 10s Phase 1 and `socks` use: those
  wrap a one-shot handshake future that cannot re-arm, so their bound does not transfer to a client's
  idle-pool budget. Both roles are pinned by tests
  ([egress.rs:200-244](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/tests/egress.rs#L200-L244), [egress.rs:303-358](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/tests/egress.rs#L303-L358)).

  It reaches the inner connection of a **TLS-intercepted** tunnel too: hudsucker clones the builder
  into `InternalProxy` ([hudsucker mod.rs:156-164](https://github.com/omjadas/hudsucker/blob/v0.24.1/src/proxy/mod.rs#L156-L164)) and serves the
  decrypted stream with it ([hudsucker internal.rs:406-410](https://github.com/omjadas/hudsucker/blob/v0.24.1/src/proxy/internal.rs#L406-L410)). A
  tunnel forwarded raw is not bounded — it leaves HTTP/1 at the CONNECT upgrade. A partially-sent
  head is dropped, not answered: hyper writes no `408`, so the Phase 1 status code did not come back
  with the Phase 1 bound.
- **Connections stalled inside the HTTP/2 preface sniff.** <span class="status-caveat">open</span>
  The bound arms only once hyper-util has sniffed the preface and picked a protocol, and that read
  carries no deadline of its own
  ([hyper-util auto/mod.rs:337-372](https://github.com/hyperium/hyper-util/blob/v0.1.20/src/server/conn/auto/mod.rs#L337-L372)). It keeps
  waiting while every byte sent so far matches a prefix of the 24-byte preface and fewer than 24 have
  arrived — sending nothing at all is only the simplest way to sit there, and 22 matching bytes does
  it too. One diverging byte ends the sniff, which is why an ordinary stalled request head *is*
  bounded. Closing this needs a deadline on the accepted stream rather than a server setting, so it
  is tracked separately, in [#272](https://github.com/pleaseai/honmoon/issues/272).
- **Oversized head.** hyper bounds its own header buffer, so this is not unbounded — but the bound
  is hyper's `max_buf_size` default and honmoon neither chooses nor asserts it. The page claims no
  8 KB cap.
- **Tunnel bytes.** honmoon never reads from the client socket, so it cannot consume tunnel bytes;
  hudsucker performs the `CONNECT` upgrade and either terminates TLS or copies bidirectionally.

::: tip What a raw tunnel shows, and what termination adds
Without `--tls-intercept` the proxy sees `host:port` and nothing else, so it populates
`Facts{domain, endpoint, http.host}` only and HTTPS rules stay **host-level**
([mitm.rs:196-215](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L196-L215)). With it, the tunnel is decrypted and
the inner request's method, path, body size and PII findings all reach the engine
([mitm.rs:614-924](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L614-L924)) — see
[Protocol-Aware Parsing](/deep-dive/protocol-parsing).
:::

## Pause, approval & audit

`host_gate` is where the verdict becomes an outcome. It builds the facts, calls `decide_explained`
(verdict + the rule that fired), audits the outcome where the table below says it does, and
dispatches
([mitm.rs:296-336](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L296-L336)):

| Verdict | Audit `Decision` | `Gate` | Source |
|---------|------------------|--------|--------|
| `Allow` | `Allowed` (on the `CONNECT` only) | `Proceed` | [mitm.rs:306-318](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L306-L318) |
| `Deny` | `Denied` | `Block` → `403 Forbidden` | [mitm.rs:319-329](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L319-L329) |
| `Pause` | `Paused` → `Approved`/`Rejected` — except on a full queue, which records `Rejected` alone and never opens a hold | held for the whole wait, then `Proceed` on approval, `Block` → `403` on a rejection or timeout, `Block` → `503` when the queue was full | [mitm.rs:330-334](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L330-L334), [mitm.rs:338-363](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L338-L363) |

**The gate returns a `Gate`, not a status** ([mitm.rs:151-158](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L151-L158)) — so what a *proceeding*
request gets depends on its shape, and only a refusal is a status the gate itself chose. A
`CONNECT` that proceeds is handed back to hudsucker, which answers `200 Connection Established`
and opens the tunnel; a cleartext or absolute-form request that proceeds goes on to `inspect_body`
and, if that forwards it, the client gets the **upstream's** response and no `200` of honmoon's
([mitm.rs:928-973](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L928-L973)). A `pause` on either shape holds the client for the whole
wait before the same split applies.

`Allow` is audited on the `CONNECT` gate but not on individual forwarded requests, which would
flood the bounded audit ring ([mitm.rs:296-301](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L296-L301)).

The hold itself is transport-agnostic and shared with the SOCKS5 data path: `approval::hold`
registers the request, audits `Paused`, and waits on a `oneshot` channel inside an **ordered**
`tokio::select!` ([approval.rs:262-372](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/approval.rs#L262-L372)). Only the HTTP
rendering of the outcome is decided in `mitm.rs`.

```mermaid
stateDiagram-v2
  [*] --> Register: pause verdict
  Register --> QueueFull: registry at capacity (1024)
  Register --> Held: slot acquired, audit Paused
  QueueFull --> [*]: Block, audit Rejected (fail closed) — HTTP 503
  Held --> Approved: human POST /approve
  Held --> Rejected: human POST /reject
  Held --> Timeout: pause_timeout (300s)
  Held --> Abandoned: caller's future dropped (client gone)
  Approved --> [*]: Proceed, audit Approved — a CONNECT gets its 200, a request its own upstream response
  Rejected --> [*]: Block, audit Rejected — HTTP 403
  Timeout --> [*]: Block, audit Rejected (auto-reject) — HTTP 403
  Abandoned --> [*]: CancelOnDrop frees the slot, audit Rejected
  note right of Held: the statuses are the HTTP rendering; SOCKS5 renders the outcomes it receives its own way
```
<!-- Sources: crates/honmoon-proxy/src/approval.rs:262-372 (hold_until), approval.rs:184-218 (CancelOnDrop), approval.rs:96-132 (register), crates/honmoon-proxy/src/mitm.rs:338-363 (the HTTP rendering), crates/honmoon-proxy/src/socks.rs:386-392 (the SOCKS5 rendering) -->

The statuses in that diagram are `mitm.rs`'s rendering, and they are the only part of it that is
HTTP's. The SOCKS5 path holds through the same `approval::hold` and collapses the outcome to a
bool — `matches!(…, HoldOutcome::Approved)` ([socks.rs:386-392](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/socks.rs#L386-L392)) — so
approval lets the connection proceed to its upstream connect, while the three endings that return a
value — rejection, timeout (which the hold itself renders as a rejection) and a full queue — collapse
into the one `REPLY_NOT_ALLOWED` (`0x02`)
([socks.rs:180-184](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/socks.rs#L180-L184), [socks.rs:59-67](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/socks.rs#L59-L67)). RFC 1928 has no
reply code for a request a human declined as opposed to a policy refusal, and none for a queue that
was full, so an operator distinguishes those on the audit log rather than on the wire.

Abandonment is not a fourth reply, because it is not an outcome this caller can receive.
`HoldOutcome::Abandoned` is returned only from the `abandoned` arm of the select, and `approval::hold`
passes `std::future::pending()` into that arm — an explicit signal is something only a caller that
keeps being polled while it waits supplies, through `hold_until`
([approval.rs:242-259](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/approval.rs#L242-L259), [approval.rs:332-339](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/approval.rs#L332-L339)). A
SOCKS5 client that leaves mid-hold drops the connection task instead, and the drop guard frees the
slot and audits the rejection with nothing left to write a reply to.

Three fail-closed properties hold here, and the first is the shared mechanism rendered twice, so it
is stated as the refusal rather than as a status. A **full pending queue** refuses new pauses rather
than growing unbounded ([approval.rs:96-132](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/approval.rs#L96-L132), [approval.rs:64-74](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/approval.rs#L64-L74)); HTTP renders that
refusal `503` ([mitm.rs:359-360](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L359-L360)) and SOCKS5 renders it `0x02`, exactly as
above. `0x02` is SOCKS5's code for a *policy* refusal, not honmoon's generic failure reply: a failed
or timed-out upstream connect is answered `0x05` ([socks.rs:499-517](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/socks.rs#L499-L517)), and a
connection that never completes a greeting or a request is dropped with no reply at all — those
reads propagate their I/O error instead of choosing a code
([socks.rs:205-301](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/socks.rs#L205-L301)). Read it in the one direction that holds: `0x02` on the
wire means policy said no, not that every refused connection shows `0x02`. A
**timeout auto-rejects** a held request so it never hangs forever
([approval.rs:318-347](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/approval.rs#L318-L347)); and a **hold that ends without a
decision** — the HTTP client disconnecting drops the caller's future — frees its slot and audits
the rejection through a drop guard, so abandoned holds cannot saturate the queue
([approval.rs:184-218](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/approval.rs#L184-L218)). The resolution travels back through the
same `Arc<ApprovalRegistry>` shared with the management API — see
[Control Plane & Dashboard](/deep-dive/control-plane).

::: tip Which `pause` rules fire today
Over a raw tunnel the gate sees the facts `host_facts` builds — `domain`, the `endpoint` name when
`(host, port)` names one, and `http.host` — so a `pause` on any of those holds there
([mitm.rs:205-215](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L205-L215)).
With `--tls-intercept --pii-mode block`, a content `pause` holds an individual request and the
approval queue names its PII labels and count — never the matched text
([mitm.rs:894-922](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L894-L922), [mitm.rs:1620-1639](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs#L1620-L1639)). SQL `pause` rules
run on the SOCKS5 PostgreSQL path, not here.
:::

## CLI wiring: `run` vs `gateway`

`honmoon-cli` dispatches five `clap` subcommands, plus a hidden sixth on Linux only. Two drive the
gateway (`run`, `gateway`), two are tooling that binds no listener (`policy validate`, `hook`), and
one is a stub (`join`). `supervise-sandbox` is an internal helper compiled in under
`#[cfg(target_os = "linux")]` — the in-namespace half of enforced `run` isolation — so a macOS
build has no sixth command at all
([main.rs:36-283](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L36-L283), [main.rs:265-282](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L265-L282), [main.rs:325-383](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L325-L383)).

```mermaid
flowchart TD
  main["honmoon (clap dispatch)"] --> run["run --policy P -- argv"]
  main --> gw["gateway --config P --addr A<br>--socks-addr --mgmt-addr --audit-log"]
  main --> join["join --gateway G"]
  run --> bind["bind two loopback pairs:<br>CONNECT + SOCKS5, v4 + v6"]
  bind --> thread["one thread, one runtime,<br>select! over the serve loops"]
  thread --> exec["exec child with *_proxy + ALL_PROXY set"]
  exec --> code["propagate child exit code"]
  gw --> gwstate["build GatewayState (audit + approvals + CA)"]
  gwstate --> gwboth["one runtime: gateway::serve + honmoon-mgmt::serve,<br>+ serve_socks unless --socks-addr off"]
  join --> bail["bail! not yet implemented"]
  style main fill:#2d333b,stroke:#6d5dfc,color:#e6edf3
  style run fill:#2d333b,stroke:#6d5dfc,color:#e6edf3
  style gw fill:#2d333b,stroke:#6d5dfc,color:#e6edf3
  style join fill:#161b22,stroke:#f85149,color:#e6edf3
  style bail fill:#161b22,stroke:#f85149,color:#e6edf3
  style bind fill:#161b22,stroke:#30363d,color:#e6edf3
  style thread fill:#161b22,stroke:#30363d,color:#e6edf3
  style exec fill:#161b22,stroke:#30363d,color:#e6edf3
  style code fill:#161b22,stroke:#30363d,color:#e6edf3
  style gwstate fill:#161b22,stroke:#30363d,color:#e6edf3
  style gwboth fill:#161b22,stroke:#30363d,color:#e6edf3
```
<!-- Sources: crates/honmoon-cli/src/main.rs:36-283 (the Command variants), main.rs:325-383 (dispatch), main.rs:586-788 (gateway), main.rs:790-912 (run) -->

### `honmoon run`

`run` binds its own sockets — **two loopback pairs**, a v4/v6 pair for the `CONNECT` proxy and
another for the SOCKS5 listener — then hands them to one background thread and execs the child
with every proxy env var (`http_proxy`, `https_proxy`, `all_proxy`, `ALL_PROXY` and the uppercase
variants) pointed at them. The child's exit code is propagated
([main.rs:790-912](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L790-L912)). Binding in one place closes the TOCTOU
window where another process could steal the port
([main.rs:799-810](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L799-L810)). A pair downgrades to IPv4 alone only where `::1` is
*proven absent* — the one case where no squatter can take a half honmoon did not bind. Every other
bind failure aborts startup rather than leaving `::1:<port>` unowned
([main.rs:953-988](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L953-L988)).

The accept loops — four of them wherever `::1` is bindable — are polled in a single
`tokio::select!` rather than spawned, deliberately: a
panic in a spawned task is parked in a `JoinHandle` nobody joins, so an accept loop could die,
drop its listener and hand that address to the first process that asked for it while `run` carried
on reporting enforced isolation ([main.rs:828-847](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L828-L847)). A loop with no listener
behind it waits forever instead of returning and taking the other three down with it
([main.rs:920-933](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L920-L933)). One
`GatewayState` sits behind every listener, so a verdict's visibility never depends on which
address family — or which protocol — the client used.

On Linux the child no longer shares the host's loopback, so those listeners are reached through a
Unix-socket bridge into the child's namespace instead
([ADR-0005](https://github.com/pleaseai/honmoon/blob/main/.please/docs/decisions/0005-empty-namespace-and-bridged-proxy-sockets.md)). `run` uses an
in-memory audit ring and does **not** expose the management API — it is the ephemeral,
single-command mode ([gateway.rs:176-192](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/gateway.rs#L176-L192)).

::: tip Enforcing on Linux and macOS, advisory elsewhere (TD-003)
An **unprivileged** child that ignores the env vars reaches nothing over the network rather than
bypassing policy ([ADR-0005](https://github.com/pleaseai/honmoon/blob/main/.please/docs/decisions/0005-empty-namespace-and-bridged-proxy-sockets.md)). On
**Linux** that is an empty user + network namespace containing nothing but loopback, with the proxy
bridged in over a Unix socket; on **macOS** a Seatbelt profile under `sandbox-exec` that denies every
socket except the proxy's loopback port — no system extension, no entitlement, no signing. Neither
replaces the filesystem, so Unix sockets that live there — `/var/run/docker.sock` and friends — stay
reachable, and anything a local daemon behind one will do on the child's behalf is still a way out.
(macOS denies one of them deliberately, the system resolver's, so that DNS is no more available
there than it is inside an empty namespace.)

Four limits keep **TD-003** open: root / `CAP_SYS_ADMIN` / passwordless `sudo` can leave either
sandbox; `run` fails open to advisory where the namespace is refused (the default Docker seccomp
profile blocks `unshare(CLONE_NEWUSER)`, so an ordinary container is advisory) or where the Seatbelt
profile no longer compiles; on **macOS** a command that daemonizes outlives `run`, which closes the
proxy port while those descendants still carry a profile whose one exception names it — free for
any local process to bind and relay for them, where an empty namespace would have stayed empty;
and every platform other than these two still only sets env vars
([tech-debt-tracker.md:11](https://github.com/pleaseai/honmoon/blob/main/.please/docs/tracks/tech-debt-tracker.md#L11)).
:::

### `honmoon gateway`

`gateway` builds a `GatewayState` (policy + audit + approvals + CA + intercept/PII/redaction
settings) and runs the egress proxy, the `honmoon-mgmt` management API and — unless
`--socks-addr off` declines it — the SOCKS5 listener on **one tokio runtime**, sharing that state — so a request held by the proxy can be approved from the
dashboard ([main.rs:586-788](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L586-L788)). Every listener is bound up
front so a bind error is reported before anything is spawned, and a `tokio::select!` surfaces an
unexpected proxy or SOCKS5 exit instead of silently leaving egress filtering down
([main.rs:755-786](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L755-L786)). With SOCKS5 declined there is nothing to join on, so that
arm waits forever rather than firing at once and killing the gateway
([main.rs:767-774](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L767-L774)).

| Flag | Default | Purpose | Source |
|------|---------|---------|--------|
| `--addr` | `127.0.0.1:8443` | Egress proxy listen address | [main.rs:68-70](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L68-L70) |
| `--socks-addr` | `127.0.0.1:1080` | SOCKS5 listen address — the transport for non-HTTP protocols. `off` disables it; the CONNECT proxy keeps running | [main.rs:71-75](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L71-L75), [main.rs:687-697](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L687-L697) |
| `--mgmt-addr` | `127.0.0.1:8444` | Management API + dashboard address | [main.rs:76-78](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L76-L78) |
| `--tls-intercept` | off | Terminate TLS to inspect request bodies. Agents must trust the CA; `InterceptPolicy::All` when set, `None` otherwise | [main.rs:154-157](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L154-L157), [main.rs:640-659](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L640-L659) |
| `--pii-mode` | `detect` | `detect` audits the would-be verdict; `block` enforces it inline. `block` requires `--tls-intercept` | [main.rs:190-195](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L190-L195), [main.rs:616-618](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L616-L618) |
| `--redact-secrets` | off | Rewrite detected secrets and Tier-1 PII to stable placeholders before forwarding, and restore them in identity-encoded responses. Requires `--tls-intercept` | [main.rs:158-168](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L158-L168) |
| `--signed-body` | `block` | What to do when redaction would rewrite a body an authentication signature covers: `block` refuses locally with `403`, `forward` sends the original bytes unredacted. Requires `--redact-secrets` | [main.rs:169-189](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L169-L189), [gateway.rs:102-115](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/gateway.rs#L102-L115) |
| `--mgmt-token` | (minted at `~/.honmoon/mgmt-token`, `0600`) | Bearer token required by **every** `/api/*` route — the audit, approval and policy reads as well as the Claude Code hook endpoint. Browsers exchange it at `GET /login?token=…` — the URL honmoon prints on startup — for a session secret they send in the `X-Honmoon-Session` header; deliberately not a cookie, whose scope would cover every other port on `127.0.0.1` (#188). `--hook-token` / `HONMOON_HOOK_TOKEN` remain accepted as deprecated aliases. Prefer the environment variable to the flag: a command line can be read by other local users via `ps` (how far that reaches is platform- and configuration-dependent), while a token file honmoon created is `0600`. An existing file that is readable beyond its owner is reported rather than tightened — replacing such a token is the operator's call, since it invalidates anything holding the old value. Minting — whether the file is absent or empty — happens under a `mgmt-token.lock` sentinel in the same directory, so a gateway and an `@honmoon/api` starting together converge on one token instead of each keeping the one it minted (#189); a lock a start left behind by crashing mid-mint is broken after ten seconds, and a start that waits thirty seconds for one refuses rather than minting a second token. `@honmoon/api` reads only the variable or the file, never this flag | [main.rs:99-138](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L99-L138), [mgmt_token.rs:301-402](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/mgmt_token.rs#L301-L402), [auth.ts:64-68](https://github.com/pleaseai/honmoon/blob/main/packages/api/src/auth.ts#L64-L68), [auth.ts:310-362](https://github.com/pleaseai/honmoon/blob/main/packages/api/src/auth.ts#L310-L362) |
| `--audit-log` | (in-memory only) | Append every **recorded** verdict — the set the intro describes, not each forwarded request — and any recorded security degradation, to a JSONL file. Must name a **regular file**: opened with `O_NOFOLLOW`, so a symlink as the final path component is refused, as are a FIFO, socket, device and directory, and the refusal aborts startup. Created owner-only when absent; an existing file keeps its mode | [main.rs:79-98](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L79-L98), [main.rs:629-638](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L629-L638) |

## Hermetic integration tests

`crates/honmoon-proxy/tests/egress.rs` proves the host gate with no external processes: an
in-process TCP upstream and a hand-rolled client over loopback exercise the **real**
`serve_listener` proxy ([egress.rs:1-76](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/tests/egress.rs#L1-L76)):

| Test | Asserts | Source |
|------|---------|--------|
| `denied_host_is_blocked_with_403` | Denied host over `CONNECT` → `403` | [egress.rs:104-117](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/tests/egress.rs#L104-L117) |
| `allowed_host_tunnels_through_to_upstream` | Allowed host → `200`, then real bytes flow | [egress.rs:119-142](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/tests/egress.rs#L119-L142) |
| `plain_http_to_denied_host_is_blocked_with_403` | Cleartext `http://` is gated too — no bypass by skipping `CONNECT` | [egress.rs:144-162](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/tests/egress.rs#L144-L162) |
| `absolute_form_https_without_connect_is_blocked_with_403` | The `https://` scheme alone does not prove an authorized tunnel | [egress.rs:164-181](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/tests/egress.rs#L164-L181) |
| `origin_form_request_is_gated_via_host_header` | `GET /` is gated on its `Host` header, not on an empty host | [egress.rs:183-198](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/tests/egress.rs#L183-L198) |
| `partial_request_head_is_dropped_after_the_head_read_timeout` | A head that never completes is dropped rather than held for the life of the process | [egress.rs:200-244](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/tests/egress.rs#L200-L244) |
| `forwarded_request_preserves_the_client_header_casing` | Supplying a server builder keeps hudsucker's two wire-fidelity settings rather than silently dropping them | [egress.rs:246-281](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/tests/egress.rs#L246-L281) |

The Phase 1 `405`-on-non-CONNECT test is gone on purpose: since hudsucker the proxy serves plain
HTTP as well, so a `GET http://denied/` is answered with the stronger `403` rather than a method
refusal ([egress.rs:144-148](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/tests/egress.rs#L144-L148)).

Two more suites cover the phases above it. `crates/honmoon-proxy/tests/mitm.rs` runs a real
`tokio-rustls` client against an in-process CA, so each claim below is a test rather than a
milestone: TLS termination and PII detection in the body
([mitm.rs:231-236](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/tests/mitm.rs#L231-L236)), both PII modes
([mitm.rs:239-262](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/tests/mitm.rs#L239-L262), [mitm.rs:267-289](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/tests/mitm.rs#L267-L289)), a content
`pause` held to approval ([mitm.rs:292-337](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/tests/mitm.rs#L292-L337)), chunked and gzip bodies
([mitm.rs:342-353](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/tests/mitm.rs#L342-L353), [mitm.rs:358-377](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/tests/mitm.rs#L358-L377)), Kubernetes
endpoint rules ([mitm.rs:656-680](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/tests/mitm.rs#L656-L680)), the uninspectable-endpoint refusal
([mitm.rs:504-541](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/tests/mitm.rs#L504-L541)), and the tunnel-not-scheme recognition of #100
([mitm.rs:897-965](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/tests/mitm.rs#L897-L965)).
`crates/honmoon-mgmt/tests/e2e.rs` holds a live `CONNECT` on a `pause` rule, finds it on the
management API's approval queue, and shows approving it lets the tunnel through (`200`) while
rejecting blocks it (`403`), asserting the `Paused`/`Approved` and `Rejected` audit entries for
each ([e2e.rs:248-294](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-mgmt/tests/e2e.rs#L248-L294), [e2e.rs:297-325](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-mgmt/tests/e2e.rs#L297-L325)).

## Related Pages

- [Policy Model & Decision Engine](/deep-dive/policy-engine) — `decide_explained()` and the audit `Decision`.
- [Control Plane & Dashboard](/deep-dive/control-plane) — the management API that resolves held requests.
- [Protocol-Aware Parsing](/deep-dive/protocol-parsing) — the parsers TLS termination and the SOCKS5 path feed.
- [Quick Start](/getting-started/quick-start) — running `run` and `gateway`.

## References

- [crates/honmoon-proxy/src/gateway.rs](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/gateway.rs)
- [crates/honmoon-proxy/src/mitm.rs](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/mitm.rs)
- [crates/honmoon-proxy/src/approval.rs](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/src/approval.rs)
- [crates/honmoon-cli/src/main.rs](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs)
- [crates/honmoon-proxy/tests/egress.rs](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-proxy/tests/egress.rs)
- [.please/docs/decisions/0003-adopt-hudsucker-for-tls-termination.md](https://github.com/pleaseai/honmoon/blob/main/.please/docs/decisions/0003-adopt-hudsucker-for-tls-termination.md)
- [.please/docs/decisions/0002-phase1-connect-proxy-on-tokio.md](https://github.com/pleaseai/honmoon/blob/main/.please/docs/decisions/0002-phase1-connect-proxy-on-tokio.md)
