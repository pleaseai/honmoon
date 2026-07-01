# ADR-0003: Adopt hudsucker for TLS termination (MITM) in the data plane

## Status

Accepted

(Resolves the framework question [ADR-0002](0002-phase1-connect-proxy-on-tokio.md) deferred to
"the TLS-terminating HTTP-inspection phase", and closes the "revisit Pingora" direction from
[ADR-0001](0001-adopt-pingora-http-data-plane.md).)

## Context

Phase 5 adds content-aware PII/DLP: the policy engine must see request **bodies**, not just the
destination host. Over a raw `CONNECT` tunnel (Phase 1, ADR-0002) the proxy sees only `host:port`;
the HTTPS payload is encrypted end-to-end. The merged Tier-1 detector (`honmoon-core::pii`) is
complete and CEL-wired (`Facts.pii`) but has **no live data source**. TLS termination (MITM) is
that source: after `CONNECT` `200`, terminate the agent's TLS with a per-host leaf certificate
minted from a **local CA the agent trusts**, decrypt, inspect the inner HTTP, then re-encrypt to
the real upstream.

This is architecturally significant (it decrypts all agent TLS) and security-sensitive, so we
evaluated the ecosystem rather than hand-rolling. Candidates:

- **hudsucker** (`omjadas/hudsucker`) — a dedicated Rust MITM HTTP/S proxy library built on
  `hyper` 1.x + `rustls` + `rcgen`. MIT/Apache, actively maintained (v0.24.1, May 2026). Its
  `HttpHandler` gives the full request (with body) and can short-circuit with a response;
  `should_intercept` selects which tunnels to terminate; `RcgenAuthority` mints and caches
  per-host leaf certs. HTTP/1.1 + HTTP/2 + WebSocket.
- **Hand-rolled `tokio-rustls` + `hyper` + `rcgen`** — full control, but we would reimplement CA
  management, per-host leaf caching, the TLS acceptor, HTTP/2 handling, and selective bypass —
  all security-sensitive code hudsucker already ships and tests.
- **Pingora** — ADR-0002 found its `HttpProxy` reverse-proxy-oriented and unfit for terminating
  CONNECT-MITM (would require hijacking the raw session stream outside the happy path).
- **rama** (`plabayo/rama`) — capable modular proxy framework with MITM support, but `0.3-alpha`
  with API churn, MSRV 1.93 (forcing a workspace toolchain bump from 1.85), and optional
  BoringSSL FFI. More surface than this milestone needs.

For our egress model — agents using `https_proxy` → `CONNECT` tunnel → MITM — hudsucker fits
exactly: after `CONNECT` we already own the client stream, and hudsucker's handler maps 1:1 onto
Honmoon's policy engine.

## Decision

Adopt **hudsucker** as the TLS-termination engine for `honmoon-proxy`.

- hudsucker owns the proxy accept loop (`Proxy::builder()...start()`). Honmoon's
  transport-agnostic core (`decide_explained`, `ApprovalRegistry`, `AuditLog`) is driven from a
  `HttpHandler` (`crate::mitm::HonmoonHandler`). The Phase 1 control logic (host allow/deny/pause,
  audit) was **ported** into the handler, not rewritten.
- Host-level policy runs on the **CONNECT request** (and on cleartext `http://` requests), so the
  egress allowlist keeps working for every tunnel — intercepted or not — and cannot be bypassed by
  skipping CONNECT. `403`/`pause`-hold semantics are preserved.
- **Selective termination** via `InterceptPolicy` (`should_intercept`): `None` (raw tunnel — the
  default and the Phase 1 behavior), `All`, or a host set. Cert-pinned hosts stay pass-through.
- **Detect-only v1**: decrypted request bodies are scanned with `detect_pii` and findings are
  recorded to the audit log (`verdict` carries the would-be decision), but content does **not**
  block yet. Enforcing content rules is a fast follow.
- **Local CA** (`crate::ca::CaMaterial`, rcgen via `RcgenAuthority`): generated on first run and
  persisted; the CA private key is written `0600` and never logged; the CA certificate is exposed
  for installation into agents' trust stores. `honmoon gateway --tls-intercept` enables MITM.
- **Memory safety**: request bodies are buffered for inspection only when `Content-Length` is
  present and ≤ `MAX_INSPECT_BODY`; larger/unknown-length bodies stream through un-inspected, so a
  large upload cannot exhaust memory.

## Consequences

### Positive

- Reuses a maintained, tested MITM stack (correct cert handling, leaf caching, HTTP/2, selective
  bypass) instead of hand-rolling security-critical code.
- The Tier-1 PII detector now has a live data source; the Phase 5 exit criterion (a body-borne RRN
  to a non-allowlisted host is caught) is reachable — proven detect-only by
  `crates/honmoon-proxy/tests/mitm.rs`.
- Host-level egress filtering, `pause`/approval, and audit are preserved end-to-end
  (`honmoon-mgmt/tests/e2e.rs` still green); plain-HTTP forward requests are now filtered too.

### Negative

- New dependency tree (`hudsucker` → `hyper`, `rustls`/`aws-lc-rs`, `rcgen`, `tokio-tungstenite`):
  heavier build than the raw-tokio proxy, and `aws-lc-rs` brings a C build.
- MITM is a powerful trust surface: the CA can impersonate any host to a trusting agent. Mitigated
  by opt-in (`--tls-intercept`), `0600` key permissions, and never logging the key or raw PII.
- Cert-pinned hosts break under interception → must be listed as pass-through (follow-up: a
  pinned-host catalog).

### Neutral

- `docs/roadmap.md` and `.please/docs/knowledge/tech-stack.md` updated: the data plane uses
  hudsucker for TLS termination; Pingora is closed out and rama noted as a future reconsider if the
  data plane grows into multi-protocol / fingerprinting.

## Alternatives Considered

- **Hand-roll `tokio-rustls` + `hyper` + `rcgen`**: rejected — reimplements CA cache, cert
  resolver, HTTP/2, and selective bypass that hudsucker already provides and tests.
- **Pingora**: rejected — reverse-proxy-oriented, unfit for terminating CONNECT-MITM (ADR-0002).
- **rama**: deferred — alpha API churn, MSRV 1.93 bump, BoringSSL FFI, broader than needed now;
  reconsider if the data plane expands to many protocols / fingerprinting.
- **Squid + SSL Bump (external)**: rejected — moves the data plane out of the inline Rust engine
  and requires ICAP integration for policy/PII.

---

_Date: 2026-07-01_
_Related: [ADR-0001](0001-adopt-pingora-http-data-plane.md), [ADR-0002](0002-phase1-connect-proxy-on-tokio.md), `crates/honmoon-proxy/src/{gateway,mitm,ca}.rs`, `docs/roadmap.md`_
