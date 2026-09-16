---
name: gateway-head-read-timeout-reach
description: "honmoon's gateway HEAD_READ_TIMEOUT is hyper's header_read_timeout and reaches past the first request head — hyper re-arms it on every poll_read_head, so it is also the idle keep-alive bound, and hudsucker clones the same builder into the MITM inner connection so an intercepted TLS tunnel inherits it; this is why the value is hyper's 30s default and not the 10s its one-shot namesakes use (PR #273, issue #267)"
metadata:
  type: project
---

`gateway::server_builder()` (`crates/honmoon-proxy/src/gateway.rs`) passes hudsucker a `hyper_util`
`auto::Builder` with `.timer(TokioTimer)` + `.header_read_timeout(HEAD_READ_TIMEOUT)`.

Three facts traced and measured once, so a later pass does not re-derive them:

1. **`header_read_timeout` is an idle keep-alive timeout as well as a partial-head timeout.**
   hyper 1.10.1 `proto/h1/conn.rs:219-240` arms the timer on *every* `poll_read_head`, and a
   keep-alive connection waiting for its next request is parked in exactly that read. Measured on
   the 10s draft of PR #273: the proxy sent FIN at 10.002s on an idle proxied HTTP/1 connection.

2. **The builder is shared with the MITM inner connection.** hudsucker 0.24.1 clones the server
   builder into `InternalProxy` (`proxy/mod.rs:156-164`) and serves the decrypted TLS stream with it
   (`proxy/internal.rs:406-410`). Under `InterceptPolicy::All` — what `honmoon-cli/src/main.rs`
   selects for `--tls-intercept` — an intercepted tunnel's inner HTTP/1 connection inherits the same
   bound. A tunnel forwarded raw does not: it leaves HTTP/1 at the CONNECT upgrade.

3. **hudsucker's default builder sets exactly two things**, both HTTP/1 wire fidelity
   (`title_case_headers(true)`, `preserve_header_case(true)`, `proxy/mod.rs:117-124`) — nothing
   else. So `with_server` replacing it costs no other security-relevant default: `max_headers`,
   `max_buf_size`, `ignore_invalid_headers`, `half_close` and `keep_alive` are hyper defaults before
   and after. A later review does not need to re-enumerate that.

**What was decided, so it is not re-litigated.** Fact 1 is why the constant is **30s, hyper's own
default for this setting**, and not the 10s that Phase 1's `HEAD_READ_TIMEOUT` and
`socks::HANDSHAKE_TIMEOUT` use. Those two wrap a one-shot handshake future that cannot re-arm, so
their value says nothing about a client's idle-pool budget; PR #273's first draft reasoned from that
parity, and the parity is the part that was wrong. Both roles are now stated in the constant's doc
comment and pinned by tests in `crates/honmoon-proxy/tests/egress.rs`
(`partial_request_head_is_dropped_after_the_head_read_timeout`,
`an_idle_keep_alive_connection_is_held_for_the_head_read_timeout`) — so a finding that the doc
understates the reach, or that the idle role is untested, is answered by this note and by those
tests rather than being a new defect.

The preface-sniff residual is knowingly out of scope and tracked on #272 — do not report it as
undisclosed. Its reach is wider than "a peer that sends nothing": hyper-util's `ReadVersion::poll`
has no deadline of its own and keeps waiting while every byte so far matches a prefix of the
24-byte HTTP/2 preface and fewer than 24 have arrived, so a 22-byte partial preface is held just as
a zero-byte connection is (measured 45s). One diverging byte ends the sniff and hands the
connection to HTTP/1, which is why an ordinary stalled head *is* bounded by `HEAD_READ_TIMEOUT`.
