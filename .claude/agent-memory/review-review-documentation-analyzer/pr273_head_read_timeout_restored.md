---
name: pr273-head-read-timeout-restored
description: >-
  PR #273 (issue #267) restored gateway.rs's head-read timeout via hyper's header_read_timeout +
  TokioTimer at 30s; every dependency-chain citation in egress-gateway.md's rewritten section was
  verified against the pinned crate sources, and the two defects review found on the PR — a stale
  contributor-guide.md slowloris sentence and a 10s bound that silently shortened idle keep-alive —
  were both fixed inside the PR, so neither is a live finding
metadata:
  type: project
---

PR #273 adds `crates/honmoon-proxy/src/gateway.rs::server_builder()` (`with_server` + `TokioTimer` +
`header_read_timeout(HEAD_READ_TIMEOUT)`), closing the regression `egress-gateway.md` had documented
since #260/#268 as "Guards the Phase 1 proxy had and honmoon no longer implements."

**Verified against the pinned dependency versions** (hudsucker 0.24.1, hyper-util 0.1.20, hyper
1.10.1 — resolve from `Cargo.lock`, the registry cache holds others):

- hyper's default-vs-configured distinction (`hyper/src/common/time.rs:70-85`: `Dur::Default` on
  `Time::Empty` warns and returns `None`; `Dur::Configured` panics). The cited 70-78 covers the
  Default branch, which is what the sentence beside it claims.
- hudsucker's builder sets only `title_case_headers`/`preserve_header_case`, no `.timer(...)`
  (`hudsucker/src/proxy/mod.rs:117-124`).
- hyper writes no `408` on a header-read timeout — `Kind::HeaderTimeout` is only constructed and
  returned as a `poll` error (`conn.rs:264`, `error.rs:436-437`); nothing writes a response.
- HTTP/2's `keep_alive_timeout` (20s) does nothing without `keep_alive_interval`
  (`hyper/src/proto/h2/server.rs:73-74`).
- hyper-util's preface sniff `ReadVersion::poll` (`auto/mod.rs:337-372`) carries no deadline — the
  `#272` "still held on zero bytes" residual is accurate.

**Both defects review found were fixed in the PR. Do not re-report either.**

1. `contributor-guide.md` described the slowloris guard as "a `tokio::time::timeout` around reading
   the request head", citing a range that had pointed at `SignedBodyMode` since before the branch
   (`gateway.rs:64-67` on `origin/main`); the PR's mechanical anchor shift moved it without reading
   it. Fixed: the sentence now points the `tokio::time::timeout` idiom at `socks::handle_connection`,
   which really is that shape, and says the HTTP guard is a server-builder setting instead. Note the
   shape for next time — `scripts/check-wiki-source-anchors.ts` cannot catch this class, because
   `pub enum SignedBodyMode {` opens on a plain declaration line, so the citation resolves as
   structurally valid while supporting nothing its sentence claims.
2. The bound shipped at 10s in the first draft, reasoning from parity with `socks::HANDSHAKE_TIMEOUT`
   and the Phase 1 constant. That parity was the wrong argument: hyper re-arms `header_read_timeout`
   on every head read, so it is also the idle keep-alive bound, while both namesakes wrap a one-shot
   future that cannot re-arm. Fixed: the value is hyper's own 30s default, the doc comment and the
   wiki state both roles and the intercepted-tunnel reach, and both roles are pinned by tests. See
   [[gateway-head-read-timeout-reach]] for the traced mechanism.

**Do not flag `quick-start.md`'s Phase-1 `400`/`405`/`408` status table.** It describes the proxy
ADR-0003 replaced and is tracked under #119. PR #273 moved `gateway.rs` far enough that its stale
anchors stopped tripping any rule in `check-wiki-source-anchors.ts`, so they were dropped from
`TRACKED` and the loss was recorded on #119 — meaning the table is now stale *and* unreported. That
is #119's to fix, not a finding against a later PR.
