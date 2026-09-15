---
name: pr268-egress-gateway-hudsucker-rewrite
description: >-
  PR #268 (issue #260) rewrote egress-gateway.md against the hudsucker data plane rather than
  repointing it — so the Phase 1 names (handle, authorize, hold_for_approval, read_head) are
  deliberately absent and must not be flagged as missing; the page's slowloris claim is verified
  true through a four-hop dependency chain recorded here, so do not re-derive it and do not
  "correct" the page to say hudsucker owns that guard
metadata:
  type: project
---

Issue #260 was not anchor drift. `wiki/deep-dive/egress-gateway.md` described the hand-rolled
tokio CONNECT proxy ADR-0003 replaced, so the *claims* were wrong and no line range could support
them. The page was rewritten against `mitm.rs` / `approval.rs`, and the three `#260` entries left
in `scripts/check-wiki-source-anchors.ts`'s `TRACKED` ledger by #264 were dropped with it.

**Renames, so a reviewer arriving with an old name does not report it as a gap.** `handle` has no
successor by that name — the per-request entry point is `HonmoonHandler::handle_request`;
`authorize` → `host_gate`; `hold_for_approval` → `HonmoonHandler::hold` over `approval::hold`;
`read_head` is gone because hudsucker parses the head. `HEAD_READ_TIMEOUT` and `MAX_REQUEST_HEAD`
exist nowhere in `crates/`. The page carries a `::: warning Names that moved` block for exactly
this reason; it is deliberate, not leftover prose.

**The slowloris claim is true, and the chain is four hops — do not re-derive it, and do not
"fix" the page to credit hudsucker with the guard.** The page says honmoon no longer implements a
head-read timeout and that hyper's default never arms. Verified by this review pass
independently of the author, who had traced the same chain:

1. `gateway::serve` never calls `ProxyBuilder::with_server` — `gateway.rs:190-196` passes only a
   listener, CA, rustls connector and handler.
2. With no server supplied, `hudsucker::Proxy::start` builds its own
   `hyper_util::server::conn::auto::Builder` and sets only `title_case_headers` /
   `preserve_header_case`. **`.timer(...)` appears nowhere in hudsucker 0.24.1.**
3. `hyper_util` 0.1.20's `auto::Builder::new` just wraps `http1::Builder::new()`; it installs no
   timer either.
4. `hyper` 1.10.1's `http1::Builder::new` starts at `timer: Time::Empty` with
   `h1_header_read_timeout: Dur::Default(Some(30s))`, and `Time::check` on a `Dur::Default` with
   `Time::Empty` logs `timeout ... has default, but no timer set` and returns `None`
   (`hyper/src/common/time.rs:70-85`). `Dur::Configured` would panic; `Dur::Default` goes quiet.

So `set_http1_header_read_timeout` is never called. Filed as issue #267 (fix:
`with_server` + `TokioTimer`). The **head-size** bound does survive — hyper's h1 read path errors
`new_too_large()` once the read buffer reaches `DEFAULT_MAX_BUFFER_SIZE` (8192 + 4096*100) with an
incomplete message — but it is hyper's, not honmoon's, and it does not mitigate slowloris, because
a client that never fills the buffer never trips it. The page states both at exactly that strength.

**What this review pass missed, which is the part worth keeping.** Three defects reached the PR
and were caught by others, all of them the same shape — a claim stated more widely than the code
supports:

- The verdict table's "Client response" column said `tunnel (200)`. `host_gate` is not
  CONNECT-only: `handle_request` runs it for every cleartext and absolute-form request no
  authorized tunnel covers, and `Gate::Proceed` there reaches `inspect_body` and forwards, so the
  client gets the *upstream's* response. **codex and cubic found this independently; my pass did
  not.** Fixed by reporting the `Gate` the cited ranges actually show (`Proceed` /
  `Block(response)`, `mitm.rs:151-158`) and moving the shape split to prose.
- The sequence diagram used mermaid `opt` for two refusal paths that **return early** in the code,
  so the diagram read as "this may happen, and then the rest happens anyway". `opt` has no
  early-return semantics. Check every `opt` in an honmoon sequence diagram against whether its
  block's code path continues.
- `inspect_body` was cited `614-640` — doc comment plus signature, none of the ~285-line body —
  while every sibling row cited doc-through-end. An under-cited range is invisible to
  `check-wiki-source-anchors.ts`, which only checks where a range *opens*.

**Two drift classes that script cannot see**, both hit on this PR:

- A range whose opening line is ` */` (a doc-comment closer). `BARE_DELIMITER` is
  `/^[)\]}]+[,;]?$/`, so `*/` does not match and the citation still resolves. `ed53fb4` (#262)
  extracted `attemptUnderLock` out of `mintOrAdoptUnderLock` and shifted `packages/api/src/auth.ts`
  by one line at exactly the point this page's `--mgmt-token` row cited, turning `auth.ts:309-393`
  into a range opening on ` */` and running past the end of the function it named. Repointed to
  `auth.ts:310-362` plus `auth.ts:64-68` for the `10_000` / `30_000` constants the cell names by
  value. `control-plane.md`'s `auth.ts:142-198` was unaffected — both endpoints byte-identical
  across #262.
- A range that opens correctly and simply covers too little (the `inspect_body` case above).

**`wiki/**` is in the root `eslint.config.mjs` ignore list (line 22), confirmed with
`eslint --print-config`.** The `markdown/no-missing-atx-heading-space` trap that a `#123`
reference wrapping to column 1 triggers elsewhere in this repo does **not** fire on wiki pages, so
a bare `(#188)` in wiki prose is correct and expanding it to `(issue #188)` is churn. The wiki's
own gate is `cd wiki && bun run build`.

See [[wiki-is-a-fourth-claim-site]] for why `wiki/` drifts from the normative documents at
all, and [[pr264-wiki-anchor-ledger-253-verified]] for the ledger this PR drew three entries from.
