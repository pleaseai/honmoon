---
name: pr268-egress-gateway-hudsucker-rewrite
description: >-
  PR #268 (issue #260) rewrote egress-gateway.md against the hudsucker data plane rather than
  repointing it — so the Phase 1 names (handle, authorize, hold_for_approval, read_head) are
  deliberately absent and must not be flagged as missing; the page's slowloris claim is verified
  true through a four-hop dependency chain recorded here, so do not re-derive it and do not
  "correct" the page to say hudsucker owns that guard; nearly every defect review found on it was a
  quantifier or count no single code path keeps, a diagram whose shape does not match the code, or a
  citation that does not support its sentence — sweep for those three shapes rather than waiting for
  the round that names them
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

**What this review pass missed, which is the part worth keeping.** Review kept finding defects on
this page round after round, and they fall into three shapes. No running tally here on purpose — a
count is exactly the kind of claim that goes stale on the next round. The shapes are the durable
part:

1. **A quantifier or a count** — the most common by far. A claim scoped more widely (and
   occasionally more narrowly) than any single code path keeps. Grep the page for
   `every|all|only|always|never` and each bare number, then check every hit against the branch that
   has to hold it.
2. **A diagram whose shape does not match the code** — recurring, each time a round after the last
   was fixed. Two were control flow: `opt` has no early-return semantics, and a two-way `alt`
   cannot carry three verdicts. The third is the one to internalize, because a sweep for quantifiers
   will not find it: **a mechanism shared by two transports has two renderings, and a diagram of one
   is a claim about both unless it says otherwise.** `approval::hold` is shared with the SOCKS5 data
   path — the prose said so two paragraphs above the diagram — while the diagram's terminal states
   were HTTP statuses with nothing marking them as such.
3. **A citation that does not support its sentence** — and every variant of this is invisible to
   `check-wiki-source-anchors.ts`, which validates only where a range *opens*. Seen here in all
   three directions: a range covering too little (`inspect_body` cited at doc-plus-signature), a
   range running past its subject (test ranges ended on the *next* test's `#[test]` attribute), and
   a range pointing at a module doc comment while the sentence enumerated eight behaviours the
   comment does not mention. **A sentence that enumerates cases needs one citation per case, or
   fewer cases.**

**Sweeping for a shape beats waiting for the round that finds it — but sweep for the shape, not
for the sentence.** Once each shape was named, one pass over the whole page looking for *that*
shape caught several more before the next round reached them: four quantifiers (`f7cba25` — `status_response` as "the refusal every gate
returns" when three refusals carry a reason body instead; two mermaid nodes still unqualified a
screen below prose already corrected; `--audit-log`'s "every verdict"), two diagram branches
(`afcc4c2`, `90aef36` — the hold diagram carrying the verdict table's own CONNECT-only defect one
section below it, and a third site of the audit claim), and one shared-mechanism claim (`96c7281` —
the intro tip's "gates every connection the same way", which after the `http.host` fix actively
contradicted it, since `connection_gate` builds `Facts { domain, endpoint, ..Default::default() }`).
The sweep is cheap and mechanical; the review round costs a CI cycle and a bot pass.

**The trap inside that method, hit once here.** `96c7281` fixed a shared-mechanism claim on the
SOCKS5 tip by writing "puts **every** connection through the same allow / deny / pause gate" — and
the next round flagged that quantifier, correctly: the `kubernetes` refusal runs *before*
`connection_gate` (`socks.rs:175-178`), so such a destination never reaches the gate, and a `pause`
on it is audited as a refusal with its rule attribution intact rather than held for an approval
nobody could act on (`socks.rs:419-456`). **Widening a claim to fix a neighbouring one re-creates
the first shape.** After editing a sentence for one shape, re-read it for the other two.

The ones worth keeping as worked examples, in the order they were found:

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
- The `audit_allow` asymmetry. "The gateway records every decision to the audit log" is false for
  an ordinary forwarded request: `handle_request` passes `audit_allow = true` on the CONNECT
  (`mitm.rs:943`) and `false` on the inner/cleartext request (`mitm.rs:967`), and `host_gate`
  records the `Allow` only under that flag (`mitm.rs:308`). `inspect_body` is quiet the same way —
  it records an `Allow` only when the scan found PII (`mitm.rs:853-867`) — and says so, citing
  `host_gate`'s `audit_allow` as its precedent. Both are deliberate: the audit ring is bounded, and
  recording every clean allow would cycle out the refusals. **Narrow such a claim to the positive
  set rather than hedging it**; a hedge on a universal claim draws the same finding next round.
- "hands all four to one background thread". `bind_loopback_pair` returns `(v4, None)` when `::1`
  is *proven absent* — `AddrNotAvailable | Unsupported` only (`main.rs:953-988`) — and the loop
  behind the missing half takes `std::future::pending()` (`main.rs:920-933`). `AddrInUse` retries
  and every other error fails closed, deliberately.
- "runs the egress proxy, the SOCKS5 listener and the management API". `--socks-addr off | none |
  disabled` sets `socks_listener` to `None` (`main.rs:691-697`) and the select arm pends
  (`main.rs:767-774`). The flag table one screen below already documented `off`, so the overview
  contradicted its own page — **an internal contradiction between prose and a table is the cheapest
  of these to catch, and it still shipped.**
- "only `http.host`-based rules see facts" over a raw tunnel — too **narrow**. `host_facts` sets
  `domain`, `endpoint` (via `resolve_endpoint`) and `http.host` (`mitm.rs:205-215`), so a `pause`
  on any of the three holds there. On this page understating the gate is the same defect as
  overstating it; the check is "what does the code populate", not "is the claim safe".
- "dispatches six `clap` subcommands". `Command::SuperviseSandbox` carries
  `#[cfg(target_os = "linux")]` **on the variant** (`main.rs:270`), so a macOS build has five and
  `clap` never sees the sixth. **A `cfg`-gated enum variant makes a CLI surface count
  target-specific** — and this page documents macOS Seatbelt behavior two screens later, which is
  exactly the reader who would go hunting for it.
- The intro tip still said both `run` and `gateway` start SOCKS5, one round after the CLI section
  got the `--socks-addr off` qualifier — so the page contradicted itself two screens apart.
  **A qualifier added in one place is a prompt to grep for the other sites of the same claim**;
  `run` does start it unconditionally (`main.rs:808`) and `gateway` does not (`main.rs:691-697`),
  so the honest form splits the two commands rather than hedging both.
- The refusal diagram split the content verdict two ways — "forwards" / "blocks" — and put `Pause`
  in the blocking branch. An approved hold **forwards** (`mitm.rs:894-922`) and a `Deny` answers
  `403` with no hold in the path (`mitm.rs:883-893`), so one branch carried an outcome that does
  not block at all. Three verdicts need three branches.
- The hold state diagram's terminal states were HTTP statuses, on a diagram of a hold
  `approval::hold` shares with SOCKS5. `connection_gate` collapses the whole outcome to a bool
  (`matches!(hold(…), HoldOutcome::Approved)`, `socks.rs:386-392`) and its caller answers `false`
  with `REPLY_NOT_ALLOWED` (`socks.rs:180-184`) — so on SOCKS5 a rejection, a timeout, a full queue
  and an abandonment are **the same byte on the wire**. The diagram did not merely read as
  HTTP-flavoured; it told an operator they could tell four outcomes apart where they cannot. RFC
  1928 has no code for "a human declined" as against a policy refusal, and none for a full queue.
- "Bodies are scanned as well" on the cleartext and inner shapes, unconditionally.
  `MAX_INSPECT_BODY` is 2 MiB — declared, discovered while reading, or reached by decompression
  (`body.rs:56-61`) — and a body past it is forwarded unscanned. The guards table five sections
  down did say so; the shape list, which is where a reader learns what each shape gets, did not.
  **A cap stated once, far from the claim it bounds, reads as not applying there.**
- The `Pause` row gave `Paused → Approved/Rejected` as its audit lifecycle while its `Gate` cell
  covered the queue-full case, which records `Rejected` alone and returns before any `Paused` entry
  or hold exists (`approval.rs:286-295`). **Two cells of one row disagreeing is the same asymmetry
  tell as two sides of one mechanism.**

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
