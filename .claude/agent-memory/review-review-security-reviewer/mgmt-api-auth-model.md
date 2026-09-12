---
name: mgmt-api-auth-model
description: 'How the honmoon management API authenticates after #173 — mandatory Arc<str> token, nested /api router + route_layer, the HMAC session cookie whose off-browser replay reaches reads AND writes (#188), how the Rust and Bun loaders were made to agree on what counts as a token, and which constant-time/route-ordering questions are settled so they are not re-derived'
metadata:
  type: project
---

Settled facts about `crates/honmoon-mgmt/src/lib.rs` auth (PR #186, issue #173). Re-verify
against the file before citing, but do not re-derive these from scratch.

**Shape.** `AppState.mgmt_token: Arc<str>` is mandatory (asserted non-empty *and* non-padding —
see the cross-runtime section below). `router()` builds an
inner `Router` of the six `/api` routes, applies `route_layer(from_fn_with_state(state,
require_credential))`, and `nest("/api", api)`. Outside the gate: `GET /healthz`, `GET /login`,
and the `static_handler` SPA fallback. Token resolution lives in `honmoon-cli/src/mgmt_token.rs`
(`$HOME/.honmoon/mgmt-token`, `O_CREAT|O_EXCL`, file `0600` in a `0700` directory);
`packages/api/src/auth.ts` reads the same file for the TS audit server.

**Already checked, no defect — do not re-report:**
- Route ordering / `nest` vs `fallback`: unknown `/api/...`, `/api`, `//api/...`, trailing slash
  all fall to `static_handler`, which 404s any `api`-prefixed path rather than SPA-falling-back.
  No path reaches a handler ungated.
- `constant_time_eq` (lib.rs) folds both sides through HMAC-SHA256 and compares `CtOutput`;
  `digest 0.10.7` `mac.rs:283` implements `PartialEq` via `subtle::ConstantTimeEq`. The
  constant-time claim in the doc comment is accurate. `packages/api` uses `timingSafeEqual` over
  two SHA-256 digests — also accurate.
- `same_origin()` fails closed on `Origin: null` and on an absent `Host` (h2).
- Failed `GET /login` sends no `Set-Cookie`; success sends `Cache-Control: no-store`.

**The cookie's loopback-port scope — narrowed, not closed.** `honmoon_session` is `Path=/`,
`SameSite=Strict`, and a cookie's scope has no port (RFC 6265 §8.5) while "site" ignores port too,
so the cookie travels to *every* `127.0.0.1:<port>` the operator's browser touches, including a
listener another local user owns. That listener can harvest it.

What PR #186 did about it, so **do not re-report these as open**:
- `same_origin()` refuses a cookie-authenticated non-safe method carrying neither
  `Sec-Fetch-Site` nor `Origin` — the shape of a *naive* off-browser replay. Pinned by
  `a_cookie_replayed_without_browser_labelling_cannot_write` and
  `the_origin_fallback_decides_a_cookie_write_when_fetch_metadata_is_absent`.
- `static_handler` serves `X-Frame-Options: DENY` and `Content-Security-Policy:
  frame-ancestors 'none'`, so the framed-shell variant is closed.
- Origin/Host compare case-insensitively (RFC 9110 §4.2).

**What `same_origin()` does NOT do — the correction to an earlier version of this note, which
claimed "there is no permissive arm for writes any more". That was wrong.** Every header it reads
is unforgeable by a *page*, not by a *client*: a replay from `curl` that simply sets
`Sec-Fetch-Site: same-origin` passes the check and reaches the writes
(`POST /api/approvals/{id}/approve`). Raised by codex on PR #186 and confirmed. What the function
genuinely closes is the browser-driven path — a page on a sibling `127.0.0.1` port causing the
operator's own browser to issue the request, which `SameSite=Strict` permits because different-port
is same-site.

What genuinely remains, therefore: a harvested cookie has **full management access — reads and
writes**, not reads only, until the token is rotated. Tracked as **#188** — report against that
issue, not as new. No header check can close it, because each one presupposes a browser at the
other end; the fix is to make the cookie unharvestable (TLS on the management listener so it can
carry `Secure` + a `__Host-` prefix) or to stop using a cookie for writes. Dropping the cookie
outright would reopen the DNS rebinding it defeats by construction.

**Cross-runtime agreement on "what is a token" — settled in #186, do not re-report.** The token
file is read by a Rust loader and a Bun one, and their defaults disagreed in four ways, each
found as a separate review finding:

- `str::trim` and `String.prototype.trim` strip different sets. Unicode `White_Space` includes
  U+0085 and excludes U+FEFF; JavaScript's `WhiteSpace` is the reverse on both. A U+FEFF-only file
  was a credential to the gateway and an empty file to `@honmoon/api`; U+0085 the other way.
  Both now apply the union explicitly — `is_token_padding`/`trim_token` (mgmt_token.rs), `trimToken`
  (auth.ts, exported and also used by `routes.ts`'s `createFetchHandler` guard), and the same
  predicate spelled out at the `AppState` assert. JS `\s` already covers U+FEFF, so only U+0085
  is added there.
- Malformed UTF-8: Rust's `read_to_string` errors, Bun substitutes U+FFFD — a *predictable*
  token anyone could present. `readTokenAndMode` now decodes with `TextDecoder(…, {fatal:true})`.
- Windows: Rust's `random_bytes` bails off Unix, Node's does not. `auth.ts` now refuses to
  *generate* on `win32` too (reading an operator-placed token still works, as in Rust). The ACL
  residual is **#190**, not new.
- Directory mode: both create `0700` (`create_private_dir` / `mkdirSync`), and both report — never
  tighten — an existing directory writable beyond its owner, on the persisted-read path, the
  race-adopt path, and after create. Directory *write* permission is the exposure the file's read
  bits cannot see: substitute a `0600` file and the file check approves it.

**Also settled in #186, do not re-report:** the startup banner maps a wildcard bind to loopback
(`dashboard_authority`) rather than advertising `http://0.0.0.0:…`, and percent-encodes the token
so an operator-chosen `&`/`#` does not truncate the query; the token never reaches argv (the run-honmoon driver
passes `HONMOON_MGMT_TOKEN`, and the flag docs say why the variable is preferred); the startup
banner prints the token only when stderr is a terminal; `write_secret_file` chmods `0600` before
writing, so a replaced placeholder cannot keep a loose mode.