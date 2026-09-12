---
name: mgmt-api-auth-model
description: 'How the honmoon management API authenticates after #173 and #188 — mandatory Arc<str> token, nested /api router + route_layer, and the browser credential that is now an origin-scoped session secret in the X-Honmoon-Session header (NOT a cookie; same_origin() and the Credential enum were deleted with it, so do not report them as missing), how the Rust and Bun loaders were made to agree on what counts as a token, and which constant-time/route-ordering questions are settled so they are not re-derived'
metadata:
  type: project
---

Settled facts about `crates/honmoon-mgmt/src/lib.rs` auth (PR #186 / issue #173, then issue
#188). Re-verify against the file before citing, but do not re-derive these from scratch.

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
- Failed `GET /login` answers 401 with no redirect; success sends `Cache-Control: no-store`.
- `presented_session` uses `HeaderMap::get` (first value), not `get_all`, so a duplicated
  session header is not reconciled — deliberate.

**There is no session cookie any more (#188) — this is the part most likely to be
mis-reported.** The browser credential is a session secret (still
`hex(HMAC-SHA256("honmoon-mgmt-session-v1", token))`) that `GET /login?token=…` hands over in the
fragment of its `303` to `/#session=<secret>`; `apps/dashboard/src/session.ts` reads it from
`location.hash`, clears the hash with `history.replaceState`, keeps it in `sessionStorage`, and
`api.ts` attaches it as `X-Honmoon-Session` on every call. `/login` sends **no** `Set-Cookie`, and
`authorized()` accepts **no** cookie.

Why, so it is not re-litigated: a cookie's scope has no port (RFC 6265 §8.5) and "site" ignores
port too, so `honmoon_session` travelled to every `127.0.0.1:<port>` the operator's browser
touched — a listener another local user stood up could harvest it and replay it off-browser for
reads *and* the approval writes. No header check could close that (each presupposes a browser at
the other end, which is the assumption a replay breaks). `sessionStorage` is keyed by the full
origin, port included, so there is nothing for a sibling port to be sent or to read.

**Deleted with the cookie — absent by design, do not report as missing:**
- `same_origin()` and the whole `Sec-Fetch-Site`/`Origin`-vs-`Host` check, and the `Credential`
  enum that selected it. Neither credential is ambient now — a browser attaches `Authorization`
  or `X-Honmoon-Session` only because the page's script set it, and a cross-origin `fetch` that
  sets either is held behind a CORS preflight this service never answers — so there is no
  browser-provoked request left to tell from a deliberate one. `authorized()` returns `bool` and
  its doc comment states the condition under which the check would have to come back: any
  credential a browser attaches by itself.
- The `SESSION_COOKIE` public constant (replaced by `pub const SESSION_HEADER`, lowercase because
  `HeaderMap` lookups normalise that way).
- Tests `a_cookie_authenticated_write_from_another_origin_is_refused`,
  `a_cookie_replayed_without_browser_labelling_cannot_write`,
  `the_origin_fallback_decides_a_cookie_write_when_fetch_metadata_is_absent` and
  `a_forged_session_cookie_reads_no_data`. Their subject is gone; the stronger property is pinned
  by `no_session_cookie_is_a_credential_so_a_sibling_port_has_nothing_to_harvest` (the genuine
  secret in a `Cookie` header is 401 on every read and on the approval write, which stays pending),
  `the_dashboard_load_path_reads_every_route_with_its_session_header` (`/login` sets no cookie),
  `a_session_header_write_needs_no_browser_labelling` and `a_forged_session_header_reads_no_data`.

**Still true, do not re-report:**
- `static_handler` serves `X-Frame-Options: DENY` and `Content-Security-Policy:
  frame-ancestors 'none'`. Keep it: the dashboard's own script now holds the credential, so this is
  the guard against UI redress rather than a layer over an ambient cookie.
- DNS rebinding stays closed: a rebound page has its own origin's (empty) `sessionStorage` and
  nothing is attached ambiently.

**Residuals after #188** (documented in `session.ts`, `control-plane.md` and the PR, so report
only a *change* in them): the secret is script-readable where the cookie was `HttpOnly`, so a
script injection in this origin could exfiltrate a replayable credential rather than only act
while the page is open; `sessionStorage` is per tab, so a new tab is signed out until the login URL
is opened there; revocation is still rotating the token; and the token still rides in `/login`'s
query string (same-user exposure, `no-store`, nothing logged). `packages/api` was deliberately
untouched — bearer only, no browser client, nothing to harvest.

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