---
name: mgmt-api-auth-model
description: 'How the honmoon management API authenticates after #173 — mandatory Arc<str> token, nested /api router + route_layer, the HMAC session cookie and its loopback-port scope gap, and which constant-time/route-ordering questions are already settled so they are not re-derived'
metadata:
  type: project
---

Settled facts about `crates/honmoon-mgmt/src/lib.rs` auth (PR #186, issue #173). Re-verify
against the file before citing, but do not re-derive these from scratch.

**Shape.** `AppState.mgmt_token: Arc<str>` is mandatory (asserted non-empty). `router()` builds an
inner `Router` of the six `/api` routes, applies `route_layer(from_fn_with_state(state,
require_credential))`, and `nest("/api", api)`. Outside the gate: `GET /healthz`, `GET /login`,
and the `static_handler` SPA fallback. Token resolution lives in `honmoon-cli/src/mgmt_token.rs`
(`$HOME/.honmoon/mgmt-token`, `O_CREAT|O_EXCL`, `0600`); `packages/api/src/auth.ts` reads the same
file for the TS audit server.

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
- `same_origin()` **refuses** a cookie-authenticated non-safe method carrying neither
  `Sec-Fetch-Site` nor `Origin` — the shape of an off-browser replay. There is no permissive arm
  for writes any more. Pinned by `a_cookie_replayed_without_browser_labelling_cannot_write` and
  `the_origin_fallback_decides_a_cookie_write_when_fetch_metadata_is_absent`.
- `static_handler` serves `X-Frame-Options: DENY` and `Content-Security-Policy:
  frame-ancestors 'none'`, so the framed-shell variant is closed.
- Origin/Host compare case-insensitively (RFC 9110 §4.2).

What genuinely remains: a harvested cookie still **reads** (audit, policy, approvals) until the
token is rotated. Tracked as **#188** — report against that issue, not as new. The real fix needs
TLS on the management listener so the cookie can carry `Secure` + a `__Host-` prefix; dropping the
cookie instead would reopen the DNS rebinding it defeats by construction.

**Also settled in #186, do not re-report:** the token never reaches argv (the run-honmoon driver
passes `HONMOON_MGMT_TOKEN`, and the flag docs say why the variable is preferred); the startup
banner prints the token only when stderr is a terminal; `write_secret_file` chmods `0600` before
writing, so a replaced placeholder cannot keep a loose mode.