---
name: pr194-session-secret-port-scope
description: 'PR #194 (issue #188) replaced the honmoon_session cookie with a session secret delivered in /login''s redirect fragment, held in origin-scoped sessionStorage, sent as X-Honmoon-Session — README, wiki/deep-dive/control-plane.md (incl. its lib.rs line-number citations), egress-gateway.md, quick-start.md, SKILL.md, AGENTS.md, vite.config.ts, auth.ts, and all three touched .claude/agent-memory notes (pr186_mgmt_token_auth.md, mgmt-api-auth-model.md, pr186_warn_if_readable_beyond_owner.md) verified accurate against lib.rs/session.ts/api.ts in the round this note was written; the FRAME_ANCESTORS_NONE constant it named was renamed DASHBOARD_CSP in #195'
metadata:
  type: project
---

PR #194 deleted `same_origin()`, the `Credential` enum, and `pub const SESSION_COOKIE`; added
`pub const SESSION_HEADER = "x-honmoon-session"`. `/login` now redirects to `/#session=<secret>`
(fragment, never sent to a server) instead of setting `Set-Cookie`. `apps/dashboard/src/session.ts`
reads the fragment via `captureSession()` (called from `main.tsx` before first render), stores it in
`sessionStorage` (origin-scoped: scheme+host+port), and `api.ts`'s `sessionHeaders()` attaches it as
`X-Honmoon-Session` on every fetch. `X-Frame-Options: DENY` / `frame-ancestors 'none'` are unchanged —
still served on the static shell, from both arms of `static_handler` (the asset arm and the
`index.html` SPA fallback). **The constant they came off is no longer
`FRAME_ANCESTORS_NONE`**: issue #195 widened the policy past framing and renamed it
`DASHBOARD_CSP`, so grep for that (or for `CONTENT_SECURITY_POLICY`) rather than the old symbol.
Find them that way rather than by line: they sit near the end of `lib.rs`, so any edit earlier in
the file moves them.

Verified: no stale "cookie" doc anywhere (grepped whole repo, excluding target/node_modules) — the
remaining `Cookie`/`Set-Cookie` mentions are the unrelated wire-header-redaction category in
README.md/body.rs/ADR-0009, and deliberate historical references inside e2e.rs's kept-for-negative-
testing `set_cookie` helper. Login sets no cookie (verified: `login()` in lib.rs builds only
`LOCATION`+`CACHE_CONTROL`, no `SET_COOKIE`). Neither honmoon-mgmt nor `packages/api` logs request
lines or query strings (only `tracing::info!(%addr, "management API listening")` and two banner
`console.log`s). `packages/api/src/auth.ts`, `routes.ts`, `index.ts` have no cookie/login code path
— bearer only, confirmed by reading all three files.

Wiki line-citations the PR updated (`lib.rs:462-489` → `authorized()`, `lib.rs:544-574` → `login()`,
`lib.rs:393-418` → `SESSION_HEADER`) point at the right functions after the rename from
`session_cookie_value`/`session_cookie` to `session_secret`/`presented_session`. They were corrected
once mid-PR when later commits grew those doc comments — **a line range verified against an
intermediate head is not verified**, so re-check them against the final head, not against the
revision you reviewed.

A calibration point for clean PRs, following [[pr186-mgmt-token-auth]] and
[[honmoon-crate-table-convention]]'s general pattern: when the PR's own description enumerates
every doc site touched, checking each one against the diff is fast and (here) turned up nothing.
