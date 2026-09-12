---
name: pr186-mgmt-token-auth
description: 'PR #186 (issue #173) mgmt-token auth docs — README/wiki quick-start/egress-gateway/control-plane''s own "every /api route gated" section, SKILL.md, claude-plugin README all verified accurate against mgmt_token.rs/lib.rs/auth.ts; the one gap was control-plane.md''s PRE-EXISTING `@honmoon/api` route table (untouched by this diff) still describing /api/audit and /api/audit/stats with no auth note, even though packages/api/src/routes.ts (same PR) gates both'
metadata:
  type: project
---

PR #186 made the management token mandatory on every `/api` route (crates/honmoon-mgmt/src/lib.rs,
`require_credential` middleware) and on `@honmoon/api`'s two routes (packages/api/src/routes.ts,
`isAuthorized` gate, tested in routes.test.ts). It renamed `--hook-token`/`HONMOON_HOOK_TOKEN` to
`--mgmt-token`/`HONMOON_MGMT_TOKEN` with the old flag kept as a deprecated alias
(`mgmt_token.or(hook_token)` — new flag wins), added a `/login?token=…` → `Set-Cookie: honmoon_session`
→ `303 /` flow, and left `/healthz` and the static dashboard shell open by design.

**Superseded in part by #188:** that cookie is gone. `/login` now `303`s to `/#session=<secret>`
and the dashboard sends the secret as `X-Honmoon-Session` from origin-scoped `sessionStorage`
(`apps/dashboard/src/session.ts`). Everywhere the docs described a session cookie —
wiki/deep-dive/control-plane.md (both the `/api` gate paragraph and the dashboard-pipeline
section), wiki/deep-dive/egress-gateway.md's `--mgmt-token` row, wiki/getting-started/quick-start.md,
.claude/skills/run-honmoon/SKILL.md, apps/dashboard/AGENTS.md and vite.config.ts — was updated with
it. So a doc that still says "session cookie" is stale, not correct; the login *URL* is unchanged.

Verified accurate: README.md's mint-path/login-URL blurb, wiki/getting-started/quick-start.md's
`open .../login?token=$(cat ~/.honmoon/mgmt-token)` recipe, wiki/deep-dive/egress-gateway.md's
`--mgmt-token` flag-table row (audit/approval/policy/hook endpoint enumeration matches the five
`/api/*` routes in lib.rs exactly), packages/claude-plugin/README.md's `hookToken` "Required as of
0.1.0" note (0.1.0 matches root Cargo.toml `version = "0.1.0"`), apps/dashboard/AGENTS.md's
`/api`+`/healthz`+`/login` vite proxy list (matches vite.config.ts), and .claude/skills/run-honmoon/
SKILL.md's `run-honmoon-driver-token` claim (matches driver.mjs `MGMT_TOKEN` default literal).

The one finding, **FIXED in the same PR — do not re-report it**:
wiki/deep-dive/control-plane.md's new section correctly documented the dashboard's session-cookie
flow, but the pre-existing "`@honmoon/api` — the durable audit-query layer" route table further
down the *same file* still listed `GET /api/audit` and `GET /api/audit/stats` with no auth note,
even though this PR gated both. Both route tables in that file now state the credential they
require and name `/healthz` and the SPA shell as the deliberate exceptions.

Lesson worth keeping: when a PR changes auth on an already-documented route table, check every doc
section that enumerates those routes, not just the section the PR's own diff touches. Drift
between a freshly-accurate section and a stale sibling section in the *same file* is easy to miss,
because the file already shows up as "changed" in the diff stat and so reads as handled.

Also settled in this PR, so not open: the `--mgmt-token` flag row now says to prefer
`HONMOON_MGMT_TOKEN` (argv is readable by any local user via `ps`) and notes that `@honmoon/api`
cannot see the flag at all, so a flag-supplied token has to reach that service through the
variable or the file.
