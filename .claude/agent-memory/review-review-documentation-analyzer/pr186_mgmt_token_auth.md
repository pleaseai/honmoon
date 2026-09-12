---
name: pr186-mgmt-token-auth
description: PR #186 (issue #173) mgmt-token auth docs — README/wiki quick-start/egress-gateway/control-plane's own "every /api route gated" section, SKILL.md, claude-plugin README all verified accurate against mgmt_token.rs/lib.rs/auth.ts; the one gap was control-plane.md's PRE-EXISTING `@honmoon/api` route table (untouched by this diff) still describing /api/audit and /api/audit/stats with no auth note, even though packages/api/src/routes.ts (same PR) gates both
metadata:
  type: project
---

PR #186 made the management token mandatory on every `/api` route (crates/honmoon-mgmt/src/lib.rs,
`require_credential` middleware) and on `@honmoon/api`'s two routes (packages/api/src/routes.ts,
`isAuthorized` gate, tested in routes.test.ts). It renamed `--hook-token`/`HONMOON_HOOK_TOKEN` to
`--mgmt-token`/`HONMOON_MGMT_TOKEN` with the old flag kept as a deprecated alias
(`mgmt_token.or(hook_token)` — new flag wins), added a `/login?token=…` → `Set-Cookie: honmoon_session`
→ `303 /` flow, and left `/healthz` and the static dashboard shell open by design.

Verified accurate: README.md's mint-path/login-URL blurb, wiki/getting-started/quick-start.md's
`open .../login?token=$(cat ~/.honmoon/mgmt-token)` recipe, wiki/deep-dive/egress-gateway.md's
`--mgmt-token` flag-table row (audit/approval/policy/hook endpoint enumeration matches the five
`/api/*` routes in lib.rs exactly), packages/claude-plugin/README.md's `hookToken` "Required as of
0.1.0" note (0.1.0 matches root Cargo.toml `version = "0.1.0"`), apps/dashboard/AGENTS.md's
`/api`+`/healthz`+`/login` vite proxy list (matches vite.config.ts), and .claude/skills/run-honmoon/
SKILL.md's `run-honmoon-driver-token` claim (matches driver.mjs `MGMT_TOKEN` default literal).

The one finding: wiki/deep-dive/control-plane.md's new section (lines ~94-100, touched by this PR)
correctly documents the dashboard's session-cookie flow and says "Every `/api` route requires the
management token" — but the pre-existing "`@honmoon/api` — the durable audit-query layer" section
further down (route table for `GET /api/audit`, `GET /api/audit/stats`, `GET /healthz`) was NOT
touched by this diff and still lists those routes with no auth column/note, even though this same
PR added the gate (packages/api/src/routes.ts, packages/api/src/index.ts's own doc comment says
"Every route but `/healthz` requires the management token"). Lesson: when a PR changes auth on an
already-documented route table, check every doc section that enumerates those routes, not just the
section the PR's own diff touches — drift between a freshly-accurate section and a stale sibling
section in the *same file* is easy to miss because the file shows up as "changed" in the diff stat.
