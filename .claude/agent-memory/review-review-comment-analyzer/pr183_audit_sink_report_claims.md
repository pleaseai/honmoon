---
name: pr183-audit-sink-report-claims
description: "PR #183 (issue #161) audit-sink report-don't-enforce doc claims across audit.rs, index.ts, format.ts, README — every behavioral/ordering/issue-number claim checked out except one pre-existing citation quirk copied into new text"
metadata:
  type: project
---

PR #183 added ~370 lines of doc comments to `crates/honmoon-core/src/audit.rs`
(`AuditSinkFacts`, three `AUDIT_SINK_*_RULE` consts, `with_file`, `open_sink`,
`observe_sink`, `sink_exposure`) plus mirrors in `packages/policy/src/index.ts`,
`apps/dashboard/src/format.ts`, `packages/claude-plugin/README.md`, and a rewritten
memory note. Verified against code, ran `cargo test -p honmoon-core --lib audit::`
and `--test audit_sink_exposure` (25 + 4 pass) and `bun test format.test.ts` (5
pass), and checked every cited issue number with
`gh api repos/pleaseai/honmoon/issues/N`. **All behavioral claims held**: id
ordering (observation recorded before the caller's event, verified via
`recent()` reversal), event-per-observation fan-out (a loose+hard-linked sink
reports twice, mode first), `record`'s swallow-and-warn semantics, the hook's
"only opens the sink when it has a degraded key" gate
(`audit_machine_key_status` returns early on `!status.is_degraded()`),
`require_link_in_a_trusted_directory`'s `st_mode`-only check backing the macOS
ACL gap (#181, open), and every cross-referenced issue's title/state
(#138/#179/#174/#141/#143/#170/#160/#137/#181 all matched their citation).

One recurring **pre-existing citation quirk, not introduced by this PR**: two
new comments cite "issue #131" for the claim that `honmoon hook` has no
`RUST_LOG` so `EnvFilter` drops a `tracing::warn!` before it's written. Issue
#131's own title and body are entirely about the public fallback-salt HMAC key
being a guess-confirmation oracle — no mention of RUST_LOG/EnvFilter anywhere
in it. But this exact citation already exists unchanged elsewhere in the repo
(issue #165's body, `packages/policy/src/index.ts`'s pre-existing
`RedactionFacts.reason` doc, `crates/honmoon-cli/src/hook.rs`), so it's an
established (if imprecise) convention this PR is copying, not a new error.
Low-confidence flag only; the pattern is copied verbatim, not authored fresh.
