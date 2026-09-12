---
name: pr174-reason-absolute-path-td001-gap
description: 'PR #174 (issue #162) made hook.rs resolve the salt dir to absolute before it reaches `reason`, and added rustdoc to RedactionFacts::reason explaining the deliberate-untrim decision and pointing at #173 (since closed — the management reads are token-gated, do not report them as open) — README examples/prose stayed accurate (honmoon_dir() itself is unchanged, still relative when HOME is unset), and packages/policy/src/index.ts''s `reason` JSDoc was missing the mirror — the same TD-001 mirror-drift class pr170 found for a miscount, FIXED in #174 after review'
metadata:
  type: project
---

**What changed.** `load_or_create_machine_salt` now calls `absolute_salt_dir(dir)` (lexical
`std::path::absolute`, not `canonicalize`) before building the `hook-salt` path, so a
`HOME`-less hook's `reason` names an absolute (CWD-resolved) path instead of an unresolvable
relative `.honmoon/hook-salt`. `crates/honmoon-core/src/audit.rs` gained substantial new
rustdoc on `RedactionFacts::reason`: the field is "deliberately untrimmed" (issue #162), the
path is resolved before the string is built (not *unconditionally* absolute — the
unreadable-cwd fallback is #176), and the real fix for the then-unauthenticated
`GET /api/audit` exposure was tracked as #173 — **since closed, so that route is token-gated
now and must not be reported as open**. The settlement is scoped to this content — a local salt path and
an OS error — not to the field, so a future producer putting something else in the same
`String` is still reportable.

**What did NOT need to change and I verified this.** `honmoon_dir()` (`hook.rs:124`) itself is
untouched — it still returns a relative `.honmoon` when `HOME` is unset; only how
`load_or_create_machine_salt` *renders* that directory in `reason` changed. So
`packages/claude-plugin/README.md` line 240 ("A process with no `HOME` reads a `.honmoon`
relative to its working directory") is still true about file *location* and needed no edit.
The README's example `reason` strings (lines 305, 323) already showed absolute paths
(`/home/a/.honmoon/hook-salt`), consistent before and after this change, since the HOME-set
case was already absolute — the fix only touches the HOME-unset edge case, which the README
never showed an example for. No AGENTS.md/ARCHITECTURE.md/CLAUDE.md mentions `reason` or the
audit event shape at all, so no drift there. No wiki page mentions the salt rule names (holds
from [[pr170_hook_salt_was_exposed]]), so no wiki regeneration obligation.

**The gap, found here and FIXED in this same PR: `packages/policy/src/index.ts`'s
`RedactionFacts.reason` JSDoc (~line 126-131) carried none of the new rustdoc content** —
neither the "deliberately untrimmed" decision, nor the path-resolution note, nor the #173
pointer had reached the TS side, even though
[[pr170_hook_salt_was_exposed]] already established that TD-001's "keep @honmoon/policy in
lockstep with the Rust model" (`packages/AGENTS.md` lines 23, 43; `AGENTS.md` line 98) is read
by this project to include doc-comment content on `RedactionFacts`, not just field shape —
a prior PR's miscount in this exact comment block was flagged and fixed in-PR. It mattered
more on the TS side than the Rust side: `apps/dashboard` is where the "do not trim this
field" guidance is most actionable. The TS JSDoc now carries the untrimmed-by-design
decision, the renderers-must-not-summarise rule, and the #173 pointer — **so this is closed,
not open; do not re-report it.**

**Why:** Verifying PR #174 (issue #162) documentation. Confirms the TD-001 mirror-drift
category from pr170 recurs, and confirms honmoon_dir()'s relative-fallback README claim is
about file location, not reason-string rendering — don't conflate the two when checking
future salt-path changes.

**How to apply:** On any future change to `RedactionFacts::reason`'s rustdoc in
`crates/honmoon-core/src/audit.rs`, diff the same paragraph against
`packages/policy/src/index.ts`'s JSDoc before clearing the PR — treat missing sync as a TD-001
violation per the project's own AGENTS.md wording, not as an optional nice-to-have.
