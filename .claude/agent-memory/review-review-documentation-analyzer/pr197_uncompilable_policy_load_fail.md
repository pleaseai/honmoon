---
name: pr197-uncompilable-policy-load-fail
description: "PR #197 (issue #191) made an uncompilable CEL rule condition a load failure; the wiki/schema/JSDoc claims all verified against lib.rs/engine.rs, but two later in-PR commits changed the error format and the preflight advice — the re-read against the final head is what caught it"
metadata:
  type: project
---

PR #197 (issue #191) changed `Policy::from_yaml` so a rule `condition` the CEL compiler rejects
fails the load (`Error::UncompilableRuleConditions`, naming every offending rule by index/name/
condition text) instead of loading the policy with the rule silently inert.

Verified in this review, all correct:
- Re-anchored citations all point at exactly the code the prose describes. **Re-checked at the
  final head:** the engine.rs ones moved again when later commits in the same PR edited
  `program_for`'s doc and added a test, so the merged values are lib.rs:199-224, lib.rs:292-337,
  engine.rs:185-285, engine.rs:287-319, engine.rs:321-353, engine.rs:398-444. A commit that only
  touches *doc comments* shifts every anchor below it just as a code commit does — which is the
  argument #192 makes for dropping line anchors, and the reason to recompute them last rather than
  when the prose is written.
- The sample error message in policy-authoring.md's warning box matches `UncompilableRule`'s
  `Display` impl exactly for that name/index/condition. **Re-checked at the final head:** both
  changed after this note was first written — greptile found that backticks render an
  invisible-character condition as an empty pair, so `Display` now uses `{:?}` for both
  author-written values, and the box now reads:

  ```
  Error: rule "secrets" (rules[1]) has a `condition` that is not a valid CEL expression: "&&"
  ```
- All four named tests exist under the exact names claimed and assert what the prose says:
  `unknown_fact_reference_does_not_match`,
  `a_condition_that_does_not_compile_fails_the_load_for_the_whole_policy`,
  `names_every_rule_whose_condition_does_not_compile`, `a_blank_condition_is_still_reported_as_blank`.
- `wiki/llms-full.txt` regenerates byte-identical via `node wiki/.vitepress/gen-llms-full.mjs`
  (see [[pr193_cel_compile_at_load_diagram]] for the sibling PR that first re-anchored this same
  diagram — #197 continued that anchor-hygiene pattern correctly).
- packages/policy/schema/policy.schema.json's `description` and packages/policy/src/index.ts's
  JSDoc for `condition` both updated in lockstep to say the loader now catches it, matching the
  TD-001 mirror convention (see [[pr174_reason_absolute_path_td001_gap]]).
- No `^#[0-9]` markdown lint trap (see [[honmoon-md-issue-ref-lint]] in the global memory) in any
  changed wiki file.
- Grepped wiki/, README.md, ARCHITECTURE.md, .please/docs/, packages/ for other "loads and warns"
  language; the only hit was `.please/docs/tracks/completed/phase-2-cel-http-facts/spec.md` (a
  historical completed-phase spec predating #191, out of this diff's scope — not flagged).

Zero findings **from the docs angle, at the head this ran against** — and the page changed twice
afterwards in the same PR: the error format above, and the removal of a "to check a policy, load
it: `honmoon gateway --config <file>`" line that greptile and the security finder independently
flagged (it is not a dry run — on a valid policy it serves, and it resolves the mgmt token first).
#198 tracks the load-and-exit mode the page now points at.

**The lesson is the re-read, not the clean result.** A docs verification is only true of the head it
ran against, and on this PR the docs kept moving after it. Re-run the sample-output and command
claims against the final head before trusting a "docs verified" note — quoted program output and
"run this to check" instructions are the two that drift, because a later commit changes the program
rather than the page. See [[honmoon-md-issue-ref-lint]] for the other trap on this page.
