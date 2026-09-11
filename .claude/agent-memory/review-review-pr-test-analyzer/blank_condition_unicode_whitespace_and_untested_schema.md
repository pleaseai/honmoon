---
name: blank-condition-unicode-whitespace-and-untested-schema
description: honmoon-core's trim()-based blank-condition check catches Unicode whitespace (U+00A0/U+3000) and has tested it since PR #155, but deliberately not zero-width characters (U+200B/U+FEFF), which still panic — any unlexable char panics alike (#154), so do not ask for them to be folded in; policy.schema.json still has no consumer or test in-repo (filed as #157)
metadata:
  type: project
---

Written while reviewing PR #155 (the #151 blank-condition fix) and **corrected against that PR's
final head** — the first two drafts of this note were overtaken by fixes made during the review.

## The whitespace boundary, and where it actually falls

`is_blank_condition` (`crates/honmoon-core/src/lib.rs`) is `condition.trim().is_empty()`, so it
follows Rust's `char::is_whitespace` (the Unicode `White_Space` property). U+00A0 and U+3000 are
`White_Space`, so they *are* caught — and PR #155 pins both, at the loader and in the engine, so
an ASCII-only narrowing of the check fails the suite (verified: narrowing it turns
`rejects_a_rule_with_a_blank_condition` and `a_blank_condition_declines_instead_of_panicking` red,
the second with the real antlr panic). **Do not report those as untested; they are.**

What is *not* caught is the interesting part. U+200B, U+FEFF, U+2060, U+00AD and friends are not
`White_Space`, so a condition made only of them is not blank by this test, loads cleanly, and
panics in `Program::compile` at request time — the original #151 failure mode, for input that
renders as empty in an editor.

**This is deliberate, and the reasoning is the thing to remember.** It is not a missed case. The
compiler panics on *any* single character it cannot begin a token with — measured on
cel-interpreter 0.10: `"@"`, `"$"`, `"#"`, `` "`" ``, `"§"`, `"€"`, an emoji and a lone CJK
character all panic exactly as `""` does, while `"x"` and `"_"` compile fine. So U+200B panics for
the same reason `"@"` does, and a check that caught the invisible ones would be drawing a line the
compiler does not draw. The whole class is #154. Anyone proposing "just also strip zero-width
characters" should read that probe first — it fixes one arbitrary slice of a much larger set and
buys a false sense of coverage.

## The schema has no enforcement path — now filed

`packages/policy/schema/policy.schema.json` is exported (`"./schema"` in `package.json`) but has
no consumer: the only place that wants it is a TODO at `packages/cli/src/index.ts:20` ("parse YAML
+ validate against @honmoon/policy/schema"), and `packages/policy` contains no test files at all.
So a schema constraint that is wrong, over-strict, or out of step with the Rust loader passes CI
untouched. That matters more since #155, which made the two deliberately-near-identical validators
of the same field while documenting that they disagree on U+FEFF and U+0085 — a divergence held in
place by nothing but a comment.

Filed as #157. Related but broader: #42 (TD-001) would generate both models from the schema and
supersede it.

**How to apply.** For a PR touching trim-based blank checks in this crate, confirm Unicode
whitespace is exercised (it is today) and do **not** ask for zero-width characters to be folded
into the same check — point at #154 instead. For a PR touching `policy.schema.json`, note that no
test in this repo will catch a broken schema until #157 or #42 lands, so the review is the only
gate.
