---
name: pr193-compiled-conditions-claims
description: "A correct performance number can be glued to the wrong verb — PR #193 justified compiling CEL at load with a per-request cost that was real for evaluation and not for compilation, so check the operation a \"used to cost N\" claim names, not just the count"
metadata:
  type: feedback
---

PR #193 (issue #167) moved CEL rule-condition compilation from every `decide` call to
`Policy::from_yaml`. Its `CompiledConditions` doc justified the move with: "the compile is CEL
parsing, and it used to run once per endpoint-matching rule per request — twice for a rule that
reaches `pii_caused`."

The count was real and attached to the wrong operation. Pre-PR, `Program::compile` ran exactly
**once** per matching rule — the comment directly above the call site said so ("Compiled once and
reused for the attribution check below") — and it was `eval_program` that ran twice, on the
already-compiled `Program`. The same file's untouched `stdlib_env` doc states the distinction
correctly two paragraphs earlier.

**Why this one is easy to miss:** the "twice" came from issue #167's own body, which makes the same
conflation, so the claim arrived pre-blessed by the ticket and was repeated into the doc comment,
the commit message and the PR body before anyone checked it. A number inherited from an issue is
not evidence; the call site is.

**How to apply:** on any change justified by "this used to run N times per X", find the call site
and confirm which operation the N counts. A neighbouring correct claim about a *different*
operation with the same N is the tell — that is where the number gets borrowed from. Check the
same claim in every place the PR states it: doc comment, commit message, and PR body are three
separate copies, and fixing one does not fix the others.

**All three defects this note came from were fixed on PR #193 before merge** — do not re-report
them against current `main`:

1. The compile-vs-evaluate conflation above.
2. `program_for`'s doc claimed a policy whose `condition` was reassigned after load "carries an
   empty table"; only that one key misses, and every other rule still hits. "One key misses"
   inflated to "the table is empty".
3. `compile_condition`'s pre-existing "A policy that reached here was built in code rather than
   loaded" was true of the blank arm only. The PR made `CompiledConditions::compile` a second
   caller, so a *loaded* policy reaches the failed-compile arm for a non-blank malformed condition
   like `"&&"`. The PR did not create the imprecision but did make it false, and split the two
   arms' framing apart.

No line-anchor list here on purpose: an earlier draft recorded that the wiki's `engine.rs`/`lib.rs`
citations "matched exactly", and later commits on the same PR shifted every one of them. See #192.
