---
name: pr197-program-for-dead-arm
description: "A doc saying 'this arm exists for scenario Y' is checked by grepping every assignment site of the state Y needs — PR #197 claimed program_for's recorded-failure arm served 'policies whose table was not built by the loader' when no such Policy can exist; found and fixed in-PR, and the fix is the model answer"
metadata:
  type: feedback
---

**Status: found on PR #197 (issue #191) and fixed before merge.** The text quoted below is *not*
in the tree — do not flag `program_for`'s doc for it. What survives is the check that caught it.

## The claim, and why it was wrong

PR #197 added prose to `program_for`'s doc in `crates/honmoon-core/src/engine.rs`: "A **hit** on a
recorded failure declines the same way, and that is the arm this keeps for policies whose table was
not built by the loader."

Traced every place `Policy.compiled` (private, `#[serde(skip)]`) is assigned:
`grep -rn "\.compiled = " crates/honmoon-core/src/*.rs`. At the time, one write —
`policy.compiled = engine::CompiledConditions::compile(&policy.rules)` inside `from_yaml`, which
since #191 runs `validate_compiled_conditions` immediately after and refuses the policy if any
entry is `None`. Every other `Policy` (struct literal, `..Default::default()`, deserialized) gets
an *empty* table — a **miss**, not a hit on a recorded failure. So the sentence was wrong twice
over: the scenario it named produces the other arm, and no `Policy` could reach the arm at all.

**That grep now returns two**, and the second one is worth understanding rather than filtering out:
`engine.rs`'s own `a_recorded_compile_failure_in_the_table_declines` writes `policy.compiled`
directly. It is the pin-test the fix added, and it exists *because* the state is otherwise
unreachable — reaching the arm at all required writing the field by hand. So the rule is "one
**production** writer, in `from_yaml`, which validates"; a test that assigns the field is evidence
for the invariant, not a counterexample to it. Scope the grep to non-`#[cfg(test)]` code when
re-running it (caught by `cubic-dev-ai` on the PR that added this note — the note had gone stale
against a commit in its own PR, which is the failure mode the note is about).

## Why it was easy to miss

The claim is not factually reversed — a recorded-failure hit really would decline, mechanically. It
is a "this arm still serves purpose X" rationale where X has no live instance. Same shape as
[[guard-unnecessary-doc-comment]] and the PR #147 flush-debt precedent: the reasoning reads as
settled, so the question to ask is whether the described case can be *constructed*, not whether the
described behaviour would be correct if it could.

## What the fix looked like — this is the part to reuse

The author did not delete the arm or the prose. They:

1. Rewrote the doc to say plainly that no `Policy` can present this state, naming the reason (one
   private field, one writer, and that writer refuses), rather than inventing a caller for it.
2. Kept the arm, justified on what it actually buys: the invariant is one private field away from a
   future change, not a type-level guarantee, so the arm is what a second writer of `compiled`
   would meet instead of an uncompiled program.
3. Added `a_recorded_compile_failure_in_the_table_declines` (engine.rs), which writes the table by
   hand and asserts the arm declines — turning "kept defensively" from a claim about untested code
   into a pinned behaviour.

**How to apply:** when a doc says "this arm exists for construction/scenario Y", grep every
assignment site of the state Y depends on before accepting it. A private field with exactly one
*production* write site, guarded by validation, is the tell — count test writers separately, since
a test that constructs the state by hand is usually there precisely because nothing else can. And when the answer is "unreachable",
the fix is (1) say so, (2) say what keeping it buys, (3) pin it with a test — not silent deletion
and not a rationale that names a caller who does not exist.
