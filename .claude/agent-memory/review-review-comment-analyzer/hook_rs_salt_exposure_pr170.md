---
name: hook-rs-salt-exposure-pr170
description: honmoon-cli hook.rs SaltExposure/SaltProvenance doc claims in PR #170 (issue #143) — three quantifier defects, all fixed before merge; the check that caught them is cheap to repeat
metadata:
  type: project
---

PR #170 (`crates/honmoon-cli/src/hook.rs`, issue #143) added `SaltExposure`
(Open/Closed) and `SaltProvenance` (FromFile/FreshlyWritten) plus rewrote
`MachineKeyStatus::persisted` and `restrict_to_owner_only` docs. Three prose
defects found, **all fixed in-PR** — recorded for the pattern, not as open
findings. Same recurring class as [[pr163_audit_sink_comment_claims]] and #150:
an absolute claim in prose that a nearby branch contradicts.

1. **"Two occasions/instants" overclaim (fixed).** Both `MachineKeyStatus::persisted`
   and `restrict_to_owner_only` stated a uniform count of 2. The body contradicted
   it: `SaltProvenance::FreshlyWritten` sets `found = None` without calling
   `mode_of` (one instant), and `publish_secret_atomically`'s winner path passes
   `None` without calling `restrict_to_owner_only` at all (zero). Both docs now
   scope the count to the provenance and say `None` is the same value for all
   three cases.
2. **`write_secret_file`'s "(a short/corrupt file no loader ever adopted as a
   key)" (fixed).** Its single call site is reached from the short-bytes arm AND
   from `Err(e) if e.kind() != NotFound`, where contents and length were never
   read — so "short/corrupt" mischaracterised it and "no loader ever adopted it"
   was asserted rather than provable. The prose now splits the two arms and files
   the replaced key's unrecorded exposure as #171.
3. **`packages/policy/src/index.ts` "on all three of those rules the provenance is
   genuinely fine" (fixed).** One of the three named is `hook-salt-fallback`,
   where provenance is exactly what is broken — self-contradicting within its own
   paragraph, from an editing slip off the pre-PR singular "on that rule".

**The durable lesson.** When a PR adds a second variant or branch to an existing
binary condition (Open/Closed, one rule to two), re-check every doc comment that
made a "the only way this happens" or "N instances" claim about the old case.
Those numbers and scopes go stale silently — nothing fails to compile, and the
sentence still reads as settled reasoning. Grepping the diff for bare numerals and
for "both"/"either"/"only" near a changed enum found all three of these.
