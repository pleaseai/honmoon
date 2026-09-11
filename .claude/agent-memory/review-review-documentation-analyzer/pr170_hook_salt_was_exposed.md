---
name: pr170-hook-salt-was-exposed
description: PR #170 (issue #143) hook-salt-was-exposed docs — I verified the "two instants" claim as exact and it was false; the TS enumeration-count miss is the transferable check
metadata:
  type: project
---

PR #170 added the `hook-salt-was-exposed` degraded audit rule (the loader found the salt
file loose, tightened it, and records the modes it saw). Two things to carry forward, and
the first is a correction to my own pass.

**I reported the "two instants the loader looked" claim as matching the implementation
exactly. It did not.** The comment analyzer and the security reviewer both showed that
only `SaltProvenance::FromFile` looks twice: `FreshlyWritten` skips the pre-`stat`
entirely, and `publish_secret_atomically`'s winner path never calls
`restrict_to_owner_only` at all. I had read the doc against `restrict_to_owner_only`'s
happy path and stopped, which is how a claim about *every* path gets confirmed from one.
The docs were corrected in-PR to scope the count to the provenance.

This is the same failure as [[pr150_adr0009_body_only_contract]], one PR later: a
universally-quantified sentence checked against a single branch. The check that works is
mechanical — for a claim of the form "N instants" or "every X", enumerate the call sites
and branches first, then read the claim against the list, rather than reading the claim
and looking for a confirming path.

**The TS mirror miscount (real, fixed).** `packages/policy/src/index.ts` (TD-001
hand-kept mirror of `crates/honmoon-core/src/audit.rs`) said "on all three of those rules
the provenance is genuinely fine" where only two rules carry `key_source: 'persisted'` —
`hook-salt-fallback` never does. The Rust side correctly said "Both". Worth grepping
`index.ts` against `audit.rs` for enumeration **counts** specifically, not just for the
presence of the same facts: the drift can be a wrong number while both sides name the
same rules.

**Still true after the fixes:** the README's example `reason` string, the rule-table
remedies, and the "one event per loose-find" claim all match the implementation (the last
one now scoped in-PR to where the correction took, since the unconfirmed-read-back arm
can repeat). No `wiki/` page or other repo doc mentions the salt rule names, so this
change triggers no `wiki/AGENTS.md` regeneration obligation — re-verified against the
merged head.
