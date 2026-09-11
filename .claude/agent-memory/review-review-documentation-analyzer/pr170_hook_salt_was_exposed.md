---
name: pr170-hook-salt-was-exposed
description: PR #170 (issue #143) hook-salt-was-exposed docs — universally-quantified claims verified from one branch and found false twice; the reusable check is that a self-clearing trigger breaks prose written for persistent ones
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

**A third rule whose trigger self-clears broke two more README claims (both fixed).** The
page's visibility section promised that a hook-side degradation "still reaches the
dashboard on any host that runs a gateway, because the trigger is shared" — true for
`hook-salt-fallback` and `hook-salt-exposed`, whose conditions persist until an operator
acts, and false for `hook-salt-was-exposed`. Both processes run the same loader
(`crates/honmoon-cli/src/main.rs:387` calls `hook::machine_key()` at gateway startup), so
whichever reaches a loose salt first tightens it and the other reads `0600` and records
nothing: hook-first means the event exists only in the JSONL sink. The other was my own
new prose describing the unconfirmed arm as a loader that "cannot see the file's
permissions at all", which the event contradicts — `found_exposure` only emits that
`reason` when the *pre*-correction read succeeded and was loose.

**The generalisation, and it is the useful part of this note.** When a change adds a
variant whose trigger is *consumed by observing it*, every surrounding sentence that
reasons from "the condition is still there when the next process looks" goes stale — and
those sentences do not mention the new rule by name, so a grep for the rule name misses
them. Enumerate the prose that argues from persistence, not just the prose that names the
thing you changed.

**Still true after the fixes:** the README's example `reason` string and the rule-table
remedies match the implementation, and the "one event per loose-find" claim is scoped
in-PR to where the correction took. No `wiki/` page or other repo doc mentions the salt
rule names, so this change triggers no `wiki/AGENTS.md` regeneration obligation —
re-verified against the final head.
