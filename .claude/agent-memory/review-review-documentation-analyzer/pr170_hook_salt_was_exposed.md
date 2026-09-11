---
name: pr170-hook-salt-was-exposed
description: PR #170 (issue #143) hook-salt-was-exposed docs — a single "reaches the dashboard on any host" guarantee took four rounds of valid findings, one unstated premise each (trigger semantics, which branch fires, path resolution, a concurrency race); narrow the claim rather than add qualifiers
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

**The visibility paragraph took four rounds of valid findings, and that is the datapoint.**
It promised that a hook-side degradation "still reaches the dashboard on any host that runs
a gateway, because the trigger is shared". Each round removed one unstated premise from that
one sentence:

1. It is false for `hook-salt-was-exposed`, whose trigger is *consumed by observing it*.
   Both processes run the same loader (`crates/honmoon-cli/src/main.rs:387` calls
   `hook::machine_key()` at gateway startup), so a correction that lands first leaves the
   other reading `0600` and recording nothing — the event then exists only in the JSONL sink.
2. My replacement described the unconfirmed arm as a loader that "cannot see the file's
   permissions at all", which the event itself contradicts: `found_exposure` emits that
   `reason` only when the *pre*-correction read succeeded and was loose.
3. "Both processes read the same `~/.honmoon/hook-salt`" is a premise, not a fact.
   `honmoon_dir()` (`hook.rs:124`) resolves each process's own `HOME`, else a CWD-relative
   `.honmoon` — the page documents this under "different key bytes break parity" and the new
   paragraph had asserted straight past it.
4. "The first to reach it tightens it" serialises an unsynchronised pair. `restrict_to_owner_only`
   stats *before* it chmods, so two overlapping loaders both observe the loose mode and both
   record; the witness claim has to be bounded on completion, not on start order.

**Two generalisations, and they are the useful part of this note.**

*On what to grep for.* When a change adds a variant whose trigger is consumed by observing
it, every surrounding sentence that reasons from "the condition is still there when the next
process looks" goes stale — and those sentences do not mention the new rule by name, so a
grep for the rule name misses them. Enumerate the prose that argues from persistence, not
just the prose that names the thing you changed.

*On when to stop qualifying.* Rounds 2-4 were all defects in prose written to fix the
previous round, each a real false claim and each found only after the fix shipped. A
sentence asserting a guarantee over "any host" invites one valid finding per round, because
every unstated premise is a counterexample and the reviewer needs only to name the next
one — and they are not all of a kind: these four were the trigger's own semantics, which
branch actually emits the event, how the path resolves per process, and a race between two
loaders. Adding a fifth qualifier is the wrong move — narrow what the
sentence claims (name the deployment it holds for and defer to the limitation section)
instead of enumerating the ways it fails.

**Still true after the fixes:** the README's example `reason` string and the rule-table
remedies match the implementation, and the "one event per loose-find" claim is scoped
in-PR to where the correction took. No `wiki/` page or other repo doc mentions the salt
rule names, so this change triggers no `wiki/AGENTS.md` regeneration obligation —
re-verified against the final head.
