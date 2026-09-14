---
name: pr242-hook-salt-adoption-pinned
description: "PR #242 (issue #126 stage 1) pinned hook-salt adoption as an interface; the 'whole of what parity takes' overclaim it introduced was found in review and narrowed before merge — do not re-flag it, and check the decision COMMENT on an issue before calling a PR's framing invented"
metadata:
  type: project
---

PR #242 added a rustdoc block to `load_or_create_machine_salt` (`crates/honmoon-cli/src/hook.rs`),
a module-doc paragraph to `crates/honmoon-core/src/hook_salt.rs`, and expanded
`packages/claude-plugin/README.md`'s "Getting one key onto both sides" section, plus four new
tests pinning the 16-byte floor, no-ceiling adoption, and cross-dir salt parity.

**Verified true, mechanically, against the code** (still true at merge): the `>= 16` floor
wording, "16 is a floor and not a size" / no truncation-padding-re-derivation (HMAC takes a key
of any length, and `a_salt_longer_than_a_generated_key_is_adopted_whole` proves no
normalisation), the three-arm "under 16 / absent / unreadable all mint a fresh 32-byte key"
claim (Corrupt/Unread/Absent all call `random_bytes(32)` once before the match), and "adopted
even when world-readable" (mode never gates whether `fs::read` adopts the bytes). All four
newly-named tests exist and pin exactly what they are cited for.

**The overclaim this PR introduced was fixed inside this PR — do not report it again.** The
rustdoc first read "identical bytes at each process's salt path is the whole of what parity
takes", which omitted the second salt input: `hook_salt_context` returns an operator-pinned
context when there is one and only otherwise the payload's `session_id`, so a gateway started
with `--hook-salt-context` and unpinned command hooks disagree on a matching key. The merged
text scopes the claim to what the loader itself contributes and names the context as a second
input that must agree. Same failure shape as [[docs-completeness-claim-unbounded-review]] and
[[pr170-hook-salt-was-exposed]]; the fix was to scope the claim, not to add a qualifier.

**The README's `0600` sentence took four rounds, and each round's wording was refuted by the
next — so read the merged text, not this note's account of any intermediate one.** It now says
`hook-salt-exposed` fires where the file is **still** readable beyond its owner afterwards; that
where the record *reaches* is per-transport (a gateway records into the ring its dashboard polls
with or without `--audit-log`, while `honmoon hook` needs `HONMOON_AUDIT_LOG`, or `--audit-log`
by hand, to outlive the process, and the dashboard never shows it); and that a `chmod` failing on
a file already at `0600` is deliberately silent. An earlier draft said the record "reaches you
only where an audit sink is configured" — **that is false for the gateway**, which builds an
`AuditLog::new(1024)` ring regardless, and it also contradicted this README's own "Where each
event is visible" section. Check any future wording against `restrict_to_owner_only`'s three
cases *and* against that section.

The same PR qualified the unforgeability claims on the README's provisioning section and on
`load_or_create_machine_salt`'s rustdoc — and, in the follow-up, `session_salt`'s — on the key
being unguessable and not merely secret. **That list is the claim; do not read it as "every
occurrence".** `session_salt`'s was missed on the first pass and found by codex on the follow-up
PR, so a fresh grep for "unforgeable" is still worth a pass rather than trusting this note. It
also added a **"Generate the bytes; do not choose them"** block
generating under `umask 077` and creating `~/.honmoon` before `install` (which does not create a
missing parent — the earlier recipe simply failed on a fresh host). Note what that block may
**not** say, because a draft did and it was wrong: a weak key provisioned in a *loose* file is
not accepted silently — the loose mode fires `hook-salt-was-exposed`. The true claim is narrower,
and is the one merged: every rule is about the file rather than the bytes, so a weak key in an
owner-only file draws nothing, key strength being the one property none of them inspects.

**A false positive worth remembering, because two reviewers hit it independently.** Both the
rustdoc and the README describe the first-class key input as "issue #126's second stage,
deferred to `honmoon join` (#37)". Reading issue #126's **body** alone makes that look invented
— the body only says the work is "worth deciding alongside #37". The **decision comment** on the
same issue states it verbatim: "Stage 1 — now", "Stage 2 — deferred to #37". On this repo an
issue's governing decision often lives in a comment rather than the body, so `gh issue view N`
without `--comments` is not enough evidence to call a PR's framing fabricated.

**Not an issue:** the write-failure gap (the loader falls back to `FALLBACK_MACHINE_KEY` when
the replacement write genuinely fails). The merged README names that fallback in the same
sentence, so it is no longer even silent-by-context.
