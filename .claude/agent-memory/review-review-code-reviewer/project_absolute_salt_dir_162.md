---
name: project-absolute-salt-dir-162
description: "PR #174 (issue #162) — absolute_salt_dir resolves the hook salt dir before any reason string is built; every producer traced, the new negative assertion mutation-tested, the unresolvable fallback split out as #176"
metadata:
  type: project
---

PR #174 answers issue #162 (whether `RedactionFacts::reason`, served by unauthenticated
`GET /api/audit`, should be trimmed) by deciding to keep it whole — filed as #173 (missing
auth layer) — and fixing the other half: `honmoon_dir()` returns a relative `.honmoon` when
`HOME` is unset, so a reason like `salt file .honmoon/hook-salt ...` names no file.

Fix: `load_or_create_machine_salt` rebinds `dir` through a new `absolute_salt_dir` (lexical
`std::path::absolute`, falls back to the path as given on error) as its first line, before
`path = dir.join("hook-salt")`. Traced every `reason`-producing string in
crates/honmoon-cli/src/hook.rs (`restrict_to_owner_only`, `publish_secret_atomically`, the
short/corrupt and unexpected-error `eprintln!` arms) — all derive from `path`/`dir` after the
rebind, so all reach `/api/audit` absolute **whenever the resolution succeeds**. Single entry
point: `machine_key()` and `machine_key_in()` both funnel through
`load_or_create_machine_salt`, so there is no producer that bypasses the absolutization.

The qualifier is load-bearing: `absolute_salt_dir` falls back to the path as given when
`std::path::absolute` fails (relative dir + unreadable cwd), and nothing in the event marks
that, so the record cannot distinguish "tried and failed" from "never tried". Split out as
**#176** — report against that issue, not as a new finding.

Verified by mutation: reverting the `absolute_salt_dir` rebind (restoring plain `dir`) makes
the new test `a_relatively_addressed_salt_is_recorded_by_its_absolute_path` fail — the
negative assertion is real, not vacuous. `cargo check -p honmoon-cli --tests` and the new
test both pass on the actual diff.

This reviewer found nothing; **the round did not come back clean.** The security and comment
finders landed accepted findings against the *prose* in the same PR, and the rustdoc was
rewritten after this note was first written — so do not read "traced clean" as covering the
doc comments. What the final rustdoc says, and what was corrected into it: the absolutization
is a disclosure *trade* rather than the neutral change the first draft claimed (a `HOME`-less
gateway now has its cwd filled in, which `passwd` does not reveal), the settlement covers
this content — a local salt path and an OS error — rather than the field, and the lexical
`..` guarantee is the Unix one. The claims that did check out against the code: deliberately
untrimmed, salt loader resolves dir first, CSPRNG fallback names `/dev/urandom` and no salt
path, and `honmoon_dir()` never returns an empty path even for `HOME=""`.

Method worth reusing: the over-claims were all in prose, and all of the form "X always holds"
or "no worse than before". Grep a doc-heavy diff for unconditional claims first.

See also [project-hook-salt-was-exposed-143](project_hook_salt_was_exposed_143.md) for the
prior miss on this same file — this time traced every producer explicitly rather than
top-down reading.
