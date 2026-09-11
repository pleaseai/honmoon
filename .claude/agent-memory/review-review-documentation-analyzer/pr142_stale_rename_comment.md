---
name: pr142-stale-rename-comment
description: PR #142 (issue #141 exposed-salt detection) hook-salt doc review — found one stale cross-reference from a rename, everything else verified accurate
metadata:
  type: project
---

PR #142 renamed `set_permissions_0600` to `restrict_to_owner_only` in
`crates/honmoon-cli/src/hook.rs` (to return `Option<String>` naming an observed
exposed mode, issue #141) and rewrote the surrounding rustdoc thoroughly and
accurately — README `rule` table, `RedactionFacts`/`RedactionKeySource::Persisted`
rustdoc, the TS mirror in `packages/policy/src/index.ts`, the example `reason`
string (`salt file {} is readable beyond its owner (mode {mode:04o}) and could
not be restricted to 0600`) all check out against the code exactly.

But the rename missed one cross-reference: `random_bytes`'s doc comment (a
function untouched by this diff, several functions away) still reads `#[cfg(unix)]
to match `set_permissions_0600` and the `OpenOptionsExt` open modes...` — that
symbol no longer exists anywhere in the file. Classic rename-blast-radius miss:
grep the *old* name across the whole file (not just the hunk being edited) when
reviewing a rename-with-behavior-change diff in this codebase.

**Why:** the task instructions explicitly said to grep for `set_permissions_0600`
as a known smell for this PR — worth remembering as a real, cheap check for any
future PR touching hook.rs's exposure/permission-restriction code path.

**How to apply:** on any Honmoon Rust diff that renames a private helper, grep
the whole file (not just the diff hunks) for the old identifier in backticks
inside doc comments — renames reliably update call sites and the `[`...`]` doc
links rustdoc would catch, but not other doc comments' *prose* mentions in
backticks, which don't fail a build.

Result: 1 finding (confidence ~85, minor/moderate — internal doc comment, not
user-facing) out of an otherwise clean, well-verified doc PR. Same author
pattern as [[pr122_hook_salt_parity]] — prose is carefully cross-checked against
code, but a rename's non-doc-link prose references can still slip through.
