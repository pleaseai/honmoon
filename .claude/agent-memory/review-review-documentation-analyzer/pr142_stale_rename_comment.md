---
name: pr142-stale-rename-comment
description: PR #142 (issue #141 exposed-salt detection) hook-salt doc review — one stale cross-reference from a rename, since fixed; the reusable lesson is to grep the old name file-wide on any rename
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

During review the rename had missed one cross-reference: `random_bytes`'s doc
comment (a function untouched by the diff, several functions away) still read
``#[cfg(unix)] to match `set_permissions_0600` and the `OpenOptionsExt` open
modes...`` — a symbol the rename had removed.

**That reference has since been corrected and the finding is closed.**
`crates/honmoon-cli/src/hook.rs:705` now reads ``match [`restrict_to_owner_only`]``
and `set_permissions_0600` no longer appears anywhere in the repo, so do not go
looking for it as a live smell — grepping the old name today returns nothing, and
treating its absence as a miss would be a false positive.

The transferable part is the check, not the instance: on a diff that renames a
private helper, grep the *old* name across the whole file rather than only the
edited hunks.

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
