---
name: pr206-dev-dep-redundant-claim
description: "Cargo exposes a package's normal [dependencies] to its tests/*.rs integration tests, so a dev-dependency re-declaration for a crate already in [dependencies] is redundant — check such a claim by deleting the entry and building, not by reasoning about Cargo's model"
metadata:
  type: project
---

Cargo makes every entry under a package's `[dependencies]` available to its `tests/*.rs`
integration test binaries. A `[dev-dependencies]` re-declaration is needed only for crates that
are *not* already a normal dependency (`assert_cmd`, `tempfile`, and the like).

PR #206 (issue #166) briefly got this wrong: it added `serde_json.workspace = true` under
`[dev-dependencies]` in `crates/honmoon-core/Cargo.toml` — where `serde_json` is already a
normal dependency — with a comment saying the entry "only makes it linkable from an integration
test". Four reviewers reported it independently and **the entry was removed during review**, so
the merged PR does not contain it. Do not go looking for it; the note is here for the method,
not the defect.

The method: verify by deleting the entry in a scratch worktree and running `cargo check -p
<crate> --test <target>` — the specific target the comment claims needs it. It compiles clean,
which settles the question in seconds. Reasoning about Cargo's dependency-resolution model from
memory is what produced the wrong comment in the first place.

One trap in doing that check, worth more than the finding itself: an edit that silently fails to
apply makes the check **vacuous** rather than failing loudly — the build then succeeds because
the entry is still there, and reads as proof it was not needed. Assert the anchor matched before
trusting a removal, and confirm with `git diff` that the file actually changed. The author of
PR #206 hit exactly this and had to redo the check.

**How to apply:** any comment justifying a dependency re-declaration ("only for X", "not new
because Y already provides it") is checked by removing the entry and building the named target —
never on the stated reasoning alone, and never on a removal you have not confirmed landed.
