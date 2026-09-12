---
name: pr163-audit-sink-comment-claims
description: "Doc-comment claims in audit.rs that were wrong when first written across PR #163 and PR #179 (issue #160) — drifted names, unqualified/self-contradicted errno claims, overstated portability, a stale one-line fn doc left behind by a more careful comment added nearby — plus the checks that caught them, which are cheap to repeat"
metadata:
  type: project
---

PR #163 added ~130 lines of doc comments to `crates/honmoon-core/src/audit.rs`
(`open_sink`, `describe_file_type`) plus a `Cargo.toml` dependency justification. Four
claims were wrong on first draft. **All four were corrected before merge — the notes
below are about the checks, not about defects still present.** Verified against the code
and `man 2 open` on macOS/Darwin.

- **A function name from another crate had drifted.** The doc cited
  `set_permissions_0600` in `honmoon-cli/src/hook.rs`; that function was renamed to
  `restrict_to_owner_only` in #142 and the old name exists nowhere in the repo. The issue
  text the PR was written from still used the old name, which is how it got copied in.
  Cross-crate function names cited from a doc comment drift silently — grep every one.
- **An errno was stated without a platform qualifier.** `describe_file_type`'s doc said a
  socket fails `ENXIO`. True on Linux; macOS documents `EOPNOTSUPP` for opening a socket
  and reserves `ENXIO` for a missing char/block device and the FIFO + `O_NONBLOCK` case.
  This crate targets both. Checking `man 2 open` locally is fast and authoritative.
- **A portability claim overstated the limit.** The doc said closing the
  symlinked-parent gap needs `openat2(RESOLVE_NO_SYMLINKS)` or an `openat` walk, "neither
  portable to macOS". Only `openat2` is Linux-only; a component-by-component `openat` walk
  is POSIX and macOS has it. The gap is unwritten, not unavailable.
- **A dependency justification was contradicted by its own diff.** `Cargo.toml` said "No
  syscall is made through `libc` here" while the same PR added a test calling
  `unsafe { libc::mkfifo(...) }`. A justification scoped to "this crate" has to account
  for test code added alongside it.

Cross-issue references (#131, #137, #138, #160, #161) were all real and accurate — this
repo's issue-linking discipline in this area is good; do not spend much budget
re-checking issue existence.

**PR #179 (issue #160, the symlinked-parent-directory walk) repeated the pattern at a
smaller grain, flagged during review before merge:**

- `open_directory`'s one-line doc said the `openat(O_DIRECTORY|O_NOFOLLOW)` call refuses a
  symlink "with `ELOOP`" — stated as the only outcome. Fourteen lines below it, in the same
  file, an inline comment on the retry loop explains the two platforms disagree: Linux
  reports `ELOOP`, macOS reports `ENOTDIR` — which is *why* the code classifies with
  `fstatat` instead of trusting the errno at all. The short function doc was a leftover
  from before that platform split was written up and never got reconciled with the more
  careful comment sitting right next to it. Lesson: when a file states a general rule in
  one place and a qualified/contradicting version of the same rule nearby, the short
  version is usually the stale one — diff both.
- `unusable_path`'s doc claimed it reports a bad path "before any syscall is made." True
  for three of its five call sites in `open_sink_file` (an unreachable Windows-only
  `Component::Prefix` check, the "names a directory" check, and the "has no final
  file-name component" check, all before `open_walk_root` runs) — false for the other
  two, which fire only after the walk has already run several `openat`/`fstatat`/
  `readlinkat` calls (the `MAX_SYMLINK_HOPS` bound, and a `Component::Prefix` found inside
  an already-resolved symlink target). A shared helper's doc comment describing "when it
  runs" needs checking against *every* call site, not just the one nearest the doc.

One correction to draw from this PR about
[[guard-unnecessary-doc-comment]]: the "**Still accepted, deliberately:**" section was
read on its merits and its *stated* argument held (an operator-chosen log path may be
group-read by a shipper on purpose, unlike the hook salt) — **but the list was still
hiding a gap**, because it enumerated the link types refused rather than the ways the
final inode can be attacker-chosen. Hard links and hostile pre-creation fell outside it
entirely. The merged version adds a third bullet reading the list from the inode side.
The lesson is that a sound rationale for one item does not make the enumeration complete;
see [[enumerate-from-the-wrong-side]].
