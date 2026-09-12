---
name: audit-symlink-walk-untested-branches
description: "What is and is not covered in the audit sink's openat walk (crates/honmoon-core/src/audit.rs) as merged by PR #179 — plus the macOS /var -> private/var effect that makes one branch's coverage platform-dependent, and which two gaps were left open deliberately"
metadata:
  type: project
---

`open_sink_file` in `crates/honmoon-core/src/audit.rs` walks an audit path
component-by-component with `openat(O_NOFOLLOW|O_DIRECTORY)` (issue #160, PR #179).
The inline test module is thorough — strong `err.kind()` plus message-substring
assertions throughout, never bare `is_err()`.

**The platform effect to know before writing a coverage finding here, because it
runs opposite to this repo's usual trap.** The splice after a trusted symlink
branches on `target.is_absolute()`: an absolute target resets `dir` to the walk
root, a relative one keeps `dir` and prepends the target's components. On macOS
`std::env::temp_dir()` is `/var/folders/...` and `/var` is itself a symlink whose
target `private/var` is **relative** — so every sink test in the file takes the
relative branch on its first hop on that platform, including the ones with nothing
to do with symlinks. On Linux `temp_dir()` is `/tmp`, a real directory, and none
of them do.

So a finding phrased "this branch is never exercised" is refutable on one of the
two platforms CI runs, and gets refuted rather than fixed. Phrase it as the
platform asymmetry it is. PR #179 closed this particular one with
`with_file_follows_a_relative_symlink_target`, which plants a link whose target is
literally `"real"` — covered on both platforms now, not on whichever CI drew.

**Covered as merged** (each mutation-tested — the guard was broken and the test
observed to fail): the symlinked parent and grandparent in a world-writable
directory; the deliberate follow in an owner-only one; a **group-writable** `0o770`
directory being untrusted, which pins `mode & 0o022` against a narrowing to
`0o002` (note `0o750` does *not* test this — group `r-x` has no write bit, a
mistake worth not repeating); a relative symlink target; a 48-link chain past the
40-hop budget, paired with a 4-link chain that still resolves so the test cannot
pass by refusing symlinks outright; concurrent creation of one new sink; and the
three path shapes that name a directory rather than a file.

**Left uncovered deliberately, with the reasons** — do not re-file these without
new argument:

- **Interior-NUL guard (`c_component`).** Neither input source can carry a NUL:
  `--audit-log` arrives through argv and `HONMOON_AUDIT_LOG` through environ, both
  NUL-terminated by the OS. It is defence-in-depth over an unreachable input, and a
  test would be testing `CString::new`.
- **`SINK_OPEN_ATTEMPTS` (4) exhaustion.** Covered probabilistically by the
  concurrent-create race test. Driving the loop to its bound deterministically needs
  syscall injection this crate has no harness for.

One correction about the hop budget, which an earlier draft of this note got wrong:
a *cyclic* symlink chain does **not** hang without the budget. Every hop goes
through `readlinkat` and increments `hops`, so the walk makes progress and errors at
41. The budget bounds unbounded resolution; it is not a hang guard.

None of this is platform *vacuity* in the sense the repo was bitten by before (the
`/dev/full` absence on macOS). The trust-boundary tests evaluate correctly whether
or not CI runs as root, since the mode check is ANDed with the uid check either way.

See also [[audit-sink-fifo-enxio-shortcircuits-fstat]] for the FIFO half of this
same file's coverage.
