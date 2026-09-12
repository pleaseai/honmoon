---
name: audit-symlink-walk-untested-branches
description: PR #179's openat-walk fix for issue #160 (crates/honmoon-core/src/audit.rs) — which walk branches have no test, and the one whose coverage is platform-dependent because macOS reaches temp_dir through the relative symlink /var -> private/var and Linux does not
metadata:
  type: project
---

`open_sink_file` in `crates/honmoon-core/src/audit.rs` walks an audit path
component-by-component with `openat(O_NOFOLLOW|O_DIRECTORY)` (issue #160, PR #179).
The inline test module is otherwise thorough — strong `err.kind()` plus
message-substring assertions throughout, not bare `is_err()`.

**The platform-dependent one, and it runs the opposite way to this repo's usual
trap.** The splice after a trusted symlink branches on `target.is_absolute()`:
an absolute target resets `dir` to the walk root, a relative one keeps `dir` and
prepends the target's components. Every symlink *planted by a test* points at an
absolute target (`dir.join("attacker")`, `dir.join("real")`, both rooted at
`std::env::temp_dir()`). But that does not mean the relative branch is dead:
on macOS `std::env::temp_dir()` is `/var/folders/...`, and `/var` is itself a
symlink whose target `private/var` is **relative** — so every sink test in the
file takes the relative branch on its first hop, on that platform, including the
ones that have nothing to do with symlinks. On Linux `temp_dir()` is `/tmp`, a
real directory, and the relative branch is never taken by anything.

So: covered incidentally on macOS, uncovered on Linux. Do not write "this branch
is never exercised" — it is wrong on one of the two platforms CI runs, and a
finding phrased that way gets refuted rather than fixed. Phrase it as the
platform asymmetry it is.

**Genuinely untested branches** (verified against PR #179's head):

- **Group-writable but not world-writable directory.** The doc comment on
  `require_link_in_a_trusted_directory` says "a group-writable directory counts
  as untrusted even where the group is one this process belongs to" — a one-bit
  decision (`mode & 0o022`, not `mode & 0o002`). Every trust-boundary test uses
  `0o777` (untrusted) or `0o755` (trusted); nothing at `0o770`/`0o775`, so
  narrowing the mask to `0o002` would pass the whole suite.
- **`MAX_SYMLINK_HOPS` (40).** No test builds a chain long enough to reach the
  budget, so deleting the check or an off-by-one in `hops > MAX_SYMLINK_HOPS`
  fails nothing. Note the check does work: a *cyclic* chain does not hang, because
  each hop through `readlinkat` increments `hops` and the walk errors at 41. Do
  not claim a cycle would loop forever — it would not.
- **Interior-NUL guard (`c_component`).** Never driven through
  `AuditLog::with_file`. Low value to test: neither input source can carry a NUL
  (argv and environ are both NUL-terminated by the OS), so this is
  defence-in-depth over an unreachable input, and a test for it would be testing
  `CString::new`.
- **`SINK_OPEN_ATTEMPTS` (4) exhaustion.** Covered only probabilistically, by the
  concurrent-create race test. Making it deterministic needs syscall injection
  this crate has no harness for.

None of this is platform *vacuity* in the sense the repo was bitten by before
(the `/dev/full` absence on macOS). The trust-boundary tests evaluate correctly
whether or not CI runs as root, since the mode check is ANDed with the uid check
either way.

See also [[audit-sink-fifo-enxio-shortcircuits-fstat]] for the FIFO half of this
same file's coverage.
