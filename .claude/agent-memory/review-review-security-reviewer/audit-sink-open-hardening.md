---
name: audit-sink-open-hardening
description: 'What AuditLog::open_sink (honmoon-core/src/audit.rs, #138) does and does not defend against — O_NOFOLLOW/O_NONBLOCK/fstat semantics plus the macOS acl_get_fd_np/ACL_TYPE_EXTENDED/errno facts behind #181, each verified once, so do not re-derive them — and the hard-link + hostile-pre-creation gap the doc comment omits'
metadata:
  type: project
---

`AuditLog::with_file` routes the operator-supplied `--audit-log` / `HONMOON_AUDIT_LOG`
path through `open_sink` (`crates/honmoon-core/src/audit.rs`), which on Unix adds
`mode(0o600)` + `custom_flags(O_NOFOLLOW | O_NONBLOCK)` and then rejects any fstat
that is not a regular file. `libc` is a `cfg(unix)` dep of honmoon-core for the two
constants only. `mode(0o600)` is umask-filtered, so it is a ceiling rather than an
exact mode, and `explain_refusal` rewrites `ELOOP` — which reads as a link *cycle* —
into a message naming `O_NOFOLLOW`.

Verified once, do not re-derive:
- `File::metadata()` is fd-based (`statx(fd, "", AT_EMPTY_PATH)` on Linux, `fstat`
  elsewhere — std `sys/fs/unix.rs::file_attr`), so the type check has no TOCTOU window.
- std always ORs `O_CLOEXEC` in and masks `O_ACCMODE` out of `custom_flags`, so the
  hardened fd is still close-on-exec.
- `O_NONBLOCK` surviving on the returned fd is inert: regular-file read/write ignore
  it on Linux and macOS (the only exception, Linux mandatory locking, was removed in 5.15).
- `O_CREAT | O_NOFOLLOW` refuses a *dangling* symlink too (ELOOP, both platforms) —
  it does not create the link's target.
- macOS extended-ACL probe (#181 / PR #213), measured on Darwin 24 with a C harness:
  `ACL_TYPE_EXTENDED` is `0x0000_0100` in the SDK's `sys/acl.h` (matches the
  hand-declared constant in `darwin_acl`); `acl_get_fd_np` on a directory with no ACL
  returns NULL **with errno `ENOENT`** (not `ENOATTR`), and returns a non-NULL handle
  as soon as one `chmod +a` ACE exists; it answers identically on an `O_SEARCH`
  descriptor, so the walk's `O_TRAVERSE` retry does not blind it. `libc` still carries
  no `acl_*` on Apple targets, which is why the two symbols are declared in-crate.
- A FIFO is refused either way: no reader → `ENXIO` from the nonblocking open; reader
  attached → open succeeds, fstat rejects it.

**Why:** these four were each challenged in the #163 review and each held; re-checking
them costs a full trip through std's source and two platform manpages.

**How to apply:** when reviewing this area, spend the effort on what is NOT closed
instead — see [[audit-sink-residual-gaps]].
