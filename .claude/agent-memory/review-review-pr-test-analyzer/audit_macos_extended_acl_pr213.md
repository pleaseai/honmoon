---
name: audit-macos-extended-acl-pr213
description: "PR #213 (issue #181) adds carries_an_extended_acl() to audit.rs's trusted-directory check on macOS — the new red-verified test genuinely isolates the ACL branch from the pre-existing group-writable branch via a distinct error-message substring; two documented-but-untested branches remain: deny-only ACL over-refusal and the non-ENOENT errno fail-closed arm"
metadata:
  type: project
---

`require_link_in_a_trusted_directory` in `crates/honmoon-core/src/audit.rs` gained
`carries_an_extended_acl(dir)` on macOS (issue #181): a root-owned `0755` dir with an
NFSv4 ACL (`chmod +a`) no longer reads as trusted just because `st_mode` says so.

**The new test is sound, not vacuous.** The two error messages differ textually
("carries an extended ACL" vs. "writable by someone other than root or this
process's own user"), so `with_file_refuses_a_symlinked_parent_in_a_directory_an_acl_opens_up`'s
`err.to_string().contains("extended ACL")` assertion cannot pass via the older
group-writable rule firing instead. The test also asserts its own premise
(`meta.mode() & 0o022 == 0` after `chmod +a`, so the mode bits genuinely still read
trusted) before asserting the refusal, and asserts `chmod +a` itself succeeded
(panics with a clear message otherwise, rather than silently no-oping) — same
"vacuity" bug class as [[audit-sink-fifo-enxio-shortcircuits-fstat]]'s /dev/full trap,
avoided here. `carries_an_extended_acl` reverted to `false` would make the test panic
at `let Err(err) = ... else { panic!() }` — genuinely red against the unfixed code.

CI wiring: `.github/workflows/ci.yml`'s `rust-macos` job's `cargo test` and
`cargo clippy` gained `-p honmoon-core` alongside the pre-existing `-p honmoon-cli`,
so the new `#[cfg(target_os = "macos")]` tests actually run. The ubuntu job is
untouched. No existing test body was modified — the diff's only `-` lines in
`audit.rs` are a doc-comment rewrite plus the single `return Ok(());` line the fix
itself replaces.

**Left untested, both merely documented in the doc comment above
`carries_an_extended_acl`, not exercised:**
- The deny-only-ACL over-refusal case (macOS home dirs carry
  `group:everyone deny delete` by default, which the function still treats as
  untrusted even though a deny ACE can only subtract access) — the doc names this
  cost explicitly but no test builds a deny-only ACL fixture to pin the current
  (over-refusing) behavior.
- The non-`ENOENT` errno branch of `carries_an_extended_acl` (any error other than
  "no ACL" is treated as untrusted, fail-closed) — no test forces
  `acl_get_fd_np` to fail with something other than `ENOENT`.

Both are named in prose as intentional, so they read as lower-severity than a silent
bug, but they're real behavioral gaps this diff introduces and neither was closed
in-PR (unlike [[audit-sink-response-fallback-only-tests-key-source]]'s pattern where
the gap was found and closed in the same PR).
