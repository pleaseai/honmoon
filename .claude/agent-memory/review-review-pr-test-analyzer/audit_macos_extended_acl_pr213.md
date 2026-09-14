---
name: audit-macos-extended-acl-pr213
description: "PR #213 (issue #181) adds carries_an_extended_acl() to audit.rs's trusted-directory check on macOS — the new red-verified test genuinely isolates the ACL branch from the pre-existing group-writable branch via a distinct error-message substring; four macOS tests in the end — the deny-only over-refusal and the O_SEARCH-descriptor claim were gaps found in review and closed in this same PR, leaving only the non-ENOENT errno arm untested"
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

**Two gaps were found mid-review and closed in the same PR** — do not re-report them:

- `with_file_refuses_a_symlinked_parent_whose_acl_only_denies` builds the deny-only
  fixture (`chmod +a "everyone deny delete"`) and pins the over-refusal macOS home
  directories make common. It exists so an allow/deny refinement with the sense
  inverted fails a test: the allow-case test above would stay green.
- `an_extended_acl_is_visible_through_a_search_only_descriptor` pins the doc's claim
  that the ACL query answers the `O_SEARCH` descriptor the `O_TRAVERSE` retry
  produces. Nothing else reaches that pairing —
  `with_file_opens_a_sink_under_a_search_only_parent_directory` exercises the retry,
  but its parent holds no symlink, so the trust rule never runs in it.

**Left untested, one branch:** the non-`ENOENT` errno arm of `carries_an_extended_acl`
(any error other than "no ACL" is treated as untrusted, fail-closed). Forcing
`acl_get_fd_np` to fail with a different errno needs a filesystem fixture the suite has
no way to build, and the arm fails closed, so a wrong implementation surfaces as an
over-refusal rather than a hole. Named in prose as intentional; not a finding to
re-raise without a way to exercise it.
