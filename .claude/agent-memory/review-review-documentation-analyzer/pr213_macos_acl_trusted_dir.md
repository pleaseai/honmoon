---
name: pr213-macos-acl-trusted-dir
description: "PR #213 (issue #181) macOS extended-ACL trusted-directory check — crates/AGENTS.md's new libSystem-extern paragraph, ci.yml's job rename/widen, and audit.rs's rustdoc rewrite all verified accurate; zero findings, a clean-PR calibration point"
metadata:
  type: project
---

PR #213 adds `carries_an_extended_acl()` (macOS `acl_get_fd_np`/`acl_free`, hand-declared
`unsafe extern "C"` in a `darwin_acl` submodule) to `require_link_in_a_trusted_directory` in
`crates/honmoon-core/src/audit.rs`, closing the gap where an NFSv4-style ACL has no `st_mode`
representation and previously let a root-owned `0755` dir with `user:mallory allow write` read
as trusted.

Checked and accurate, all in this diff:

- **`crates/AGENTS.md`**: new paragraph explicitly opens with "does **not** come through
  `libc`", directly updating (not contradicting) the pre-existing "`libc` is here for that open
  and nothing else" sentence a few lines above — the tension is resolved in-text, not left. It
  also correctly argues the "ask first: adding a new workspace dependency" Boundaries bullet
  isn't tripped: no `Cargo.toml`/`Cargo.lock` diff (verified via `git diff --stat`), and
  `honmoon-core/tests/crate_boundary.rs` reads `cargo metadata`, which the manifest move would
  show and doesn't.
- **`.github/workflows/ci.yml`**: old job name `Rust — macOS enforced isolation` has zero
  remaining references anywhere in the repo (grepped). The rewritten comment's claim "there are
  now two such places" (crates with `cfg(target_os = "macos")` code) is exactly right — grep
  across `crates/packages/apps/scripts` finds only `honmoon-cli` (hook.rs, isolate/mod.rs,
  tests/enforced_isolation.rs) and `honmoon-core` (audit.rs).
- **`audit.rs` rustdoc**: `ACL_TYPE_EXTENDED = 0x00000100` and the `acl_get_fd_np`/`acl_free`
  signatures match the real macOS SDK header (`$(xcrun --show-sdk-path)/usr/include/sys/acl.h`)
  byte-for-byte — worth doing this check with the actual SDK header when a PR hand-declares a
  system extern, it's cheap and catches a wrong constant immediately.
- **No user-facing doc gap**: `--audit-log`'s refusal behavior (symlink, group-writable dir, and
  now extended-ACL) has never been documented in README/roadmap for any of its prior causes
  (#138, #160) — this PR widening the causes doesn't newly violate that established precedent
  (see [[pr183-audit-sink-readme-verified]] and [[honmoon-pg-runtime-timeout-docs]] for the same
  "hardening detail lives in code doc, not README" pattern in this repo).
