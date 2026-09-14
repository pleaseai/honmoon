---
name: pr213-macos-acl-trusted-dir
description: "PR #213 (issue #181) macOS extended-ACL trusted-directory check — how to check a hand-declared system extern (SDK header, cargo metadata, grep the old CI job name), and the docs pass that found nothing while a second pass found three overclaims in the same prose: a docs-vs-implementation sweep is not a claim-by-claim audit"
metadata:
  type: project
---

PR #213 adds `carries_an_extended_acl()` (macOS `acl_get_fd_np`/`acl_free`, hand-declared
`unsafe extern "C"` in a `darwin_acl` submodule) to `require_link_in_a_trusted_directory` in
`crates/honmoon-core/src/audit.rs`, closing the gap where an NFSv4-style ACL has no `st_mode`
representation and previously let a root-owned `0755` dir with `user:mallory allow write` read
as trusted.

**Read the calibration note at the bottom before trusting the "accurate" list.**

Checked and accurate, all in this diff:

- **`crates/AGENTS.md`**: the new paragraph opens with "does **not** come through `libc`" and
  correctly argues the "ask first: adding a new workspace dependency" Boundaries bullet isn't
  tripped: no `Cargo.toml`/`Cargo.lock` diff (verified via `git diff --stat`), and
  `honmoon-core/tests/crate_boundary.rs` reads `cargo metadata`, which a manifest move would
  show and doesn't. What this pass got *wrong* is recorded below.
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

**Calibration, which is the part worth keeping.** This pass reported zero findings; a
comment-accuracy pass over the same prose then found three real overclaims, all fixed before
merge:

- `crates/AGENTS.md`'s pre-existing "`libc` is here for that open and nothing else: [four
  syscalls] and the definitions those four take" was left *incomplete* by the new extern block,
  which is typed in `libc::c_int`/`c_uint`/`c_void` and reads `libc::ENOENT` — uses that belong
  to neither of the four. This note originally called that tension "resolved in-text"; it was
  not, and the sentence was rewritten.
- The `darwin_acl` module doc called its declarations `sys/acl.h`'s "transcribed" when
  `acl_type_t` and `acl_t` are spelled as the raw types they are — ABI-equal, not text-equal.
- "the `acl_type_t` enum has no negative value, so C gives it unsigned rank" states an
  implementation-defined choice as a language rule. Its four-byte width is what makes `c_uint`
  right.

The lesson is about method, not about this PR: checking that documentation *matches the
implementation* is a different sweep from checking that each sentence's claim is *true*. A
paragraph can describe the code correctly and still overclaim about C, about a header, or about
what a neighbouring paragraph now says. When a diff adds prose that reasons about a language, a
platform or a sibling document, the second sweep is the one that finds things.
