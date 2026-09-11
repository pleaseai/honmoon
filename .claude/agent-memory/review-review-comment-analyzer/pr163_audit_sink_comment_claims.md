---
name: pr163-audit-sink-comment-claims
description: PR #163 (audit.rs open_sink hardening) doc-comment verification results — wrong function name, wrong errno on macOS, self-contradicted libc claim
metadata:
  type: project
---

PR #163 added ~130 lines of doc comments to `crates/honmoon-core/src/audit.rs` (`open_sink`,
`describe_file_type`) plus a `Cargo.toml` dependency-justification comment. Verified against
code and `man 2 open` on macOS/Darwin (2026-09-11/12):

- The doc cites `set_permissions_0600` in `honmoon-cli/src/hook.rs` as the function that
  re-tightens the hook salt on every read. No such function exists — it's
  `restrict_to_owner_only` (hook.rs:742). Names of functions in *other* crates cited from a
  doc comment need grepping every time, they drift silently.
- `describe_file_type`'s doc says a socket fails `ENXIO` and therefore never reaches the
  function. True on Linux; on macOS `man 2 open` documents `EOPNOTSUPP` for opening a socket,
  not `ENXIO` (macOS's `ENXIO` is reserved for missing char/block device and the
  FIFO+`O_NONBLOCK` case). Errno claims stated without a platform qualifier in a crate that
  targets both Linux and macOS are worth checking against the local `man 2 open` directly —
  it's fast and authoritative.
- `Cargo.toml`'s "No syscall is made through `libc` here" was contradicted by the same PR's own
  new test (`with_file_refuses_a_fifo_without_blocking_on_it`), which calls
  `unsafe { libc::mkfifo(...) }`. A dependency-justification comment scoped to "this crate"
  needs to account for test code added in the same diff, not just the production path it was
  written about.
- Cross-issue references (#131, #137, #138, #160, #161) were all real and accurate — this repo's
  issue-linking discipline in this area is good; don't spend much verification budget re-checking
  issue existence unless the PR is old enough for issues to have been closed/renumbered.

See [guard-unnecessary-doc-comment](guard-unnecessary-doc-comment.md) — this PR's "Still
accepted, deliberately" section (not re-tightening an existing file's mode, unlike the hook
salt) was evaluated on its merits and held up; the operator-configurable-log-shipper rationale
is a real asymmetry, not a hidden gap, this time.
