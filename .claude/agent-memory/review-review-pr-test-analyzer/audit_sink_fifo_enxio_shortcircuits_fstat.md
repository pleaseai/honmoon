---
name: audit-sink-fifo-enxio-shortcircuits-fstat
description: open_sink's FIFO refusal test (#163) exercises O_NONBLOCK/ENXIO, not the fstat is_file() check that is the real defense against a reader-primed FIFO
metadata:
  type: project
---

`crates/honmoon-core/src/audit.rs`'s `open_sink()` refuses a FIFO audit-log target
two different ways: (1) `O_NONBLOCK` makes `open()` fail `ENXIO` immediately when
no reader is attached, and (2) if a reader *is* attached (so the open succeeds),
the post-open `fstat`/`!file_type.is_file()` check refuses it via `describe_file_type`'s
`is_fifo()` branch.

Empirically verified (macOS) with a standalone probe: opening a reader-less FIFO
with `O_NONBLOCK` fails at the OS level with `ENXIO` before `file.metadata()` is
ever called; the `is_fifo()` code path in `describe_file_type` only fires when a
reader happens to be attached at the moment of open.

PR #163's `with_file_refuses_a_fifo_without_blocking_on_it` test creates a
reader-less FIFO, so it only exercises the ENXIO fast path. The fstat/`is_fifo()`
defense — which is what actually stops an adversary who pre-attaches a reader to
the FIFO specifically to defeat the ENXIO fast path (a realistic move given the
function's own threat model of a hostile local user) — is completely untested.
A regression that removed the `!file_type.is_file()` check would not be caught by
any test in this module.

**How to apply:** when reviewing tests for `open_sink`/`describe_file_type` (or
similar not-a-regular-file guards gated by both a fast open-time flag and a
post-open fstat check), verify a test exists for the *reader-attached* FIFO case
too, not just the trivial reader-less one. See also [[shadowed_rules_self_shadow_gap]]
for the general pattern of "two defenses exist, only the shallow one is tested."
