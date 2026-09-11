---
name: audit-sink-fifo-enxio-shortcircuits-fstat
description: open_sink refuses a FIFO two ways and only one is reachable per test — a reader-less FIFO never reaches the fstat check; both cases are covered since #163, do not re-flag
metadata:
  type: project
---

`crates/honmoon-core/src/audit.rs`'s `open_sink()` refuses a FIFO audit-log target
two different ways, and **a single test can only reach one of them**:

1. No reader attached → `O_NONBLOCK` makes `open()` itself fail `ENXIO` before
   `file.metadata()` is ever called.
2. A reader attached → the open *succeeds*, and only the post-open
   `fstat`/`!file_type.is_file()` check refuses it, through `describe_file_type`'s
   `is_fifo()` branch.

Verified empirically on macOS with a standalone probe replicating `open_sink`'s exact
`OpenOptions` and flags. Case 2 is the adversarial ordering, not a curiosity: anyone who
can hold the FIFO open for reading defeats the `ENXIO` fast path, and the type check is
the only thing left.

**Status as merged (#163): both cases are covered.** A first draft of that PR tested the
reader-less case alone, which left a regression that dropped `!file_type.is_file()`
undetectable; review caught it and the PR added
`with_file_refuses_a_fifo_that_already_has_a_reader`, which attaches an
`O_RDONLY | O_NONBLOCK` reader first and asserts the refusal carries
`ErrorKind::InvalidInput` and the words "a FIFO" — i.e. that it came from the type
check, not from the open. **Do not report the fstat branch as untested.**

**Why:** the two-defenses shape is what makes this easy to get wrong — the shallow
defense makes the test pass, so the deep one looks covered when nothing exercises it.

**How to apply:** when reviewing any guard that is gated *both* by an open-time flag and
by a post-open check, confirm a test exists that defeats the flag so the check is the
thing under test. For this file, the two test names above are that pair. See also
[[shadowed_rules_self_shadow_gap]] for the general "two defenses, only the shallow one is
tested" pattern.
