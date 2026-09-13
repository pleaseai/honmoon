---
name: crate-boundary-dependency-set-vs-stdlib-behavior
description: "What honmoon-core's tests/crate_boundary.rs actually catches — verified: a new [dependencies] or [build-dependencies] entry including target.cfg(unix), and not a [dev-dependencies] one; it cannot see std-only I/O, and crates/AGENTS.md says so itself rather than claiming the whole boundary is enforced"
metadata:
  type: project
---

`crates/honmoon-core/tests/crate_boundary.rs` (issue #166) asserts the crate's
`cargo metadata --no-deps` dependency set — everything whose `kind` is not `"dev"` — against a
hard-coded list.

**Verified by mutating `Cargo.toml` and running it**, so this is measured rather than inferred:

- a new `[dependencies]` entry → fails (the assertion has teeth)
- a new `[build-dependencies]` entry → fails (also caught; `kind` is `"build"`, not `"dev"`)
- a new `[dev-dependencies]` entry → passes unchanged (deliberately out of scope, and the
  module doc says why)
- `libc`, declared under `[target.'cfg(unix)'.dependencies]`, **is** included — `cargo metadata`
  is the only reading of the manifest that covers a target table, which is the reason the test
  shells out instead of scanning `Cargo.toml`

**What it cannot catch, and this is not a documentation defect.** `crates/AGENTS.md`'s "Still
forbidden" list also names an environment read, a config-file lookup, a spawned process, and any
second open file. All four reach through `std` and the `libc` already present, so no dependency
moves and this test stays green — `crate_boundary.rs` itself spawns a process and reads an
environment variable to call `cargo metadata`. The amended AGENTS.md states this division
explicitly ("Half of that list is checked and half is not, so do not read it as enforced"), and
the test's module doc repeats it. **Do not report the division as an overclaim** — an earlier
draft of that section did overclaim it, four reviewers said so, and the wording was fixed before
merge.

**How to apply:** when a change adds a dependency to `honmoon-core`, this test is the gate and it
is reliable. When a change adds an env read, a process spawn, or a second `File::open`, the test
is silent by construction and review is the only gate — so read those diffs rather than trusting
a green suite.
