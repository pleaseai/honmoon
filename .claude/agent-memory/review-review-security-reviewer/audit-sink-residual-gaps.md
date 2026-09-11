---
name: audit-sink-residual-gaps
description: The audit-sink open's residual gaps after #138 — symlinked parent (#160), pre-existing mode (#161), and the undocumented hard-link/hostile-pre-creation confidentiality bypass
metadata:
  type: project
---

`open_sink`'s doc comment (`crates/honmoon-core/src/audit.rs:345`) lists two accepted
gaps: a symlinked *parent* directory (#160) and the mode of an already-existing file
(#161). Both are described accurately.

What the prose does **not** name, and what a reviewer should raise if this area is
touched again: `O_NOFOLLOW` constrains *symbolic* links only. In the same
untrusted-directory threat model that motivates it, a local attacker can instead

- pre-create the audit path as an ordinary `0666` regular file, or
- `link(2)` it to a file they own,

and every record honmoon appends — hosts, SQL tables, PII categories, a hook's
absolute `$HOME` salt path — lands in a file they can read. The fstat passes (it *is*
a regular file) and `mode(0o600)` does not apply because the file already exists.
On macOS there is no `protected_hardlinks` equivalent, so the hard-link form also
reopens the integrity half of CWE-59.

The cheap close is an fstat-based owner/link check next to the existing type check
(`st_uid == geteuid()`, `st_nlink == 1`), or an `O_EXCL` create attempt first.

**Why:** #161 is framed as a benign-history problem ("left group-readable by an
earlier honmoon or by the operator"), which makes the adversarial version easy to
read as already-tracked when it is not.

**How to apply:** cite this before accepting "#161 covers it" on any future audit-sink
review. Related: [[audit-sink-open-hardening]].
