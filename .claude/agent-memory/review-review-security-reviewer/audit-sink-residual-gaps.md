---
name: audit-sink-residual-gaps
description: The three residual gaps in the audit-sink open after #138 — symlinked parent (#160), pre-existing mode and the hard-link/hostile-pre-creation bypass (both #161) — all documented in-code; verify the list still has all three rather than re-reporting them as unnamed
metadata:
  type: project
---

`open_sink`'s doc comment (`crates/honmoon-core/src/audit.rs`) has a "**Still accepted,
deliberately:**" section listing three residual gaps. **All three are named in the code
and tracked; report them as new findings only if the prose stops matching.**

1. **A symlinked parent directory** — `O_NOFOLLOW` constrains the final component only.
   Tracked in #160. `openat2(RESOLVE_NO_SYMLINKS)` is Linux-only; a component-by-component
   `openat` walk is portable and simply unwritten.
2. **The mode of a file that already exists** — `mode` applies on creation only, so a log
   created by a pre-#138 honmoon at the umask default stays there. Tracked in #161, pinned
   by `an_existing_sink_keeps_the_mode_it_had`.
3. **A final inode chosen by means other than a symlink.** `O_NOFOLLOW` constrains
   *symbolic* links only. In the same untrusted-directory threat model, a local actor can
   pre-create the audit path as an ordinary `0666` regular file, or `link(2)` it onto a
   file they own. The `fstat` passes — it *is* a regular file — and the creation mode does
   not apply, so every record (hosts, SQL tables, PII categories, a hook's absolute
   `$HOME` salt path) lands where they read it. On macOS there is no
   `protected_hardlinks` equivalent, so the hard-link form also reopens the integrity half
   of CWE-59.

Gap 3 was **missing from the list** when #163 was first pushed, and #161 was then framed
as benign history ("left group-readable by an earlier honmoon or by the operator"), which
made the adversarial version read as already-tracked when it was not. Both were fixed
before merge: the bullet was added and #161's body was widened to cover it explicitly.

The cheap close for gap 3 is an fstat-based owner/link check beside the existing type
check (`st_uid == geteuid()`, `st_nlink == 1`). It sits in #161 rather than its own issue
because it is the *same decision* as the mode question — may honmoon refuse, or
re-tighten, an audit file it did not create? — and that refusal is exactly what would
break the log-shipper scenario the mode half exists to protect.

**How to apply:** on any future audit-sink review, check the in-code list still has all
three bullets and that #161 still carries the adversarial framing. If it does, this is
covered; spend the budget elsewhere. Related: [[audit-sink-open-hardening]],
[[enumerate-from-the-wrong-side]].
