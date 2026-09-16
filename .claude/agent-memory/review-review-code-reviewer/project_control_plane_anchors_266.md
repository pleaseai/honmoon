---
name: project-control-plane-anchors-266
description: "PR #276 (issue #266) repoints six control-plane.md anchors and adds a describe block to check-wiki-source-anchors.test.ts — reviewed clean; two things worth not re-deriving"
metadata:
  type: project
---

PR #276 fixed six stale `honmoon-mgmt/src/lib.rs` citations on `wiki/deep-dive/control-plane.md`
and added a ~90-line `describe('control-plane.md shows the management API it cites', …)` block to
`scripts/check-wiki-source-anchors.test.ts`. Two things a reviewer would otherwise re-derive:

1. `new RegExp(`${MGMT_LIB.replace(/[./]/g, '\\$&')}:(\\d+)-(\\d+)`)` is correct, not a bug. In a
   JS string literal `'\\$&'` is the three characters backslash, `$`, `&` — `replace`'s `$&` token
   substitutes the whole match, so the callback-free replacement literally backslash-escapes every
   `.` and `/` in the path before it goes into `RegExp`. Verified by constructing it and matching a
   trap string that would false-positive if `.` were left as a wildcard — it does not. Don't flag
   this construction again without reproducing it; reasoning about the escaping in the abstract
   reads as a bug that isn't one.

2. A conditional `throw` sitting directly in a `describe()` callback body (not inside `test()` or
   `beforeAll`) does surface in `bun:test`: it prints "Unhandled error between tests" and the
   process exits non-zero, so CI still fails. Verified empirically (bun 1.4.2) with a three-describe
   sandbox file — the throwing describe's own tests never run, but sibling describes before and
   after it still do, and the run exits 1. It is a structural deviation from every other describe in
   this file (all of which put every read/assertion inside `test()`, nothing at describe-scope) but
   not a silent-skip bug. That deviation was raised on #276 and rejected as out of scope: it is
   style with no rule to cite, and the reads are deliberately hoisted so ten tests share one read
   of `lib.rs`. Do not re-file it.

The off-by-one in `lines.slice(anchor.start! - 1, anchor.end!)` matches the file's own convention
(`checkAnchor` uses `lines[start - 1]` the same way against `readCited`'s post-trailing-pop line
array) — not a bug either.
