---
name: pr262-lock-dispose-claims
description: 'PR #262 (issue #256) audited the mgmt-token lock doc comments after moving release from try/finally to using/Symbol.dispose — the PR #255 checklist held clean, and the one real defect (a directional "below" reference stranded when the loop body became attemptUnderLock) was fixed before merge; the reusable part is that an extraction strands the enclosing comment, not the extracted one'
metadata:
  type: project
---

PR #262 refactored `mintOrAdoptUnderLock` in `packages/api/src/auth.ts`: the acquire/re-read/
publish/release sequence moved into a new `attemptUnderLock` function using `using held =
acquireLock(...)` (a `LockGuard` with `[Symbol.dispose]`) instead of a hand-placed `try`/`finally`.
Mirrors the Rust CLI's `LockGuard` + `Drop` in `crates/honmoon-cli/src/mgmt_token.rs`.

**Checked against the [[pr255-mgmt-token-lock-claims]] checklist — all six patterns came back
clean this round:**
- `{@link}`/`{@link X}` targets (`readOnDisk`, `publishToken`, `breakAbandonedLock`,
  `attemptUnderLock`, `writeAll`, `lockStillOurs`, `releaseLock`, `acquireLock`) all resolve to
  real symbols at HEAD — no stale rename links this time.
- Cross-language `LockGuard`/`Drop` symmetry claim verified directly against
  `mgmt_token.rs:478-524`: same fields conceptually (path/inode/pinned-fd), same `still_ours`
  method, same `Drop::drop` gating logic. The "process-local, not part of the interlock" claim is
  true — only the lock file's name/location/protocol crosses processes, the guard object never
  does.
- Test's ordering claims (`console.warn` fires under the lock, before the identity check; the
  `rmSync`+`writeFileSync` pair yields a different inode because the original process's fd is
  still open pinning the old inode) were traced through the actual call sequence and confirmed —
  ran the test standalone (`bun test -t "leaves a successor"`) to double-check, green.
- The `LockAttempt`/`attemptUnderLock` "needs nothing written for them" `using`-disposal claim:
  the one seemingly-uncovered exit (`return assertNever(underLock)` in the default switch arm) is
  in fact still a `return` statement, so it's covered by "the returns below" even though it also
  throws — not a real enumeration gap, don't flag it again if re-reviewed.

**The one real finding — stale directional prose, not a false mechanism. Fixed in PR #262
itself; do not re-report it against the merged code.** The long `mintOrAdoptUnderLock` doc block
(mostly unchanged prose describing what breaking an abandoned lock costs) said "Gated: the publish
below runs only if `{@link lockStillOurs}` says the path still holds this start's lock". Before
that PR the publish really was later in the same function body ("below"). The extraction moved it
into `attemptUnderLock` — a different function, not below that comment's own function at all. The
underlying claim (gating exists, same narrowed window) stayed true; what went stale was the
"below" pointer and the implicit "runs directly through `lockStillOurs`" phrasing, since the call
is now mediated through the guard's `stillOurs()`. Merged wording names `{@link attemptUnderLock}`
and the guard method, so the reference no longer depends on where either lives.

The reusable shape: **an extraction strands the *enclosing* comment, not the extracted one.** The
moved code carries its own comments with it and they stay correct; the long doc block left behind
keeps pointing at code that is no longer where it says. This is the
[[line-anchors-drift-from-your-own-commits]] family caused by a *sibling* hunk of the same diff
rather than by the reviewed citation itself. On any PR that lifts a loop body into a helper, grep
the enclosing doc comment for "below", "above", "the ... that follows" and re-read each against
the post-extraction layout.
