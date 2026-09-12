---
name: agent-memory-index-129
description: 'scripts/agent-memory-index.ts (PR #156) answers `[]` from trackedIndexFiles only when git says "not a git repository", and raises on any other git failure — an empty list means the tracked-index invariant was checked and holds, never that checking failed; keep that distinction if the function is touched'
metadata:
  type: project
---

`scripts/agent-memory-index.ts` (PR #156, issue #129) derives each agent's `MEMORY.md` index from
note frontmatter instead of hand-appending it, closing the git-conflict class described in the
file's own header comment.

**The failure mode worth remembering.** `trackedIndexFiles()` returns the list of `MEMORY.md`
files git still tracks, and `[]` is the value that means *the invariant holds*. The first draft
wrapped the git call in a bare `catch { return [] }` commented "not a git checkout (or no git)".
Three independent reviewers caught the same thing: the catch was wider than its own comment, so a
git that failed for an unrelated reason — missing binary, unreadable index, a sandbox that blocks
it — would downgrade the one invariant the whole change rests on to an unverified pass, with the
CI `--check` gate and the `bun test` regression guard both reading green.

The merged version only answers `[]` when git says "not a git repository", and throws otherwise.
**If this function is touched again, that asymmetry is the thing to preserve:** a check whose
"all clear" value is indistinguishable from its "could not check" value is not a check. The
general shape — a comment explaining why a broad swallow is safe, sitting exactly where the
missing guard is — is the same one recorded in [[framing-deliberate-skips]].

**The same function then failed the same way a second time, for a different reason**, which is
why it is worth a note rather than a commit message. It read `git ls-files` without `-z`. Git
C-quotes any path containing a non-ASCII character, a quote or a backslash, so a tracked
`agent-mémoire/MEMORY.md` came back as `"agent-m\303\251moire/MEMORY.md"` — ending in `"`, not
in `MEMORY.md`. The `endsWith` filter dropped it and the function returned `[]`: all clear, from
a path it had in hand and failed to parse. **Any code that filters `git ls-files` output by
suffix needs `-z`**, and the general rule is that a porcelain-shaped default (quoting, coloring,
pager) is a display format, not a parse format.

Also worth knowing: the script's tests pin the *positive* case (`trackedIndexFiles` finds a
committed index in a throwaway `git init` checkout), not just the repository's current all-clear
state. A guard only exercised against a clean repo would pass identically if it could never find
anything.
