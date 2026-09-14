/**
 * Keep the published wiki off the claim that `honmoon-core` performs no I/O.
 *
 * The crate is **transport-agnostic, not I/O-free**: it opens exactly one file,
 * the operator's JSONL audit sink in `audit.rs`, and the hardening around that
 * open stays in the crate because it enforces an invariant of `AuditLog` itself
 * (issue #166). `crates/AGENTS.md`, the root `AGENTS.md` and `ARCHITECTURE.md`
 * were amended to say so in #206.
 *
 * The wiki was not, and that is what this guards. The claim had to be chased
 * twice already — #206 fixed three normative documents and left four more places
 * asserting the opposite, and #207 then found the same sentence living in six
 * wiki pages and in the generated `llms-full.txt`. A contributor following one
 * document should not get the opposite rule from another, and here the other
 * document is the one users actually read.
 *
 * Two rules, which catch different failures:
 *
 * 1. **Retired phrasings** — the exact wordings #207 removed. Cheap, and it is
 *    what stops an edit from restoring one by hand. `I/O-free` is negation-aware,
 *    because "transport-agnostic is not I/O-free" is the *correct* sentence.
 * 2. **The invariant must carry its exception** — a page that states what the
 *    core does not have must also name the sink. This is the rule with teeth: it
 *    reaches a *new* page that states the invariant in wording nobody has seen
 *    yet, which is the failure #207 actually describes ("a page left
 *    contradicting the other four is the same defect with a different filename").
 *
 * **What it does not cover, so it is not cited as more than it is.** Rule 1 is a
 * list of known strings: a fresh paraphrase — "the core never touches the disk" —
 * passes it. Rule 2 fires only on a page that pairs "transport-agnostic" with an
 * explicit capability-absence phrase; a page implying purity without either
 * passes. Neither rule reads meaning. They are a floor under review, not a
 * replacement for it — the same checked/unchecked split `crates/AGENTS.md` draws
 * around `crates/honmoon-core/tests/crate_boundary.rs`.
 *
 * `llms-full.txt` is scanned along with the pages. It is generated
 * (`wiki/.vitepress/gen-llms-full.mjs`) and inlines every page, so a page edited
 * without regenerating it leaves the retired wording there — which fails here
 * rather than shipping to the readers who consume that file.
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'
import { Glob } from 'bun'

export const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url))

/**
 * Markdown under `wiki/` that VitePress does not publish.
 *
 * Mirrors `srcExclude` in `wiki/.vitepress/config.mts`: the instruction files
 * for agents working on the site are not pages, and a rule written there is
 * allowed to quote the wording the pages must not use.
 */
const UNPUBLISHED = ['AGENTS.md', 'CLAUDE.md', 'README.md']

export interface Problem {
  where: string
  detail: string
}

interface Rule {
  /** Matches the retired wording. */
  pattern: RegExp
  /** What to say instead. */
  detail: string
}

/**
 * The wordings #207 retired, each with what replaced it.
 *
 * Every pattern is global so a page carrying the claim twice reports twice — the
 * invariant paragraph and the invariant table in `deep-dive/architecture.md` were
 * two separate edits.
 */
const RETIRED: Rule[] = [
  {
    pattern: /zero I\/O/gi,
    detail: 'the policy engine is unit-tested without a runtime, a network or a container — not '
      + '"with zero I/O", which reads as a claim about the crate',
  },
  {
    pattern: /every byte of I\/O/gi,
    detail: 'the transport, the protocol handling and the framework choice are pushed to the '
      + 'edges — not every byte of I/O; the audit sink open is in the core by decision',
  },
  {
    pattern: /purity of\s+`?honmoon-core`?/gi,
    detail: 'the seam is transport, not purity — say what is forbidden (an async runtime, a '
      + 'socket, a network client, a second file) rather than asking for purity',
  },
  {
    pattern: /add I\/O to\s+`?honmoon-core`?/gi,
    detail: 'what is forbidden is an async runtime, a socket, a network client or a *second* '
      + 'open file; I/O as such is not, and the sink proves it',
  },
  {
    pattern: /\bno\b[^.\n]{1,40}\bI\/O\b[^.\n]{1,20}\bin core\b/gi,
    detail: 'the core has no async runtime, socket or network client, and one file — the audit sink',
  },
]

/**
 * Cues that turn an `I/O-free` mention into the correct *denial* of the claim.
 *
 * Searched in what precedes the mention within its own sentence, because the
 * denial is not always adjacent to it: "transport-agnostic is not the same as
 * I/O-free" puts four words between them. A sentence that negates the negation
 * ("it is not true that the core is I/O-free") would read as correct here; no
 * such sentence is worth writing, and rule 2 is what carries the weight anyway.
 */
const NEGATED = /\b(?:not|never|rather than|isn't|no longer|instead of)\b/i

/**
 * A page asserts the invariant when it names it *and* says what the core lacks.
 *
 * The adjective alone is not enough: `index.md` describes a linked page as
 * covering "the transport-agnostic core", which owes no reader the exception.
 */
const ASSERTS_INVARIANT = /transport-agnostic/i
const CAPABILITY_ABSENCE = /\bno\s+(?:`?tokio`?|async runtime|sockets?|network client|networking dependency)/i
const NAMES_THE_SINK = /audit sink|JSONL sink/i

/**
 * Drop markdown emphasis so a rule matches the sentence a reader sees.
 *
 * Not cosmetic: `deep-dive/policy-engine.md` wrote "The crate has **no**
 * networking dependency", and every rule below that looks for a negation next to
 * a capability missed it over two asterisks. Only `*` is removed — `_` is more
 * often part of an identifier here (`open_sink`, `with_file`) than emphasis.
 */
function plain(text: string): string {
  return text.replaceAll('*', '')
}

/** Every problem in one document. `where` only labels the findings. */
export function checkDocument(source: string, where: string): Problem[] {
  const text = plain(source)
  const problems: Problem[] = []

  for (const { pattern, detail } of RETIRED) {
    for (const match of text.matchAll(pattern)) {
      problems.push({ where, detail: `retired claim "${match[0]}" — ${detail}` })
    }
  }

  for (const match of text.matchAll(/I\/O-free/gi)) {
    const window = text.slice(Math.max(0, match.index - 96), match.index)
    const sentence = window.slice(window.search(/[.!?\n][^.!?\n]*$/) + 1)
    if (!NEGATED.test(sentence)) {
      problems.push({
        where,
        detail: 'asserts the crate is I/O-free — it is transport-agnostic *and not* I/O-free, '
          + 'which is the whole distinction',
      })
    }
  }

  if (ASSERTS_INVARIANT.test(text) && CAPABILITY_ABSENCE.test(text) && !NAMES_THE_SINK.test(text)) {
    problems.push({
      where,
      detail: 'states what `honmoon-core` does not have without naming the one file it does open '
        + '(the operator\'s JSONL audit sink) — a reader takes the list for the whole rule',
    })
  }

  return problems
}

/** Published wiki pages plus the two aggregate files, relative to the repo root. */
export function wikiDocuments(): string[] {
  const pages = [...new Glob('**/*.md').scanSync(join(REPO_ROOT, 'wiki'))]
    .filter(rel => !UNPUBLISHED.includes(rel.split(/[/\\]/).pop()!))
    .map(rel => join('wiki', rel))
    .sort()
  return [...pages, join('wiki', 'llms.txt'), join('wiki', 'llms-full.txt')]
}

export function checkRepository(): Problem[] {
  return wikiDocuments().flatMap(rel =>
    checkDocument(readFileSync(join(REPO_ROOT, rel), 'utf8'), rel),
  )
}

export function main(): number {
  const documents = wikiDocuments()
  const problems = checkRepository()

  if (problems.length > 0) {
    for (const { where, detail } of problems) {
      console.error(`${where}: ${detail}`)
    }
    console.error(
      `\nwiki I/O claim: ${problems.length} problem(s). \`honmoon-core\` is transport-agnostic, `
      + 'not I/O-free — see `crates/AGENTS.md` under "What `honmoon-core` may touch".',
    )
    return 1
  }

  console.log(
    `wiki I/O claim: ${documents.length} documents describe honmoon-core as transport-agnostic `
    + 'rather than I/O-free',
  )
  return 0
}

if (import.meta.main) {
  process.exit(main())
}
