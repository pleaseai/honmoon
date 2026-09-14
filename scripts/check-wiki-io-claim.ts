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
 * asserting the opposite, and #207 then found the same sentence living in five
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
 * passes. The `I/O-free` negation search looks back 96 characters and stops at a
 * sentence boundary, so a denial further away than that reads as an assertion —
 * a false positive on correct prose rather than a miss. Neither rule reads
 * meaning. They are a floor under review, not a replacement for it — the same
 * checked/unchecked split `crates/AGENTS.md` draws around
 * `crates/honmoon-core/tests/crate_boundary.rs`.
 *
 * And nothing here checks that a page restating the *audit-sink hardening*
 * carries its caveats — the descriptor-scoped limit, the open issue #215 gap, the
 * `cfg(not(unix))` arm. Those are review's, and `crates/AGENTS.md` is where they
 * are written.
 *
 * `llms-full.txt` is scanned along with the pages. It is generated
 * (`wiki/.vitepress/gen-llms-full.mjs`) and inlines the pages it lists — every
 * page but `index.md` — so a page edited without regenerating it leaves the
 * retired wording there, which fails here rather than shipping to the readers
 * who consume that file.
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
 * Mirrors `srcExclude` in `wiki/.vitepress/config.mts`, including the part that
 * is easy to flatten. It globs `AGENTS.md` and `CLAUDE.md` with a leading
 * any-depth wildcard, but names `README.md` bare — and VitePress resolves a bare
 * entry against the source root only. So a nested `wiki/onboarding/README.md` is
 * a page it publishes, and excluding it by basename here would leave a real page
 * unscanned under a comment claiming the two lists agreed.
 *
 * The instruction files for agents working on the site are not pages, and a rule
 * written in one may quote the wording the pages must not use.
 */
const UNPUBLISHED_AT_ANY_DEPTH = new Set(['AGENTS.md', 'CLAUDE.md'])
const UNPUBLISHED_AT_ROOT = new Set(['README.md'])

/**
 * Directories under `wiki/` holding markdown that is not the site's source.
 *
 * `bun install` and `bun run build` inside `wiki/` leave both behind, and a
 * scan that picks them up reads a few hundred dependency READMEs — where a rule
 * here would be judging prose nobody in this repository wrote. The job that runs
 * this check — `ci.yml`'s `js` — installs at the repository root and never enters
 * `wiki/`, so the stray trees appear only after a local build, which is exactly
 * the run whose green a contributor trusts before pushing. Not "CI never installs
 * there": `deploy-wiki.yml` does, with `working-directory: wiki`. It does not run
 * this check today, and this filter is what would keep it honest if it ever did.
 */
const NOT_SOURCE = ['node_modules', '.vitepress/cache', '.vitepress/dist']

/** The hand-maintained link index, and the generated bundle of every page it lists. */
const LLMS = 'wiki/llms.txt'
const LLMS_FULL = 'wiki/llms-full.txt'

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
export const RETIRED: Rule[] = [
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
 * a capability missed it over two asterisks. `_` is emphasis only at a word's
 * edge (`_no_ networking`); between word characters it is an identifier
 * (`open_sink`, `with_file`) and stays, so `\bno\b` still finds the one and
 * never tears the other.
 */
function plain(text: string): string {
  return text.replaceAll('*', '').replace(/\b_+|_+\b/g, '')
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

/**
 * Published wiki pages plus the two aggregate files, relative to the repo root.
 *
 * Always `/`-separated, whatever the host's separator: the paths label findings
 * and are what the tests assert on, and `readFileSync` accepts them everywhere.
 * The sort is by code unit, spelled out so the order does not depend on a
 * locale.
 */
export function wikiDocuments(): string[] {
  const pages = [...new Glob('**/*.md').scanSync(join(REPO_ROOT, 'wiki'))]
    .map(rel => rel.split(/[/\\]/))
    .filter(parts => !UNPUBLISHED_AT_ANY_DEPTH.has(parts.at(-1)!))
    .filter(parts => !(parts.length === 1 && UNPUBLISHED_AT_ROOT.has(parts[0]!)))
    .filter(parts => !NOT_SOURCE.some(dir => parts.join('/').startsWith(`${dir}/`)))
    .map(parts => ['wiki', ...parts].join('/'))
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
  return [...pages, LLMS, LLMS_FULL]
}

/**
 * The pages `llms-full.txt` says it inlines, as it names them.
 *
 * The generator writes one `<doc … path="wiki/…">` per page it bundles, so the
 * committed artifact carries the canonical page list without this file keeping a
 * second copy of it to drift.
 */
export function inlinedPages(aggregate: string): string[] {
  return [...aggregate.matchAll(/<doc\s[^>]*\bpath="([^"]+)"/g)].map(match => match[1]!)
}

/**
 * Findings about the *scan* rather than about any document's prose.
 *
 * Without this the guard's failure mode is a vacuous pass. `wikiDocuments()`
 * appends `llms.txt` and `llms-full.txt` unconditionally and discovers everything
 * else by glob, so anything that stops the glob matching pages — an `.mdx`
 * migration, a directory rename, a pattern regression — leaves it scanning two
 * committed files that contain no retired wording. `checkRepository()` would
 * return `[]`, the end-to-end test would stay green, and every published page
 * would be unread, while `main()` kept printing a reassuring document count.
 *
 * Cross-checking against the bundle's own `<doc>` list is what makes that loud
 * instead: a page the generator bundles but the scan did not reach is reported.
 * It needs no floor number to rot, and it moves on its own when a page is added.
 */
export function checkCoverage(documents: string[], aggregate: string): Problem[] {
  const scanned = new Set(documents)
  return inlinedPages(aggregate)
    .filter(page => !scanned.has(page))
    .map(page => ({
      where: LLMS_FULL,
      detail: `bundles \`${page}\`, which the page scan did not reach — the scan is not seeing `
        + 'the published wiki, so a clean result here would mean nothing',
    }))
}

export function checkRepository(): Problem[] {
  const documents = wikiDocuments()
  const read = (rel: string): string => readFileSync(join(REPO_ROOT, rel), 'utf8')
  return [
    ...checkCoverage(documents, read(LLMS_FULL)),
    ...documents.flatMap(rel => checkDocument(read(rel), rel)),
  ]
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
      + 'not I/O-free — see `crates/AGENTS.md` under "What `honmoon-core` may touch".\n'
      + 'Rewrite the page so the passage reaches that rule (no async runtime, no socket, no '
      + 'network client, and exactly one file: the operator\'s JSONL audit sink), then regenerate '
      + 'the bundle: `cd wiki && bun .vitepress/gen-llms-full.mjs`. A finding only in '
      + '`wiki/llms-full.txt` means the page was fixed and the bundle was not regenerated.',
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
