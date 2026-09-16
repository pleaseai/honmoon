// Generates llms-full.txt: full page content inlined in <doc> blocks, frontmatter stripped.
//
// `renderBundle()` is exported because `scripts/check-wiki-bundle-current.ts`
// holds the requirement in `AGENTS.md` that a content change is followed by a
// regeneration, and the only way to check that without re-implementing this
// file — which could then drift from it exactly the way the bundle drifts from
// the pages — is to call it.
import { readFileSync, realpathSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

const wikiRoot = join(dirname(fileURLToPath(import.meta.url)), '..')

// Section order per the llms.txt spec: Onboarding → Architecture → Getting Started → Deep Dive.
const pages = [
  ['onboarding/contributor-guide.md', 'Contributor Guide'],
  ['onboarding/staff-engineer-guide.md', 'Staff Engineer Guide'],
  ['onboarding/executive-guide.md', 'Executive Guide'],
  ['onboarding/product-manager-guide.md', 'Product Manager Guide'],
  ['deep-dive/architecture.md', 'Architecture'],
  ['deep-dive/policy-engine.md', 'Policy Model & Decision Engine'],
  ['deep-dive/protocol-parsing.md', 'Protocol-Aware Parsing'],
  ['deep-dive/egress-gateway.md', 'Egress Gateway (Data Plane)'],
  ['deep-dive/control-plane.md', 'Control Plane & Dashboard'],
  ['getting-started/overview.md', 'Overview'],
  ['getting-started/installation.md', 'Installation & Toolchain'],
  ['getting-started/quick-start.md', 'Quick Start'],
  ['getting-started/policy-authoring.md', 'Policy Authoring'],
  ['deep-dive/roadmap-open-core.md', 'Roadmap & Open-Core Model'],
]

function stripFrontmatter(src) {
  if (src.startsWith('---')) {
    const end = src.indexOf('\n---', 3)
    if (end !== -1) return src.slice(src.indexOf('\n', end + 1) + 1).replace(/^\n+/, '')
  }
  return src
}

const header = `# Honmoon — Full Documentation

> A policy-based firewall gateway guarding the boundary between AI agents and production systems.
> Full wiki content inlined for LLM consumption. Phases 0–3 implemented and tested; Phases 4–7 are
> roadmap. Implemented vs planned is marked throughout.

`

/** Where the bundle is written, and where the check reads it back from. */
export const BUNDLE_PATH = join(wikiRoot, 'llms-full.txt')

/** How many pages a full bundle inlines, for a caller reporting the result. */
export const PAGE_COUNT = pages.length

/**
 * The exact bytes `llms-full.txt` must hold, built from the pages on disk.
 *
 * Pure: it reads the pages and returns the text, so a caller can compare the
 * result against the committed file without writing anything.
 */
export function renderBundle() {
  let out = header
  for (const [rel, title] of pages) {
    const body = stripFrontmatter(readFileSync(join(wikiRoot, rel), 'utf8')).trimEnd()
    out += `<doc title="${title}" path="wiki/${rel}">\n${body}\n</doc>\n\n`
  }
  return out
}

/**
 * Whether this file is the entry point, rather than an import.
 *
 * Not `import.meta.main`, which is Bun and Node >= 24.2 only. `wiki/AGENTS.md`
 * documents this as a `bun` command, but it is plain ESM that has been run with
 * `node` too, and on an older Node `import.meta.main` reads as `undefined` — so
 * the guard would skip the write, exit 0, and leave a contributor believing
 * they had regenerated the bundle. That is the silent staleness this file's
 * checker exists to catch, and it should not be introduced here to build it.
 * Comparing the entry path works on every runtime that can run the file at all.
 */
function invokedAsScript() {
  const entry = process.argv[1]
  if (entry === undefined) {
    return false
  }
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url))
  }
  catch {
    return false
  }
}

if (invokedAsScript()) {
  const out = renderBundle()
  writeFileSync(BUNDLE_PATH, out)
  console.log(`wrote llms-full.txt (${out.length} bytes, ${PAGE_COUNT} docs)`)
}
