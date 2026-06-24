// Generates llms-full.txt: full page content inlined in <doc> blocks, frontmatter stripped.
import { readFileSync, writeFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
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

let out = header
for (const [rel, title] of pages) {
  const body = stripFrontmatter(readFileSync(join(wikiRoot, rel), 'utf8')).trimEnd()
  out += `<doc title="${title}" path="wiki/${rel}">\n${body}\n</doc>\n\n`
}

writeFileSync(join(wikiRoot, 'llms-full.txt'), out)
console.log(`wrote llms-full.txt (${out.length} bytes, ${pages.length} docs)`)
