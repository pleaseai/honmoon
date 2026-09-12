/**
 * Check the built dashboard shells against the CSP the gateway serves them with.
 *
 * `honmoon-mgmt` serves the embedded dashboard under `script-src 'self'`
 * (`DASHBOARD_CSP` in `crates/honmoon-mgmt/src/lib.rs`, #195). That directive is
 * what bounds a script injection in the management origin, which since #188 is
 * the origin holding a script-readable session credential — but it holds only
 * while the *built* shell takes all of its script from files. Nothing in the
 * Rust header can enforce that: it is a property of whatever Vite emitted.
 *
 * So this runs over the built artifacts, in CI, after the build that produces
 * them. A bundler upgrade or a dependency that starts inlining a `<script>`
 * fails here — instead of shipping and blanking the dashboard behind a console
 * violation an operator would have to open devtools to see.
 *
 * Both shells are checked. `dist/` is what rust-embed bakes into the binary and
 * is the one the header applies to; `dist-demo/` is that same artifact plus the
 * demo shim's `<script>` tag (`apps/dashboard/demo/build.ts`), served by
 * Cloudflare Pages, and it is checked so the shim stays a same-origin file
 * reference rather than quietly becoming inline code.
 *
 * `style-src` is deliberately not checked: it carries `'unsafe-inline'`
 * (`react-simple-code-editor` renders a `<style>` element), so there is no
 * property here to keep.
 *
 * Usage:
 *   bun scripts/check-dashboard-csp.ts                 # both built shells
 *   bun scripts/check-dashboard-csp.ts <path…>         # explicit files
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

/** Repository root, resolved from this file rather than the working directory. */
export const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url))

/** The shells to check when no path is given, relative to the repository root. */
export const DEFAULT_SHELLS = [
  'apps/dashboard/dist/index.html',
  'apps/dashboard/dist-demo/index.html',
]

/** What produces each default shell, named in the error when one is missing. */
export const BUILD_COMMANDS = `bun run --filter '@honmoon/dashboard' build:demo`

/** `<script …>…</script>`, or a self-closed one. Built HTML, not arbitrary HTML. */
const SCRIPT_TAG = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi

/** A `src=` or `href=` value, quoted either way. */
const URL_ATTR = /\b(?:src|href)\s*=\s*(?:"([^"]*)"|'([^']*)')/gi

/** An inline event handler: `onclick="…"`. Refused by `script-src` without `'unsafe-inline'`. */
const EVENT_ATTR = /\son[a-z]+\s*=\s*["']/i

/**
 * A URL that leaves this origin: any scheme (`https:`, `data:`, `blob:`) or a
 * protocol-relative `//host`. A path — `/assets/x.js`, `./demo-mode.js` — stays.
 */
const OFF_ORIGIN = /^(?:[a-z][a-z0-9+.-]*:|\/\/)/i

/** One thing wrong with one shell. */
export interface Problem {
  shell: string
  detail: string
}

/**
 * Everything about `html` that the served CSP would refuse.
 *
 * Pure, so the test can exercise the rules without a build. `shell` only labels
 * the results.
 */
export function checkShell(html: string, shell: string): Problem[] {
  const problems: Problem[] = []
  const note = (detail: string) => problems.push({ shell, detail })

  const scripts = [...html.matchAll(SCRIPT_TAG)]

  // Anti-vacuity. `crates/honmoon-mgmt/build.rs` drops a script-less placeholder
  // `index.html` so a bare `cargo build` works without a dashboard; checking that
  // file would pass every rule below while proving nothing about a real build.
  if (scripts.length === 0) {
    note(
      'no <script> at all — this is not a built dashboard shell '
      + `(the placeholder from crates/honmoon-mgmt/build.rs?). Run \`${BUILD_COMMANDS}\`.`,
    )
  }

  for (const [tag, attrs, body] of scripts) {
    if (body.trim() !== '') {
      note(`inline <script> body, which \`script-src 'self'\` refuses: ${tag.slice(0, 120)}`)
    }
    if (!/\bsrc\s*=/i.test(attrs)) {
      note(`<script> with no src, which \`script-src 'self'\` refuses: <script${attrs}>`)
    }
  }

  for (const [attr, doubleQuoted, singleQuoted] of html.matchAll(URL_ATTR)) {
    const url = doubleQuoted ?? singleQuoted ?? ''
    // A fragment link (`href="#/audit"`) never leaves the document.
    if (url.startsWith('#') || !OFF_ORIGIN.test(url)) {
      continue
    }
    note(`loads from off this origin, which \`default-src 'none'\` refuses: ${attr}`)
  }

  if (EVENT_ATTR.test(html)) {
    note('an inline event handler attribute, which `script-src \'self\'` refuses')
  }
  if (/<base\b/i.test(html)) {
    note('a <base> element, which `base-uri \'none\'` refuses')
  }
  if (/<form\b/i.test(html)) {
    note('a <form> element, whose submission `form-action \'none\'` refuses')
  }

  return problems
}

/** Check the shells at `paths` (relative to the repository root, or absolute). */
export function checkShells(paths: string[]): Problem[] {
  return paths.flatMap((path) => {
    let html: string
    try {
      html = readFileSync(join(REPO_ROOT, path), 'utf8')
    }
    catch {
      // Not found is a failure, not a skip: a check that silently passes when
      // the artifact is missing is the one that lets a regression through.
      return [{ shell: path, detail: `not found — run \`${BUILD_COMMANDS}\` first` }]
    }
    return checkShell(html, path)
  })
}

export function main(argv: string[]): number {
  const paths = argv.length > 0 ? argv : DEFAULT_SHELLS
  const problems = checkShells(paths)

  if (problems.length > 0) {
    for (const { shell, detail } of problems) {
      console.error(`${shell}: ${detail}`)
    }
    console.error(
      `\ndashboard CSP: ${problems.length} problem(s). The gateway serves this shell under `
      + '`script-src \'self\'` (crates/honmoon-mgmt/src/lib.rs) — either keep the build '
      + 'script-from-files, or change that header deliberately.',
    )
    return 1
  }

  console.log(`dashboard CSP: ${paths.length} shell(s) load only same-origin script from files`)
  return 0
}

if (import.meta.main) {
  process.exit(main(process.argv.slice(2)))
}
