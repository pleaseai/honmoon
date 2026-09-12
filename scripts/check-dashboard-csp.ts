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
 * An `<a href>` to another origin is not a violation and is not flagged: CSP
 * governs what the document fetches, not where a link takes the reader. The
 * rule has to be that narrow to be usable — a checker that failed the build
 * over a working link would be its own version of "a CSP that breaks the
 * dashboard is worse than none".
 *
 * **Scope: the shell's own markup, not the code it loads.** This reads
 * `index.html` and nothing else, so it is a guard on the shell's `<script>`
 * tags rather than on everything `script-src 'self'` implies. It would not see
 * a dependency that introduces `eval(`/`new Function(` into the emitted bundle,
 * which the policy also refuses (there is no `'unsafe-eval'`) — absent from
 * today's bundle, and tracked separately rather than claimed here.
 *
 * Usage:
 *   bun scripts/check-dashboard-csp.ts                 # both built shells
 *   bun scripts/check-dashboard-csp.ts <path…>         # explicit files
 */
import { readFileSync } from 'node:fs'
import { isAbsolute, join } from 'node:path'
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

/**
 * An attribute span inside an opening tag, as a regex source fragment.
 *
 * `[^>]*` would end the tag at the first `>`, including one inside a quoted
 * value (`<a href="a>b">`) — and every attribute after it in that tag would then
 * go unread, which is a miss rather than a finding. Quoted runs are consumed
 * whole so only a real tag terminator ends the span.
 */
const ATTRS = String.raw`(?:"[^"]*"|'[^']*'|[^>])*`

/** A complete `<script …>…</script>` pair. Built HTML, not arbitrary HTML. */
const SCRIPT_TAG = new RegExp(String.raw`<script\b(${ATTRS})>([\s\S]*?)<\/script>`, 'gi')

/**
 * Any `<script` opening tag, counted separately from {@link SCRIPT_TAG}.
 *
 * The pair regex is lazy and skips an opening tag it finds no `</script>` for,
 * so a trailing unclosed `<script>` — the shape a build step that appends code
 * produces — would otherwise leave no match and no finding, while an earlier
 * well-formed tag kept the count non-zero and satisfied the anti-vacuity guard
 * below. A shell this file cannot fully parse must fail, not pass.
 */
const SCRIPT_OPEN = /<script\b/gi

/** An element's opening tag: its name, and everything up to the closing `>`. */
const OPEN_TAG = new RegExp(String.raw`<([a-z][a-z0-9-]*)\b(${ATTRS})>`, 'gi')

/**
 * A `src=` or `href=` value: double-quoted, single-quoted, or bare.
 *
 * HTML does not require the quotes, and a browser fetches an unquoted value
 * just the same — so a pattern that insisted on them would pass a shell the
 * policy then refuses.
 */
const URL_ATTR = /\b(src|href)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/gi

/**
 * A `javascript:` URL — script, wherever it is carried.
 *
 * `script-src 'self'` refuses one (it needs `'unsafe-inline'`), so it is a
 * finding even in an `href` the navigation exemption below would otherwise skip:
 * that exemption exists because a *navigation* is not a fetch, and this is not a
 * navigation, it is code.
 */
const JAVASCRIPT_URL = /^\s*javascript:/i

/** A character reference inside an attribute value: `&#x73;`, `&#115;`, `&amp;`. */
const CHAR_REF = /&(?:#x([0-9a-f]+)|#(\d+)|([a-z][a-z0-9]*));?/gi

/** The named references that can appear in a scheme or in one that hides a scheme. */
const NAMED_REFS: Record<string, string> = {
  amp: '&',
  colon: ':',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: '\'',
  tab: '\t',
  newline: '\n',
  NewLine: '\n',
}

/**
 * An attribute value as the *browser* sees it, not as the file spells it.
 *
 * The HTML parser resolves character references before anything reads the value
 * as a URL, so `href="java&#x73;cript:go()"` is a `javascript:` URL to a browser
 * while a raw-prefix test sees a relative path — it bypassed both the scheme
 * check and {@link OFF_ORIGIN}, since `&` ends the scheme grammar there too.
 *
 * Decoded once, deliberately: `&amp;#x73;` is the literal text `&#x73;` in the
 * DOM, not a second reference, so decoding twice would invent a finding.
 * Control characters are dropped because a browser strips them from a scheme
 * (`java\tscript:` navigates), which is the other half of the same evasion.
 */
export function decodeAttr(value: string): string {
  return value
    .replace(CHAR_REF, (whole, hex, dec, name) => {
      if (hex !== undefined) {
        return String.fromCodePoint(Number.parseInt(hex, 16))
      }
      if (dec !== undefined) {
        return String.fromCodePoint(Number.parseInt(dec, 10))
      }
      return NAMED_REFS[name] ?? NAMED_REFS[name.toLowerCase()] ?? whole
    })
    // eslint-disable-next-line no-control-regex -- stripping them is the point
    .replace(/[\u0000-\u0020\u007F]/g, c => (c === ' ' ? ' ' : ''))
}

/**
 * Elements whose `href` is a *navigation*, not a subresource load.
 *
 * `default-src 'none'` governs what the document fetches; it does not govern
 * where a link takes the reader, and no CSP directive restricts an outbound
 * navigation at all. So an ordinary `<a href="https://…">` is not a violation,
 * and flagging one would fail the build over a link that works — the checker's
 * own version of "a CSP that breaks the dashboard is worse than none".
 * `<link href>` is the opposite case and stays checked: that one is a fetch.
 */
const NAVIGATION_HREF = new Set(['a', 'area'])

/**
 * An inline event handler: `onclick="…"`, or unquoted as `onclick=go()`.
 *
 * The value is not required to be quoted — HTML does not require it, and
 * `script-src` refuses the handler either way, so requiring a quote here would
 * pass a shell the browser would break on.
 */
const EVENT_ATTR = /\son[a-z]+\s*=/i

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
  const opened = [...html.matchAll(SCRIPT_OPEN)].length

  // Anti-vacuity. `crates/honmoon-mgmt/build.rs` drops a script-less placeholder
  // `index.html` so a bare `cargo build` works without a dashboard; checking that
  // file would pass every rule below while proving nothing about a real build.
  // Counted on opening tags, so a shell whose only script is unreadable below
  // still reports what it actually is rather than "not built".
  if (opened === 0) {
    note(
      'no <script> at all — this is not a built dashboard shell '
      + `(the placeholder from crates/honmoon-mgmt/build.rs?). Run \`${BUILD_COMMANDS}\`.`,
    )
  }

  // Every opening tag must belong to a pair this file could read. One that does
  // not is either unclosed or written `<script/>` (which HTML does not honour as
  // self-closing), and either way its content went uninspected — so it fails
  // here rather than passing as the absence of a finding.
  if (opened > scripts.length) {
    note(
      `${opened - scripts.length} <script> tag(s) with no readable \`</script>\`, whose content `
      + 'this check therefore never inspected — refusing to pass on a shell it cannot fully read',
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

  for (const [, tag, attrs] of html.matchAll(OPEN_TAG)) {
    const element = tag.toLowerCase()
    for (const [attr, name, doubleQuoted, singleQuoted, bare] of attrs.matchAll(URL_ATTR)) {
      const raw = doubleQuoted ?? singleQuoted ?? bare ?? ''
      const url = decodeAttr(raw)
      if (JAVASCRIPT_URL.test(url)) {
        note(`<${element}> carries a javascript: URL, which \`script-src 'self'\` refuses: ${attr}`)
        continue
      }
      if (name.toLowerCase() === 'href' && NAVIGATION_HREF.has(element)) {
        continue
      }
      // A fragment link (`href="#/audit"`) never leaves the document.
      if (url.startsWith('#') || !OFF_ORIGIN.test(url)) {
        continue
      }
      note(
        `<${element}> loads from off this origin, which \`default-src 'none'\` refuses: ${attr}`,
      )
    }
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
      // `join` would graft an absolute argument onto the root — `join('/repo',
      // '/tmp/x')` is `/repo/tmp/x` — and report the result as "not found",
      // which reads as a missing build rather than as a misread path.
      html = readFileSync(isAbsolute(path) ? path : join(REPO_ROOT, path), 'utf8')
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

  // The paths, not just the count: invoked with arguments this checks whatever
  // it was given, and a bare count would read the same for a narrowed set.
  console.log(
    `dashboard CSP: ${paths.length} shell(s) load only same-origin script from files `
    + `(${paths.join(', ')})`,
  )
  return 0
}

if (import.meta.main) {
  process.exit(main(process.argv.slice(2)))
}
