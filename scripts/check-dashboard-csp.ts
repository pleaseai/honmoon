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
 * Every URL it does judge is resolved with `new URL`, not matched by pattern.
 * Four rounds of review found four ways a pattern reads a URL differently from
 * the browser that will fetch it — a hidden scheme, a hidden authority, a
 * leading space, a backslash — so the parser decides, and this file only
 * decodes the character references that come before it (an HTML-level step the
 * URL parser does not do).
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
 * Two stand-in origins the shell's URLs are resolved against.
 *
 * `new URL` is the parser a browser uses, and it applies the rules a regex over
 * the raw text cannot see: leading spaces and control characters are stripped
 * before the scheme is read, a tab inside the scheme is removed
 * (`java<TAB>script:` *is* a `javascript:` URL), and a backslash stands in for
 * a slash in the authority, so `/\\cdn.example/x` leaves this origin rather
 * than being the path it looks like.
 *
 * Two of them, because the real serving origin is not known at build time: the
 * gateway serves this shell from whatever `--mgmt-addr` it was given, and the
 * demo build from Cloudflare Pages. So there is no host to compare against, and
 * comparing against one stand-in would make a URL that *names* that stand-in
 * read as same-origin. Resolving against two answers the question that actually
 * matters without naming a host at all: a relative URL follows its base and the
 * two results differ, while an absolute one — scheme or protocol-relative —
 * resolves the same way under both, and is off-origin wherever this is served.
 */
const SHELL_BASE = 'https://dashboard.invalid/index.html'
const OTHER_BASE = 'https://elsewhere.invalid/index.html'

/** A character reference inside an attribute value: `&#x73;`, `&#115;`, `&amp;`. */
const CHAR_REF = /&(?:#x([0-9a-f]+)|#(\d+)|([a-z][a-z0-9]*));?/gi

/**
 * The named references that can carry, hide, or sit inside a scheme or authority.
 *
 * Deliberately not the full HTML table — that is ~2200 entries and would be a
 * dependency. It does not have to be complete, because a name that is *not*
 * here is reported rather than passed through: see {@link UNKNOWN_REF}.
 */
const NAMED_REFS: Record<string, string> = {
  amp: '&',
  AMP: '&',
  apos: '\'',
  colon: ':',
  gt: '>',
  GT: '>',
  lt: '<',
  LT: '<',
  NewLine: '\n',
  num: '#',
  period: '.',
  quot: '"',
  QUOT: '"',
  sol: '/',
  Tab: '\t',
}

/**
 * A named reference {@link NAMED_REFS} does not cover.
 *
 * Matched against the raw attribute token by token, not against what the decode
 * left behind: `&amp;hellip;` is one reference the table knows followed by the
 * literal text `hellip;`, and scanning the decoded value would read that text
 * back as a second reference and fail the build over a working link. A `;` is
 * required for the same reason — `?a=1&b=2` is a query string, and the four
 * legacy names a browser honours unterminated (`&amp`, `&lt`, `&gt`, `&quot`)
 * spell neither a scheme nor an authority.
 */
const UNKNOWN_REF = /^[a-z][a-z0-9]*$/i

/**
 * A numeric reference's character, the way the HTML parser resolves one.
 *
 * `&#0;`, a lone surrogate, and anything past the last plane all parse to
 * U+FFFD per the spec. `String.fromCodePoint` throws a `RangeError` on each,
 * which in CI is a stack trace where a finding belongs — and the shell that
 * produced it goes unchecked either way.
 */
function fromCodePoint(code: number): string {
  if (code === 0 || code > 0x10FFFF || (code >= 0xD800 && code <= 0xDFFF)) {
    return '\uFFFD'
  }
  return String.fromCodePoint(code)
}

/**
 * An attribute value with its character references resolved, as the HTML parser
 * resolves them before anything reads the value as a URL.
 *
 * Without this, `href="java&#x73;cript:go()"` reads as a relative path here and
 * as a `javascript:` URL in a browser.
 *
 * Decoded once, deliberately: `&amp;#x73;` is the literal text `&#x73;` in the
 * DOM, not a second reference, so decoding twice would invent a finding.
 *
 * `unknown` names a reference the table does not cover, for the caller to
 * report. Its gaps have to fail the build rather than pass it — the stance the
 * unreadable-`<script>` rule takes above — because an undecoded name could be
 * standing in for the `:` or the `/` the caller is about to look for.
 *
 * Nothing else is normalised here: whitespace, control characters and
 * backslashes are the URL parser's business, and {@link SHELL_BASE} says why
 * deciding them with a pattern is what kept going wrong.
 */
export function decodeAttr(value: string): { url: string, unknown: string | null } {
  let unknown: string | null = null
  const url = value.replace(CHAR_REF, (whole, hex, dec, name) => {
    if (hex !== undefined || dec !== undefined) {
      return fromCodePoint(Number.parseInt(hex ?? dec, hex === undefined ? 10 : 16))
    }
    const decoded = NAMED_REFS[name]
    if (decoded === undefined && whole.endsWith(';') && UNKNOWN_REF.test(name)) {
      unknown ??= whole
    }
    return decoded ?? whole
  })
  return { url, unknown }
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
      const { url, unknown } = decodeAttr(doubleQuoted ?? singleQuoted ?? bare ?? '')
      if (unknown !== null) {
        note(
          `<${element}> carries the character reference \`${unknown}\`, which this check cannot `
          + `decode, so it cannot tell where the URL points — refusing to pass on it: ${attr}`,
        )
        continue
      }

      let here: URL
      let there: URL
      try {
        here = new URL(url, SHELL_BASE)
        there = new URL(url, OTHER_BASE)
      }
      catch {
        // Unparseable to this parser is unparseable to the check, while a
        // browser may still make something of it — so it fails rather than
        // passes, as everything else this file cannot read does.
        note(`<${element}> carries a URL this check could not parse: ${attr}`)
        continue
      }

      if (here.protocol === 'javascript:') {
        note(`<${element}> carries a javascript: URL, which \`script-src 'self'\` refuses: ${attr}`)
        continue
      }
      if (name.toLowerCase() === 'href' && NAVIGATION_HREF.has(element)) {
        continue
      }
      // Followed its base, so it is relative — a path, or a fragment link like
      // `href="#/audit"` that resolves to this very document.
      if (here.href !== there.href) {
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
