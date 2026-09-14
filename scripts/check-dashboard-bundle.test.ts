import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import { checkBundle, checkBundles, inspectBundles } from './check-dashboard-bundle'

function details(code: string): string[] {
  return checkBundle(code, 'chunk.js').map(problem => problem.detail)
}

describe('checkBundle', () => {
  // The shape the issue names: a dependency that reaches for the Function
  // constructor ships a dashboard that blanks behind a console violation,
  // because the served policy carries no `'unsafe-eval'`.
  test('`new Function(…)` fails', () => {
    expect(details('const compile = (src) => new Function("a", src)')).toEqual([
      expect.stringContaining('`Function` constructor'),
    ])
  })

  test('`Function(…)` without `new` fails — it is the same constructor', () => {
    expect(details('export const f = Function("return 1")')).toEqual([
      expect.stringContaining('`Function` constructor'),
    ])
  })

  test('a direct `eval(…)` call fails', () => {
    expect(details('function run(s) { return eval(s) }')).toEqual([
      expect.stringContaining('call to `eval`'),
    ])
  })

  // What a bundler emits for indirect eval, so the parenthesised comma form has
  // to be read through rather than treated as an opaque callee.
  test('the `(0, eval)(…)` form a bundler emits fails', () => {
    expect(details('const r = (0, eval)("x")')).toEqual([
      expect.stringContaining('call to `eval`'),
    ])
  })

  // `window.eval` and `globalThis.Function` are the real global bindings, and
  // the policy refuses both exactly as it refuses the bare names.
  test.each([
    ['window.eval', 'window.eval("x")', 'call to `eval`'],
    ['globalThis.eval', 'globalThis.eval("x")', 'call to `eval`'],
    ['self.eval', 'self.eval("x")', 'call to `eval`'],
    ['window["eval"]', 'window["eval"]("x")', 'call to `eval`'],
    ['new globalThis.Function', 'new globalThis.Function("x")', '`Function` constructor'],
  ])('%s reaches the global binding and fails', (_label, code, detail) => {
    expect(details(code)).toEqual([expect.stringContaining(detail)])
  })

  // The false positive this guard exists to avoid. A CI gate that blocks an
  // unrelated dependency bump is "a CSP that breaks the dashboard is worse than
  // no CSP" moved one layer out (#199), so the characters must not be the rule.
  test('the string `"eval("` inside a literal passes', () => {
    expect(checkBundle('const warn = "eval( is refused by the policy"', 'chunk.js')).toEqual([])
  })

  test.each([
    ['a template literal', 'const t = `new Function( and eval( are refused`'],
    ['a line comment', '// eval(x) and new Function(y) are refused\nconst a = 1'],
    ['a block comment', '/* eval(x) */ const a = 1'],
    ['a regular expression', 'const re = /eval\\(|new Function\\(/g'],
  ])('the characters in %s pass — this reads code, not text', (_label, code) => {
    expect(checkBundle(code, 'chunk.js')).toEqual([])
  })

  // Optional chaining is ordinary bundler output and `eval?.(src)` still calls
  // the global `eval`. It works today only because `ts.isCallExpression` covers
  // both forms, so pin it rather than leave it to a refactor.
  test.each([
    ['eval?.(x)', 'eval?.("x")'],
    ['window?.eval(x)', 'window?.eval("x")'],
  ])('the optional-call form %s still fails', (_label, code) => {
    expect(details(code)).toEqual([expect.stringContaining('call to `eval`')])
  })

  // The parenthesis unwrap on its own, without the comma operator that reaches
  // it in `(0, eval)(…)` — a different path through the same recursion.
  test.each([
    ['(Function)("x")', '(Function)("x")'],
    ['new (Function)("x")', 'new (Function)("x")'],
  ])('a bare parenthesised callee %s fails', (_label, code) => {
    expect(details(code)).toEqual([expect.stringContaining('`Function` constructor')])
  })

  // Declared non-coverage, pinned so it stays a decision rather than becoming
  // an accident: a computed name is not followed, and neither is an alias.
  test.each([
    ['a computed name', 'const k = "eval"\nwindow[k]("x")'],
    ['an alias', 'const f = Function\nf("x")'],
  ])('%s passes — the module doc declares this is not followed', (_label, code) => {
    expect(checkBundle(code, 'chunk.js')).toEqual([])
  })

  // The case a regex gets wrong most often: a method named `eval` on something
  // that is not the global object is not the global `eval` and is not refused
  // by any directive.
  test('`obj.eval(x)` passes — a method named `eval` is not the global one', () => {
    expect(checkBundle('const v = interpreter.eval(node)', 'chunk.js')).toEqual([])
  })

  // A plain object would resolve these through the prototype chain — truthy —
  // and report `function toString() { [native code] }` as the finding. The same
  // false positive the parse exists to avoid, arriving through the lookup.
  test.each([
    ['constructor', 'constructor(x)'],
    ['toString', 'toString(x)'],
    ['valueOf', 'valueOf(x)'],
    ['hasOwnProperty', 'hasOwnProperty(x)'],
    ['window.toString', 'window.toString(x)'],
  ])('a call to `%s` passes — a prototype member is not a refused construct', (_label, code) => {
    expect(checkBundle(code, 'chunk.js')).toEqual([])
  })

  test('`obj.Function(x)` passes for the same reason', () => {
    expect(checkBundle('const v = lib.Function("x")', 'chunk.js')).toEqual([])
  })

  // Same stance as the shell checker's unreadable-`<script>` rule: a file this
  // cannot read is a failure, not the absence of a finding.
  test('a file this cannot parse fails rather than passing uninspected', () => {
    expect(details('const a = ;;; function (')).toEqual([
      expect.stringContaining('could not parse'),
    ])
  })

  test('the finding names where in the file to look', () => {
    const problems = checkBundle('const a = 1\nconst b = eval("x")\n', 'chunk.js')
    expect(problems).toHaveLength(1)
    expect(problems[0].detail).toContain('2:11')
    expect(problems[0].file).toBe('chunk.js')
  })
})

describe('checkBundles', () => {
  let root: string

  /** A shell and its assets, laid out the way `vite build` lays `dist/` out. */
  function shell(name: string, scripts: string, assets: Record<string, string>): string {
    const dir = join(root, name)
    mkdirSync(join(dir, 'assets'), { recursive: true })
    writeFileSync(
      join(dir, 'index.html'),
      `<!doctype html><html><head>${scripts}</head><body><div id="root"></div></body></html>`,
    )
    for (const [path, code] of Object.entries(assets)) {
      writeFileSync(join(dir, path), code)
    }
    return join(dir, 'index.html')
  }

  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), 'honmoon-bundle-'))
  })
  afterAll(() => {
    rmSync(root, { recursive: true, force: true })
  })

  test('every file the shell loads is checked, not just the first', () => {
    const path = shell(
      'many',
      '<script src="./demo-mode.js"></script>'
      + '<script type="module" crossorigin src="/assets/index-abc.js"></script>',
      { 'demo-mode.js': 'window.fetch = f', 'assets/index-abc.js': 'const c = new Function("x")' },
    )
    expect(checkBundles([path])).toEqual([
      { file: expect.stringContaining('assets/index-abc.js'), detail: expect.stringContaining('`Function` constructor') },
    ])
  })

  test('a clean build passes', () => {
    const path = shell(
      'clean',
      '<script type="module" crossorigin src="/assets/index-abc.js"></script>',
      { 'assets/index-abc.js': 'const a = "eval("\nexport default a\n' },
    )
    expect(checkBundles([path])).toEqual([])
  })

  // The shell checker refuses a shell with no `<script>` because that is the
  // placeholder `crates/honmoon-mgmt/build.rs` writes. This one has to refuse
  // it too: with no file to read, every rule above would pass vacuously.
  test('a shell that loads no script file fails rather than passing vacuously', () => {
    const path = shell('empty', '<title>Honmoon</title>', {})
    expect(checkBundles([path])).toEqual([
      { file: path, detail: expect.stringContaining('no <script src>') },
    ])
  })

  test('a script the shell names but the build did not emit fails', () => {
    const path = shell(
      'missing',
      '<script type="module" src="/assets/index-gone.js"></script>',
      {},
    )
    expect(checkBundles([path])).toEqual([
      { file: expect.stringContaining('assets/index-gone.js'), detail: expect.stringContaining('not found') },
    ])
  })

  // Reading the file is impossible, so the check cannot say what runs. The
  // shell checker fails this shell too; neither may pass it.
  test('an off-origin <script src> fails — there is no file to read', () => {
    const path = shell('offorigin', '<script src="https://cdn.example/app.js"></script>', {})
    expect(checkBundles([path])).toEqual([
      { file: path, detail: expect.stringContaining('https://cdn.example/app.js') },
    ])
  })

  // What CI actually runs: `DEFAULT_SHELLS` is two shells in one call, and the
  // findings accumulate across the loop rather than per shell.
  test('two shells in one call are both checked, and each finding names its own', () => {
    const clean = shell(
      'pair-clean',
      '<script type="module" src="/assets/index-abc.js"></script>',
      { 'assets/index-abc.js': 'export const a = 1' },
    )
    const dirty = shell(
      'pair-dirty',
      '<script type="module" src="/assets/index-def.js"></script>',
      { 'assets/index-def.js': 'const c = eval("x")' },
    )
    expect(checkBundles([clean, dirty])).toEqual([
      { file: expect.stringContaining('pair-dirty'), detail: expect.stringContaining('call to `eval`') },
    ])
  })

  // `scriptFiles` reports an unclosed tag rather than dropping it, so the file
  // set is non-empty and the anti-vacuity rule does not fire — the finding has
  // to come from the unresolved entry itself or the shell passes unread.
  test('an unclosed <script> fails even when the other tags resolved', () => {
    const path = shell(
      'unclosed',
      '<script type="module" src="/assets/index-abc.js"></script><script src="/assets/late.js">',
      { 'assets/index-abc.js': 'export const a = 1', 'assets/late.js': 'eval("x")' },
    )
    expect(checkBundles([path])).toEqual([
      { file: path, detail: expect.stringContaining('no readable `</script>`') },
    ])
  })

  test('a missing shell fails rather than being skipped', () => {
    expect(checkBundles(['apps/dashboard/dist/no-such-shell.html'])).toEqual([
      { file: 'apps/dashboard/dist/no-such-shell.html', detail: expect.stringContaining('not found') },
    ])
  })
})

// The gap #227 names: the shell's `<script src>` tags and the set the browser
// executes are the same only while the build emits one chunk. A lazy route or a
// `manualChunks` entry emits a chunk the entry imports and the shell references
// only as `<link rel="modulepreload">`, so the walk has to reach it.
describe('the module graph beyond the shell tags', () => {
  let root: string

  /** A shell and its assets, laid out the way `vite build` lays `dist/` out. */
  function shell(name: string, scripts: string, assets: Record<string, string>): string {
    const dir = join(root, name)
    mkdirSync(join(dir, 'assets'), { recursive: true })
    writeFileSync(
      join(dir, 'index.html'),
      `<!doctype html><html><head>${scripts}</head><body><div id="root"></div></body></html>`,
    )
    for (const [path, code] of Object.entries(assets)) {
      writeFileSync(join(dir, path), code)
    }
    return join(dir, 'index.html')
  }

  /** The one `<script src>` tag Vite emits for the entry chunk. */
  const ENTRY = '<script type="module" crossorigin src="/assets/index-abc.js"></script>'

  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), 'honmoon-graph-'))
  })
  afterAll(() => {
    rmSync(root, { recursive: true, force: true })
  })

  test.each([
    ['a static import', 'import "./lazy-def.js"\n'],
    ['a namespace import', 'import * as lazy from "./lazy-def.js"\nexport { lazy }\n'],
    ['a dynamic import()', 'const go = () => import("./lazy-def.js")\nexport { go }\n'],
    ['an `export … from`', 'export * from "./lazy-def.js"\n'],
    ['a template-literal specifier', 'const go = () => import(`./lazy-def.js`)\nexport { go }\n'],
  ])('%s reaches a chunk the shell never names', (label, entry) => {
    const path = shell(`reach-${label.replaceAll(/\W/g, '')}`, ENTRY, {
      'assets/index-abc.js': entry,
      'assets/lazy-def.js': 'export const run = (s) => eval(s)\n',
    })
    expect(checkBundles([path])).toEqual([
      {
        file: expect.stringContaining('assets/lazy-def.js'),
        detail: expect.stringContaining('call to `eval`'),
      },
    ])
  })

  test('the walk is transitive, not one level deep', () => {
    const path = shell('deep', ENTRY, {
      'assets/index-abc.js': 'import "./a.js"\n',
      'assets/a.js': 'import "./b.js"\n',
      'assets/b.js': 'import "../c.js"\n',
      'c.js': 'const c = new Function("x")\nexport default c\n',
    })
    expect(checkBundles([path])).toEqual([
      {
        file: expect.stringContaining('c.js'),
        detail: expect.stringContaining('`Function` constructor'),
      },
    ])
  })

  // A bundler emits circular chunks routinely, so the walk has to terminate on
  // one — and report the finding inside it exactly once.
  test('an import cycle terminates and reports once', () => {
    const path = shell('cycle', ENTRY, {
      'assets/index-abc.js': 'import "./a.js"\nexport const e = 1\n',
      'assets/a.js': 'import "./b.js"\nexport const a = 1\n',
      'assets/b.js': 'import "./a.js"\nimport "./index-abc.js"\nexport const b = eval("x")\n',
    })
    expect(checkBundles([path])).toEqual([
      { file: expect.stringContaining('assets/b.js'), detail: expect.stringContaining('call to `eval`') },
    ])
  })

  // Two entries reaching one shared chunk. Parsing it twice would report its
  // finding twice and count it twice in the pass line.
  test('a diamond is read once', () => {
    const path = shell(
      'diamond',
      `${ENTRY}<script type="module" src="/assets/second.js"></script>`,
      {
        'assets/index-abc.js': 'import "./shared.js"\n',
        'assets/second.js': 'import "./shared.js"\n',
        'assets/shared.js': 'export const s = 1\n',
      },
    )
    const { files, problems } = inspectBundles([path])
    expect(problems).toEqual([])
    expect(files.filter(file => file.endsWith('shared.js'))).toHaveLength(1)
    expect(files).toHaveLength(3)
  })

  // The pass line is what an operator reads to see the guard was not vacuous,
  // so the widened set has to be visible in it.
  test('the pass line counts the imported chunks, not just the tags', () => {
    const path = shell('counted', ENTRY, {
      'assets/index-abc.js': 'import "./lazy-def.js"\n',
      'assets/lazy-def.js': 'export const run = 1\n',
    })
    expect(inspectBundles([path]).files).toHaveLength(2)
  })

  // The set stays closed by reporting what it cannot follow. Skipping any of
  // these is the silent narrowing the whole guard exists to refuse.
  test('a specifier that is not a string literal is reported, not skipped', () => {
    expect(details('const load = (r) => import(r)\n')).toEqual([
      expect.stringContaining('cannot read as a string'),
    ])
  })

  test('an `import()` with no argument is reported rather than dropped', () => {
    expect(details('const x = import()\n')).toEqual([
      expect.stringContaining('cannot read as a string'),
    ])
  })

  test.each([
    ['a bare specifier', 'react'],
    ['a root-absolute specifier', '/assets/other.js'],
    ['an off-origin specifier', 'https://cdn.example/app.js'],
  ])('%s is reported — no file in the build holds its code', (label, specifier) => {
    const path = shell(`bare-${label.replaceAll(/\W/g, '')}`, ENTRY, {
      'assets/index-abc.js': `import ${JSON.stringify(specifier)}\n`,
    })
    expect(checkBundles([path])).toEqual([
      {
        file: expect.stringContaining('assets/index-abc.js'),
        detail: expect.stringContaining('is not a relative path'),
      },
    ])
  })

  // The containment `scriptFiles` asserts about a `<script src>` has to hold on
  // this path too — `..` is spellable in a specifier just as it is in a `src`.
  test('a specifier that escapes the build directory is reported, not followed', () => {
    writeFileSync(join(root, 'outside.js'), 'eval("x")\n')
    const path = shell('escape', ENTRY, {
      'assets/index-abc.js': 'import "../../outside.js"\n',
    })
    expect(checkBundles([path])).toEqual([
      {
        file: expect.stringContaining('assets/index-abc.js'),
        detail: expect.stringContaining('resolves outside the build directory'),
      },
    ])
  })

  test('a chunk an import names but the build did not emit fails', () => {
    const path = shell('gone', ENTRY, { 'assets/index-abc.js': 'import "./gone-xyz.js"\n' })
    expect(checkBundles([path])).toEqual([
      {
        file: expect.stringContaining('assets/gone-xyz.js'),
        detail: expect.stringContaining('not found'),
      },
    ])
  })

  // The reconciliation the issue asks for, as a test rather than as a second
  // production notion of the build: the walked set must be every `.js` file
  // emitted under the shell's directory. A glob here proves the walk is
  // complete without a glob ever deciding what CI reads.
  test('the walked set is every .js file emitted under the shell directory', () => {
    const path = shell(
      'reconcile',
      `<script src="./demo-mode.js"></script>${ENTRY}`,
      {
        'demo-mode.js': 'window.fetch = f\n',
        'assets/index-abc.js': 'import "./route-a.js"\nimport("./route-b.js")\n',
        'assets/route-a.js': 'export * from "./shared.js"\n',
        'assets/route-b.js': 'import "./shared.js"\nexport const b = 1\n',
        'assets/shared.js': 'export const s = 1\n',
      },
    )
    const dir = dirname(path)
    const emitted = readdirSync(dir, { recursive: true })
      .map(entry => join(dir, String(entry)))
      .filter(entry => entry.endsWith('.js'))

    const { files, problems } = inspectBundles([path])
    expect(problems).toEqual([])
    expect([...files].sort()).toEqual([...emitted].sort())
  })
})
