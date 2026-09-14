import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import { checkBundle, checkBundles } from './check-dashboard-bundle'

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
