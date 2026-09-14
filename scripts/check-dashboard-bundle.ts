/**
 * Check the emitted dashboard bundle for the code construction the served CSP
 * refuses.
 *
 * `honmoon-mgmt` serves the dashboard under `script-src 'self'` with no
 * `'unsafe-eval'` (`DASHBOARD_CSP` in `crates/honmoon-mgmt/src/lib.rs`, #195).
 * That refuses `eval` and the `Function` constructor at runtime, so a
 * dependency that reaches for either ships a dashboard that breaks behind a
 * console violation an operator would have to open devtools to see — the same
 * failure `scripts/check-dashboard-csp.ts` exists to catch on the shell's
 * markup, one layer down in the code that markup loads (issue #200).
 *
 * **It parses; it does not match characters.** `eval(` occurs inside string
 * literals, in comments, and as a method name on something that is not the
 * global object, and `new Function` reads the same way — so a pattern over
 * minified bundler output would fail CI on an unrelated dependency bump. That
 * is "a CSP that breaks the dashboard is worse than no CSP" (#199) moved one
 * layer out, and it is the failure this file is shaped to avoid: a finding is
 * a *call expression* in the parsed program, at a named line and column.
 *
 * The parser is TypeScript's, which the repository already depends on at the
 * root and which reads plain JavaScript. Nothing was added for this.
 *
 * **What it covers, stated narrowly.** A call to `eval` or to `Function` where
 * the callee is that name, reached directly, through the parenthesised comma
 * form a bundler emits for indirect eval (`(0, eval)(…)`), or as a property of
 * a global object (`window.eval`, `globalThis["Function"]`). It does **not**
 * follow an alias (`const f = Function; f(src)`), a computed name
 * (`globalThis["ev" + "al"]`), or `setTimeout`/`setInterval` given a string —
 * all of which the policy also refuses. That is deliberate rather than an
 * oversight: this guards a first-party build against a dependency that starts
 * calling `eval`, and a bundle written to evade the guard is not the failure it
 * is defending against. Claiming otherwise would be the more expensive mistake.
 *
 * The files it reads are the ones {@link scriptFiles} names from the shell's
 * own `<script src>` tags — the same set `check-dashboard-csp.ts` judges, so
 * the two guards cannot disagree about what "the build" is. A `dist/assets`
 * glob would have been a second notion of it.
 *
 * Usage:
 *   bun scripts/check-dashboard-bundle.ts              # both built shells
 *   bun scripts/check-dashboard-bundle.ts <path…>      # explicit shells
 */
import { readFileSync } from 'node:fs'
import process from 'node:process'
import ts from 'typescript'
import { BUILD_COMMANDS, DEFAULT_SHELLS, scriptFiles, shellPath } from './check-dashboard-csp'

/** One thing wrong with one file. */
export interface Problem {
  file: string
  detail: string
}

/**
 * The objects whose `eval`/`Function` property is the real global binding.
 *
 * `window.eval(src)` is the global `eval`, and the policy refuses it exactly as
 * it refuses the bare name. An `eval` property on anything else is a method
 * that happens to share the name — an interpreter library's `interpreter.eval`,
 * say — which no directive governs, so the object has to be named for the
 * member form to be a finding at all.
 */
const GLOBAL_OBJECTS = new Set(['window', 'globalThis', 'self', 'global'])

/**
 * What a finding calls each refused construct, keyed by the name being called.
 *
 * A `Map`, not an object literal, and that is load-bearing rather than taste: a
 * plain object resolves `REFUSED['toString']` through the prototype chain to
 * `Object.prototype.toString`, which is truthy — so a bundle calling a function
 * named `toString`, `valueOf`, `constructor` or `hasOwnProperty` would fail CI
 * with `function toString() { [native code] }` where the finding belongs. That
 * is the same false positive this whole file is shaped to avoid, arriving
 * through the lookup instead of through a pattern. A `Map` has no such chain.
 */
const REFUSED = new Map<string, string>([
  ['eval', 'a call to `eval`'],
  ['Function', 'a call to the `Function` constructor'],
])

/** Whether `expression` names one of {@link GLOBAL_OBJECTS}. */
function isGlobalObject(expression: ts.Expression): boolean {
  return ts.isIdentifier(expression) && GLOBAL_OBJECTS.has(expression.text)
}

/**
 * The global binding `expression` evaluates to, if it plainly evaluates to one.
 *
 * `null` for everything else, including every member access on an object that
 * is not a named global — which is the false positive a pattern makes and this
 * file must not.
 */
function globalBinding(expression: ts.Expression): string | null {
  if (ts.isParenthesizedExpression(expression)) {
    return globalBinding(expression.expression)
  }
  // `(0, eval)(src)` — what a bundler emits for an indirect eval. TypeScript
  // models the comma operator as a binary expression, and only its right-hand
  // side is the value being called, so an opaque callee here would be a miss.
  if (
    ts.isBinaryExpression(expression)
    && expression.operatorToken.kind === ts.SyntaxKind.CommaToken
  ) {
    return globalBinding(expression.right)
  }
  if (ts.isIdentifier(expression)) {
    return expression.text
  }
  if (ts.isPropertyAccessExpression(expression) && isGlobalObject(expression.expression)) {
    return expression.name.text
  }
  if (
    ts.isElementAccessExpression(expression)
    && isGlobalObject(expression.expression)
    && ts.isStringLiteralLike(expression.argumentExpression)
  ) {
    return expression.argumentExpression.text
  }
  return null
}

/** What `node` is, if it is a construct the policy refuses. */
function refusal(node: ts.Node): string | null {
  if (ts.isCallExpression(node)) {
    return REFUSED.get(globalBinding(node.expression) ?? '') ?? null
  }
  // `new eval()` is a `TypeError`, not a policy violation — `eval` is not a
  // constructor — so only the one that really is one is read here.
  if (ts.isNewExpression(node) && globalBinding(node.expression) === 'Function') {
    return REFUSED.get('Function') ?? null
  }
  return null
}

/** A one-line window on the source at `start`, for a finding to point at. */
function excerpt(code: string, start: number): string {
  return code.slice(start, start + 80).split('\n')[0]
}

/**
 * The syntax errors in `source` as one detail line, or `null` if it parsed.
 *
 * TypeScript's parser recovers instead of throwing, so a file it could not read
 * would otherwise walk clean and report nothing — a silent pass in a check
 * whose whole purpose is to not have one, and the same stance
 * `check-dashboard-csp.ts` takes on a `<script>` it cannot read to a
 * `</script>`. The diagnostics come from a program because the source file's
 * own `parseDiagnostics` is an internal field; the host serves the one file and
 * resolves nothing, so no lib or import is read from disk.
 */
function syntaxErrors(source: ts.SourceFile, file: string, code: string): string | null {
  const options: ts.CompilerOptions = {
    allowJs: true,
    noLib: true,
    noResolve: true,
    target: ts.ScriptTarget.Latest,
  }
  // TypeScript's own host, with every member that would otherwise reach the
  // filesystem pointed at the one file already in hand. Nothing here reads or
  // writes the disk, and `noLib`/`noResolve` mean nothing asks it to.
  const host = ts.createCompilerHost(options)
  host.getSourceFile = name => (name === file ? source : undefined)
  host.readFile = name => (name === file ? code : undefined)
  host.fileExists = name => name === file
  host.writeFile = () => {}

  const program = ts.createProgram([file], options, host)
  const diagnostics = program.getSyntacticDiagnostics(source)
  const first = diagnostics[0]
  if (first === undefined) {
    return null
  }
  const more = diagnostics.length > 1 ? ` (and ${diagnostics.length - 1} more)` : ''
  return (
    `could not parse — ${ts.flattenDiagnosticMessageText(first.messageText, ' ')} `
    + `at ${position(source, first.start ?? 0)}${more}, so nothing in it was inspected`
  )
}

/** `line:column`, both 1-based, the way an editor and a stack trace count. */
function position(source: ts.SourceFile, start: number): string {
  const { line, character } = source.getLineAndCharacterOfPosition(start)
  return `${line + 1}:${character + 1}`
}

/**
 * Everything in `code` that the served CSP would refuse.
 *
 * Pure, so the test can exercise the rules without a build. `file` only labels
 * the results and names the source to the parser.
 */
export function checkBundle(code: string, file: string): Problem[] {
  const source = ts.createSourceFile(file, code, ts.ScriptTarget.Latest, false, ts.ScriptKind.JS)
  const unreadable = syntaxErrors(source, file, code)
  if (unreadable !== null) {
    return [{ file, detail: unreadable }]
  }

  const problems: Problem[] = []
  const visit = (node: ts.Node): void => {
    const detail = refusal(node)
    if (detail !== null) {
      const start = node.getStart(source)
      problems.push({
        file,
        detail:
          `${detail}, which \`script-src 'self'\` refuses without \`'unsafe-eval'\` — `
          + `at ${position(source, start)}: ${excerpt(code, start)}`,
      })
    }
    ts.forEachChild(node, visit)
  }
  visit(source)
  return problems
}

/** The files checked for a set of shells, and everything wrong with them. */
export interface Inspection {
  files: string[]
  problems: Problem[]
}

/** Check the code each shell at `shells` loads, and report what was read. */
export function inspectBundles(shells: string[]): Inspection {
  const inspected: string[] = []
  const problems: Problem[] = []

  for (const shell of shells) {
    let html: string
    try {
      html = readFileSync(shellPath(shell), 'utf8')
    }
    catch {
      // Not found is a failure, not a skip, for the reason the shell checker
      // gives: a check that passes when the artifact is missing is the one that
      // lets a regression through.
      problems.push({ file: shell, detail: `not found — run \`${BUILD_COMMANDS}\` first` })
      continue
    }

    const { files, unresolved } = scriptFiles(html, shell)
    for (const { src, reason } of unresolved) {
      problems.push({
        file: shell,
        detail: `its <script src="${src}"> ${reason}, so the code it loads went uninspected`,
      })
    }
    // Anti-vacuity, the same rule `check-dashboard-csp.ts` applies to the
    // script-less placeholder `crates/honmoon-mgmt/build.rs` drops so a bare
    // `cargo build` works: with no file to read, every rule above holds
    // vacuously. Only when nothing was unresolvable either — otherwise this
    // would report "not built" for a shell that is built and misreferenced.
    if (files.length === 0 && unresolved.length === 0) {
      problems.push({
        file: shell,
        detail:
          'no <script src> at all — this is not a built dashboard shell '
          + `(the placeholder from crates/honmoon-mgmt/build.rs?). Run \`${BUILD_COMMANDS}\`.`,
      })
    }

    for (const file of files) {
      let code: string
      try {
        code = readFileSync(file, 'utf8')
      }
      catch {
        problems.push({
          file,
          detail: `not found, though ${shell} loads it — run \`${BUILD_COMMANDS}\` first`,
        })
        continue
      }
      inspected.push(file)
      problems.push(...checkBundle(code, file))
    }
  }

  return { files: inspected, problems }
}

/** Check the code the shells at `shells` load. */
export function checkBundles(shells: string[]): Problem[] {
  return inspectBundles(shells).problems
}

export function main(argv: string[]): number {
  const shells = argv.length > 0 ? argv : DEFAULT_SHELLS
  const { files, problems } = inspectBundles(shells)

  if (problems.length > 0) {
    for (const { file, detail } of problems) {
      console.error(`${file}: ${detail}`)
    }
    console.error(
      `\ndashboard bundle: ${problems.length} problem(s). The gateway serves this dashboard `
      + 'under `script-src \'self\'` with no `\'unsafe-eval\'` (crates/honmoon-mgmt/src/lib.rs) — '
      + 'either keep the build free of `eval`/`Function` construction, or change that header '
      + 'deliberately.',
    )
    return 1
  }

  // The files, not just the count: this passes vacuously if it read nothing,
  // and the list is what shows it did not.
  console.log(
    `dashboard bundle: no \`eval\`/\`Function\` construction in the ${files.length} file(s) `
    + `${shells.length} shell(s) load (${files.join(', ')})`,
  )
  return 0
}

if (import.meta.main) {
  process.exit(main(process.argv.slice(2)))
}
