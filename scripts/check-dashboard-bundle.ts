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
 * **A name is read by its spelling, not by resolving the binding it refers
 * to**, which is the first thing a reader reaches for. For `eval` that costs
 * nothing: the chunks are module code, module code is strict, and `eval` is
 * not a legal binding name in strict mode — so the identifier is the global one
 * by construction. (`demo-mode.js` is a classic script, where `var eval` is
 * legal; it is forty hand-written lines in this repository.) `Function` is
 * shadowable anywhere, so `const Function = factory; Function(src)` is reported
 * and should not be. Accepted rather than closed: what is read is minified
 * first-party output, where a local binding is a one- or two-letter name, and
 * an approximate shadow check — "this file declares `Function` somewhere, so
 * skip it" — would trade a false positive nobody has hit for a missed `eval`,
 * which is the wrong direction for a guard.
 *
 * The files it reads *start* at the ones {@link scriptFiles} names from the
 * shell's own `<script src>` tags — the same set `check-dashboard-csp.ts`
 * judges, so the two guards cannot disagree about what "the build" is. A
 * `dist/assets` glob would have been a second notion of it.
 *
 * **From there it follows the emitted module graph** (#227). The tags alone are
 * what the browser runs only while the build emits one chunk, which is what it
 * does today; the first lazy route or `manualChunks` entry emits a chunk the
 * entry module imports and the shell references only as
 * `<link rel="modulepreload">`, and reading the tags alone would leave that
 * chunk unparsed while the pass line below still printed a green count. The
 * graph is walked rather than globbed for the reason the tag list was chosen
 * over a glob to begin with: it stays one notion of the build, derived from the
 * same shells.
 *
 * **A specifier this cannot follow is a finding, not a skip**, which is what
 * keeps that set closed. Followed: a string literal on an `import`, on an
 * `export … from`, or on an `import(…)`, naming a relative path that stays
 * inside the shell's own directory. Reported instead: a specifier that is not a
 * string literal (`import(route)`), one that is not a relative path, one that
 * resolves outside the build, and one naming a file the build did not emit.
 * Silently dropping any of those is the failure the unreadable-file rule above
 * exists to prevent, arriving through the walk.
 *
 * **It is the *static ESM* graph, and the residue is named rather than left to
 * be found.** Not walked and not reported: code a chunk reaches by something
 * that is not an ES module specifier — `new Worker(new URL('./w.js',
 * import.meta.url))`, a `<script>` element appended at runtime — and a
 * `require('./x.js')` call sitting in the emitted output.
 *
 * `require` is the one of those that is a static specifier in the very AST
 * walked here, so it is worth saying why it is not read. Reporting every
 * `require` call would fail CI on working output: what survives bundling is
 * mostly the dead `typeof require !== 'undefined'` branch a dependency ships,
 * and `require` is not defined in module code, so such a call is not a live
 * edge. Following one instead would report a bare `require('fs')` in that same
 * dead branch as a specifier naming no file. Either way the guard breaks a
 * build that works, which is the failure it is shaped to avoid — so the gap is
 * declared here and tracked, the way the module graph itself was. Measured on
 * the current build: the emitted chunk contains no `require` call at all (its
 * three `require` substrings are the React prop `required`).
 *
 * The residue is narrow for the same reason the alias and computed-name cases
 * above are: this guards a first-party build against a dependency that starts
 * calling `eval`, not a bundle written to evade the guard.
 *
 * Usage:
 *   bun scripts/check-dashboard-bundle.ts              # both built shells
 *   bun scripts/check-dashboard-bundle.ts <path…>      # explicit shells
 */
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import process from 'node:process'
import ts from 'typescript'
import {
  BUILD_COMMANDS,
  buildDir,
  containedIn,
  DEFAULT_SHELLS,
  scriptFiles,
  shellPath,
} from './check-dashboard-csp'

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

/**
 * The module specifier `node` imports through, if `node` imports at all.
 *
 * The three forms a bundler emits, and `null` for anything else. A dynamic
 * import is modelled as a call whose callee is the `import` *keyword* rather
 * than an identifier, so it is not a shape {@link globalBinding} could reach.
 *
 * `import()` written with no argument names nothing, and comes back as the call
 * itself so the caller reports it — a node that is not a string literal — for
 * the same reason an unreadable file fails rather than passing: an import this
 * cannot name is code that would go unread.
 */
function importSpecifier(node: ts.Node): ts.Node | null {
  if (ts.isImportDeclaration(node)) {
    return node.moduleSpecifier
  }
  // `export { a } from './x.js'` names a file. A bare `export { a }` does not.
  if (ts.isExportDeclaration(node)) {
    return node.moduleSpecifier ?? null
  }
  if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
    return node.arguments[0] ?? node
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

/** What one file holds: everything refused in it, and everything it imports. */
export interface Chunk {
  problems: Problem[]
  /** Each string-literal module specifier, in source order. */
  imports: string[]
}

/**
 * Everything in `code` that the served CSP would refuse, and what it imports.
 *
 * One parse for both: the specifiers are nodes in the very tree the refusal
 * rules walk, so reaching the rest of the build costs nothing beyond reading
 * them off. Pure, so the test can exercise the rules without a build; `file`
 * only labels the results and names the source to the parser.
 *
 * A file that does not parse reports that and nothing else — no imports either,
 * which is the same refusal to guess as the empty problem list would have been
 * a lie.
 */
export function inspectChunk(code: string, file: string): Chunk {
  const source = ts.createSourceFile(file, code, ts.ScriptTarget.Latest, false, ts.ScriptKind.JS)
  const unreadable = syntaxErrors(source, file, code)
  if (unreadable !== null) {
    return { problems: [{ file, detail: unreadable }], imports: [] }
  }

  const problems: Problem[] = []
  const imports: string[] = []
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

    const specifier = importSpecifier(node)
    if (specifier !== null) {
      if (ts.isStringLiteralLike(specifier)) {
        imports.push(specifier.text)
      }
      else {
        // Reported rather than skipped: a specifier this cannot read names a
        // file that would then go unparsed while everything else passed.
        const start = specifier.getStart(source)
        problems.push({
          file,
          detail:
            'imports through a specifier this check cannot read as a string, so the code it '
            + `loads went uninspected — at ${position(source, start)}: ${excerpt(code, start)}`,
        })
      }
    }

    ts.forEachChild(node, visit)
  }
  visit(source)
  return { problems, imports }
}

/** Everything in `code` that the served CSP would refuse. */
export function checkBundle(code: string, file: string): Problem[] {
  return inspectChunk(code, file).problems
}

/**
 * The file `specifier` names when read from `importer`, or why none could be.
 *
 * Every specifier a bundler emits into a chunk is a relative path carrying an
 * extension, so this is a `join` against the importing file's directory — with
 * the containment {@link scriptFiles} asserts about the shell's own tags, since
 * a specifier reaches the filesystem by the same route and `..` is spellable in
 * one just as it is in a `src`.
 *
 * Percent-escapes are deliberately *not* decoded, and both directions were
 * measured rather than reasoned about. A bundler emits the file name it wrote:
 * asked for a chunk whose name carries a space, Vite emitted
 * `import("./My Component-<hash>.js")` — the literal character, not `%20` — so
 * decoding buys nothing on the case it looks like it is for, while a chunk
 * genuinely named `a%20b.js` would be decoded to a name that does not exist and
 * reported missing. And an escape left intact can only ever name a file that is
 * absent, which the caller reports: `import "./..%2f..%2foutside.js"` from a
 * chunk resolves to a literal `..%2f..%2foutside.js` inside the build and is
 * reported `not found`, with the real `outside.js` never read. Decoding is what
 * would re-open the `%2f` case measured on `scriptFiles`, where a separator
 * arrives after the containment check has already run.
 */
function importedFile(specifier: string, importer: string, dir: string):
  { file: string } | { reason: string } {
  if (!specifier.startsWith('./') && !specifier.startsWith('../')) {
    return {
      reason:
        'is not a relative path — a bare, root-absolute or off-origin specifier names no file '
        + 'in the build',
    }
  }
  const file = resolve(dirname(importer), specifier)
  if (!containedIn(dir, file)) {
    return { reason: 'resolves outside the build directory, so no file in the build holds its code' }
  }
  return { file }
}

/**
 * The files checked for a set of shells, and everything wrong with them.
 *
 * `files` is the walked set — each shell's `<script src>` tags plus everything
 * reachable from them through an `import` — in the order it was read, so the
 * pass line can show what was actually inspected rather than a bare count.
 */
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

    // The tags are the entry points; what the browser runs is those files and
    // everything they import, so the queue grows as each file is read. `seen`
    // is the cycle guard — a chunk graph is routinely circular — and it also
    // keeps a diamond from being parsed and reported twice.
    const dir = buildDir(shell)
    const queue = [...files]
    const seen = new Set<string>()
    for (let next = 0; next < queue.length; next += 1) {
      const file = queue[next]
      if (seen.has(file)) {
        continue
      }
      seen.add(file)

      let code: string
      try {
        code = readFileSync(file, 'utf8')
      }
      catch {
        problems.push({
          file,
          detail: `not found, though ${shell} reaches it — run \`${BUILD_COMMANDS}\` first`,
        })
        continue
      }
      inspected.push(file)

      const chunk = inspectChunk(code, file)
      problems.push(...chunk.problems)
      for (const specifier of chunk.imports) {
        const imported = importedFile(specifier, file, dir)
        if ('reason' in imported) {
          problems.push({
            file,
            detail:
              `its import of \`${specifier}\` ${imported.reason}, so the code it loads went `
              + 'uninspected',
          })
          continue
        }
        queue.push(imported.file)
      }
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
    + `${shells.length} shell(s) load and import (${files.join(', ')})`,
  )
  return 0
}

if (import.meta.main) {
  process.exit(main(process.argv.slice(2)))
}
