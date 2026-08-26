/**
 * Post-process the stock production build into the demo bundle.
 *
 * `dist/` is produced by the ordinary `vite build` and is left byte-identical —
 * it is what rust-embed bakes into the Rust binary, and it must never contain
 * demo code. `dist-demo/` is that exact artifact plus one injected <script> tag
 * loading `demo-mode.js`, which shims `window.fetch` with fixtures at runtime.
 *
 * Run with `bun demo/build.ts` (see the `build:demo` script).
 */
import { cp, readFile, rm, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

const APP_ROOT = dirname(dirname(fileURLToPath(import.meta.url)))
const DIST = join(APP_ROOT, 'dist')
const DIST_DEMO = join(APP_ROOT, 'dist-demo')
const SHIM = 'demo-mode.js'
/** Relative, not absolute, so a subpath deploy still resolves the shim. */
const TAG = `<script src="./${SHIM}"></script>`
/** The app's bundle tag — the shim has to run before it. */
const ANCHOR = /<script[^>]*\stype="module"[^>]*><\/script>/

function fail(message: string): never {
  console.error(`demo/build.ts: ${message}`)
  process.exit(1)
}

async function main(): Promise<void> {
  let index: string
  try {
    index = await readFile(join(DIST, 'index.html'), 'utf8')
  }
  catch {
    fail(`${join(DIST, 'index.html')} not found — run \`vite build\` first.`)
  }

  // Start clean so a previous build's hashed assets don't linger.
  await rm(DIST_DEMO, { recursive: true, force: true })
  await cp(DIST, DIST_DEMO, { recursive: true })
  await cp(join(APP_ROOT, 'demo', SHIM), join(DIST_DEMO, SHIM))

  // Idempotent: re-running over an already-injected index.html is a no-op.
  if (!index.includes(TAG)) {
    const anchor = ANCHOR.exec(index)
    if (!anchor) {
      fail('no <script type="module"> tag in dist/index.html — cannot place the shim.')
    }
    index = index.replace(anchor[0], `${TAG}\n    ${anchor[0]}`)
  }

  await writeFile(join(DIST_DEMO, 'index.html'), index)
  console.log(`demo/build.ts: wrote ${DIST_DEMO} (stock dist/ + ${SHIM})`)
}

main().catch((error: unknown) => {
  fail(error instanceof Error ? error.message : String(error))
})
