/**
 * The management credential for `@honmoon/api` (#173).
 *
 * This service is a second server over the same audit data the Rust management
 * API serves — the durable JSONL log rather than the in-memory ring — and it had
 * no token concept at all. Gating the Rust reads while leaving this one open
 * would move the exposure rather than close it, so both require the same token.
 *
 * One token, resolved the same way in both processes: `HONMOON_MGMT_TOKEN`
 * (or the deprecated `HONMOON_HOOK_TOKEN`), else `~/.honmoon/mgmt-token`, else
 * minted and persisted there at mode `0600`. Whichever process starts first
 * creates the file; the other adopts it.
 *
 * Bearer only — there is no browser client here, so there is no session cookie
 * and no CSRF surface. The dashboard talks to the Rust management API.
 */
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { closeSync, mkdirSync, openSync, readFileSync, writeSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

/** File under the honmoon directory holding a generated token. */
const FILE_NAME = 'mgmt-token'

/** Bytes of entropy in a generated token (rendered as 64 hex characters). */
const TOKEN_BYTES = 32

export type TokenSource = 'environment' | 'persisted' | 'generated'

export interface ResolvedToken {
  token: string
  source: TokenSource
  /** The backing file, when the token came from (or went to) one. */
  path?: string
}

/** `$HOME/.honmoon`, matching the Rust CLI's `mgmt_token::default_dir`. */
export function defaultDir(): string {
  return join(homedir(), '.honmoon')
}

/**
 * Whether `header` presents the management token.
 *
 * Both sides are folded through SHA-256 before comparison, so the comparison
 * runs over two fixed 32-byte digests and its duration is independent of either
 * input's length — `timingSafeEqual` itself throws on a length mismatch, which
 * would otherwise leak the secret's length. A naive `===` would leak where the
 * first differing byte is.
 */
export function isAuthorized(header: string | null | undefined, token: string): boolean {
  const prefix = 'Bearer '
  if (typeof header !== 'string' || !header.startsWith(prefix)) {
    return false
  }
  const digest = (value: string) => createHash('sha256').update(value).digest()
  return timingSafeEqual(digest(header.slice(prefix.length)), digest(token))
}

function errorCode(error: unknown): string | undefined {
  return typeof error === 'object' && error !== null && 'code' in error
    ? String((error as { code: unknown }).code)
    : undefined
}

/**
 * Resolve the token this service will require.
 *
 * An unreadable token file aborts rather than minting a second token: the Rust
 * gateway, a bookmarked dashboard login URL and any operator tooling read this
 * same file, and a server that silently disagrees with all of them while
 * reporting success is worse than one that refuses to start.
 */
export function resolveToken(dir: string = defaultDir()): ResolvedToken {
  const fromEnv = process.env.HONMOON_MGMT_TOKEN ?? process.env.HONMOON_HOOK_TOKEN
  if (typeof fromEnv === 'string' && fromEnv.trim() !== '') {
    return { token: fromEnv, source: 'environment' }
  }

  const path = join(dir, FILE_NAME)
  let existed = false
  try {
    const contents = readFileSync(path, 'utf8').trim()
    existed = true
    if (contents !== '') {
      return { token: contents, source: 'persisted', path }
    }
  }
  catch (error) {
    if (errorCode(error) !== 'ENOENT') {
      throw new Error(
        `cannot read the management token ${path} (delete it to mint a new one): ${String(error)}`,
      )
    }
  }

  mkdirSync(dir, { recursive: true, mode: 0o700 })
  const token = randomBytes(TOKEN_BYTES).toString('hex')
  // `wx` is O_CREAT|O_EXCL: it neither follows nor clobbers a pre-planted
  // symlink or file, and it is how a concurrent first run is detected. An
  // existing-but-empty file has no token for anything else to hold, so it is
  // the one state it is safe to overwrite.
  try {
    const fd = openSync(path, existed ? 'w' : 'wx', 0o600)
    try {
      writeSync(fd, token)
    }
    finally {
      closeSync(fd)
    }
    return { token, source: 'generated', path }
  }
  catch (error) {
    if (errorCode(error) !== 'EEXIST') {
      throw error
    }
    // Another process created it between our read and our write. Its token is
    // the one on disk, so adopt it rather than serving one nobody can present.
    const winner = readFileSync(path, 'utf8').trim()
    if (winner === '') {
      throw new Error(`management token ${path} is empty after a lost create race`)
    }
    return { token: winner, source: 'persisted', path }
  }
}

/** The 401 every unauthenticated request to a gated route gets. */
export function unauthorized(): Response {
  return Response.json(
    { error: 'missing or invalid management token' },
    { status: 401, headers: { 'WWW-Authenticate': 'Bearer' } },
  )
}
