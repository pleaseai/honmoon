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
import { closeSync, fchmodSync, fstatSync, mkdirSync, openSync, readFileSync, writeSync } from 'node:fs'
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

/**
 * `$HOME/.honmoon`, matching the Rust CLI's `mgmt_token::default_dir`.
 *
 * The `HOME`-unset fallback is a working-directory-relative `.honmoon`, which
 * is what the Rust side does. `homedir()` would disagree with it there — it
 * falls back to the account's home from the passwd database — and the two
 * processes would then mint different tokens from the same configuration,
 * leaving a caller authenticated to one service rejected by the other.
 */
export function defaultDir(): string {
  const home = process.env.HOME
  return home !== undefined && home !== '' ? join(home, '.honmoon') : '.honmoon'
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
/**
 * Strip token padding from both ends — the counterpart of the Rust CLI's
 * `trim_token`.
 *
 * Spelled out rather than using `String.prototype.trim`, because that and Rust's
 * `str::trim` do not agree and this token crosses between them. Rust trims
 * Unicode `White_Space`, which includes U+0085 (NEL) and excludes U+FEFF;
 * JavaScript's `WhiteSpace` production is the reverse on both counts. So
 * `'\uFEFF'` was an empty token here and a valid one to the gateway, and
 * `'\u0085'` the other way round — the two services disagreeing about whether a
 * credential exists at all.
 *
 * This is the union of both sets, matching `is_token_padding` exactly:
 * JavaScript's `\\s` already covers U+FEFF, so only U+0085 has to be added.
 */
export function trimToken(token: string): string {
  // U+FEFF is already in JavaScript's `\s`; U+0085 is the one it lacks.
  return token.replace(/^[\s\u0085]+|[\s\u0085]+$/gu, '')
}

export function resolveToken(dir: string = defaultDir()): ResolvedToken {
  const fromEnv = process.env.HONMOON_MGMT_TOKEN ?? process.env.HONMOON_HOOK_TOKEN
  if (typeof fromEnv === 'string') {
    // An explicitly-set-but-empty variable is a misconfiguration, not an
    // absent one. Falling back to the file here would hand this service a
    // different credential from the gateway, which refuses to start on the
    // same input — so refuse too rather than diverge silently.
    if (trimToken(fromEnv) === '') {
      throw new Error(
        'HONMOON_MGMT_TOKEN (or HONMOON_HOOK_TOKEN) is set but empty — unset it to use the token file',
      )
    }
    return { token: fromEnv, source: 'environment' }
  }

  const path = join(dir, FILE_NAME)
  let existed = false
  try {
    const { contents, mode } = readTokenAndMode(path)
    existed = true
    if (contents !== '') {
      warnIfModeReadableBeyondOwner(path, mode)
      warnIfDirectoryWritableBeyondOwner(dir)
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

  // Refuse to mint on Windows, matching the Rust loader — whose `random_bytes`
  // hard-errors off Unix precisely because there is no safe fallback for a
  // credential. The reason is sharper here than "no /dev/urandom": a POSIX mode
  // establishes no ACL on Windows, and every mode check below deliberately
  // returns without validating anything on win32. Generating would therefore
  // write a long-lived bearer token under whatever ACL `.honmoon` happens to
  // inherit, and then accept it on each later start with nothing checking who
  // else can read it. Reading a token the operator placed themselves is still
  // allowed above; only unattended generation is refused.
  if (process.platform === 'win32') {
    throw new Error(
      'refusing to generate a management token on Windows — a POSIX mode establishes no ACL there, '
      + 'so the token would be stored under an unverified one. Set HONMOON_MGMT_TOKEN instead.',
    )
  }
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  // `mode` governs only a directory this call creates; one that already existed
  // keeps whatever it has. That matters more than the file's own mode: write
  // permission on the directory is what lets another local user substitute a
  // perfectly `0600` token file of their choosing, which the file check above
  // then approves.
  warnIfDirectoryWritableBeyondOwner(dir)
  const token = randomBytes(TOKEN_BYTES).toString('hex')
  // `wx` is O_CREAT|O_EXCL: it neither follows nor clobbers a pre-planted
  // symlink or file, and it is how a concurrent first run is detected. An
  // existing-but-empty file has no token for anything else to hold, so it is
  // the one state it is safe to overwrite.
  try {
    const fd = openSync(path, existed ? 'w' : 'wx', 0o600)
    try {
      // The mode argument applies only when the open *creates* the file, so a
      // pre-existing empty `0644` placeholder would otherwise take a live
      // credential at its old mode. Tighten before the bytes land, so the
      // token is never briefly readable beyond its owner.
      //
      // Through the descriptor, not the path: if `path` were replaced between
      // the open and this call, a path-based `chmodSync` would tighten some
      // other file while the one actually receiving the token stayed
      // permissive. `fchmodSync` can only affect the inode being written.
      if (existed) {
        fchmodSync(fd, 0o600)
      }
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
    const { contents: winner, mode } = readTokenAndMode(path)
    if (winner === '') {
      throw new Error(`management token ${path} is empty after a lost create race`)
    }
    // Same state as an ordinary persisted read — a token read off disk — so it
    // gets the same checks. The Rust loader had this identical asymmetry.
    warnIfModeReadableBeyondOwner(path, mode)
    warnIfDirectoryWritableBeyondOwner(dir)
    return { token: winner, source: 'persisted', path }
  }
}

/**
 * Read the token and its mode through a single descriptor.
 *
 * Two calls — `readFileSync(path)` then a stat of `path` — can land on two
 * different inodes if the file is replaced in between, and the failure is
 * silent in the worst direction: the token actually adopted comes from the
 * permissive file while the mode reported comes from the replacement, so a
 * credential other local users can read is announced as safe. Opening once and
 * working from that descriptor makes the bytes and the mode describe the same
 * inode by construction.
 *
 * `mode` is `null` where there is nothing meaningful to report — Windows, or a
 * stat that failed on an already-open descriptor.
 */
function readTokenAndMode(path: string): { contents: string, mode: number | null } {
  const fd = openSync(path, 'r')
  try {
    let mode: number | null = null
    if (process.platform !== 'win32') {
      try {
        mode = fstatSync(fd).mode & 0o777
      }
      catch (error) {
        // Not fatal — the token itself is still readable — but never silent:
        // saying nothing here reads exactly like "checked, and it was fine".
        console.warn(`honmoon api: warning: could not read the mode of ${path}: ${String(error)}`)
      }
    }
    // Decoded with `fatal: true` rather than read as 'utf8': Bun (like Node)
    // silently substitutes U+FFFD for malformed bytes, so a corrupt file
    // containing a lone 0xFF would become the perfectly ordinary token
    // "\uFFFD" and be served as a credential. Rust's `read_to_string` refuses
    // the same file, so accepting it here would mean the gateway aborts while
    // `@honmoon/api` starts under a guessable token — the divergence is worse
    // than either behaviour alone. Fail closed, matching Rust.
    const bytes = readFileSync(fd)
    let decoded: string
    try {
      decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    }
    catch {
      throw new Error(
        `management token ${path} is not valid UTF-8 (delete it to mint a new one)`,
      )
    }
    return { contents: trimToken(decoded), mode }
  }
  finally {
    closeSync(fd)
  }
}

/**
 * Report — but do not correct — a token file readable beyond its owner.
 *
 * The mirror of the Rust CLI's `warn_if_readable_beyond_owner`. Both processes
 * read one file, so a mode widened long after either minted it (a backup
 * restore, configuration tooling, an operator's `chmod`) must not be surfaced
 * by one operator and hidden from the other.
 *
 * Warns rather than tightening, for the same reason the Rust side does: a token
 * another local user could already have read has to be *replaced*, and only the
 * operator can decide when, since it invalidates their bookmarked login URL and
 * anything else holding the old value.
 *
 * Takes the mode rather than the path so it describes the same inode the token
 * came from — see {@link readTokenAndMode}.
 */
function warnIfModeReadableBeyondOwner(path: string, mode: number | null): void {
  if (mode === null) {
    return
  }
  if ((mode & 0o077) !== 0) {
    console.warn(
      `honmoon api: warning: management token ${path} is mode ${mode.toString(8).padStart(4, '0')} `
      + '— readable beyond its owner. Any local user it admits can read the whole management API; '
      + 'delete the file to mint a new one.',
    )
  }
}

/**
 * Report — but do not correct — a token directory writable beyond its owner.
 *
 * The mirror of the Rust CLI's `warn_if_writable_beyond_owner`, and the check
 * the file-mode one cannot stand in for: a local user who can write `~/.honmoon`
 * does not need to widen the token file, they unlink it and install a `0600`
 * file containing a value they chose. {@link warnIfModeReadableBeyondOwner}
 * then inspects that substitute, finds it owner-only, and says nothing — while
 * this service starts with a bearer token the attacker knows.
 *
 * Reported rather than corrected, matching the file case: the operator may have
 * widened the directory deliberately. Unlike the file case, replacing the token
 * is not the remedy — a fresh one lands in the same writable directory — so the
 * warning names the directory mode instead.
 */
function warnIfDirectoryWritableBeyondOwner(dir: string): void {
  if (process.platform === 'win32') {
    return
  }
  let mode: number
  try {
    const fd = openSync(dir, 'r')
    try {
      mode = fstatSync(fd).mode & 0o777
    }
    finally {
      closeSync(fd)
    }
  }
  catch (error) {
    console.warn(
      `honmoon api: warning: could not read the mode of the management token directory ${dir}: ${String(error)}`,
    )
    return
  }
  if ((mode & 0o022) !== 0) {
    console.warn(
      `honmoon api: warning: management token directory ${dir} is mode ${mode.toString(8).padStart(4, '0')} `
      + '— writable beyond its owner. Any local user it admits can substitute the token file and '
      + 'authenticate to the whole management API; chmod 700 it.',
    )
  }
}

/** The 401 every unauthenticated request to a gated route gets. */
export function unauthorized(): Response {
  return Response.json(
    { error: 'missing or invalid management token' },
    { status: 401, headers: { 'WWW-Authenticate': 'Bearer' } },
  )
}
