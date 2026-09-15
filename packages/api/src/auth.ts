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
 * Bearer only — there is no browser client here, so there is no login flow and
 * no CSRF surface. The dashboard talks to the Rust management API, which is why
 * #188's session-credential change (cookie → origin-scoped header) left this
 * service alone: it never had a browser credential to harvest.
 */
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { closeSync, fchmodSync, fstatSync, mkdirSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeSync } from 'node:fs'
import { join } from 'node:path'

/** File under the honmoon directory holding a generated token. */
const FILE_NAME = 'mgmt-token'

/** Bytes of entropy in a generated token (rendered as 64 hex characters). */
const TOKEN_BYTES = 32

/**
 * Sentinel that makes minting the token single-winner (#189).
 *
 * The name, the directory and the protocol in {@link mintOrAdoptUnderLock} are
 * shared with the Rust CLI's `mgmt_token.rs` — two processes only interlock if
 * they agree on all three, and a fix in one language alone is not a fix, because
 * the divergence this closes is *between* the two services.
 */
const LOCK_FILE_NAME = 'mgmt-token.lock'

/**
 * How the loser of the lock paces itself. A parameter of {@link resolveToken}
 * so the tests can drive the abandoned-lock and exhausted-budget paths without
 * sleeping for real; {@link DEFAULT_LOCK_TIMING} is what the server uses, and
 * its values match the Rust side's `LockTiming::DEFAULT`.
 */
export interface LockTiming {
  /**
   * Age past which a waiter treats the lock as left behind by a crashed holder.
   * The critical section it guards is one read and one short write, so this is
   * about five orders of magnitude of headroom.
   */
  staleAfterMs: number
  /**
   * Total time a waiter will spend before giving up. It never mints on expiry —
   * minting is exactly the divergence this path exists to prevent — so it
   * throws with the lock's path instead.
   */
  budgetMs: number
  /** Gap between polls of the token file and the lock. */
  pollIntervalMs: number
}

export const DEFAULT_LOCK_TIMING: LockTiming = {
  staleAfterMs: 10_000,
  budgetMs: 30_000,
  pollIntervalMs: 20,
}

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

/**
 * Resolve the token this service will require.
 *
 * An unreadable token file aborts rather than minting a second token: the Rust
 * gateway, a bookmarked dashboard login URL and any operator tooling read this
 * same file, and a server that silently disagrees with all of them while
 * reporting success is worse than one that refuses to start.
 */
export function resolveToken(
  dir: string = defaultDir(),
  timing: LockTiming = DEFAULT_LOCK_TIMING,
): ResolvedToken {
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
  const onDisk = readOnDisk(path)
  if (onDisk.kind === 'token') {
    // `mode` governs only a directory `mkdirSync` creates, so the persisted
    // path — every restart after the first — is where this check actually runs
    // in practice. Write permission on the directory is what lets another local
    // user substitute a perfectly `0600` token file of their choosing, which
    // the file check inside `readOnDisk` then approves.
    warnIfDirectoryWritableBeyondOwner(dir)
    return onDisk.resolved
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
  warnIfDirectoryWritableBeyondOwner(dir)
  return mintOrAdoptUnderLock(dir, path, timing)
}

/**
 * What the token file holds. The three cases the callers need: a usable token,
 * an empty file (the recovery #189 is about) and no file at all (a first start).
 */
type OnDisk
  = | { kind: 'absent' }
    | { kind: 'empty' }
    | { kind: 'token', resolved: ResolvedToken }

/**
 * Read the token file, warning about its mode if it holds a token.
 *
 * A file that is not there reads as `absent` rather than throwing: a start that
 * removed it is about to create it exclusively, so the answer is the same as for
 * a path that was never there. Every other read error propagates, because
 * minting past a file this service cannot read hands it a credential nothing
 * else holds.
 */
function readOnDisk(path: string): OnDisk {
  let contents: string
  let mode: number | null
  try {
    ({ contents, mode } = readTokenAndMode(path))
  }
  catch (error) {
    if (errorCode(error) === 'ENOENT') {
      return { kind: 'absent' }
    }
    throw new Error(
      `cannot read the management token ${path} (delete it to mint a new one): ${String(error)}`,
    )
  }
  if (contents === '') {
    return { kind: 'empty' }
  }
  warnIfModeReadableBeyondOwner(path, mode)
  return { kind: 'token', resolved: { token: contents, source: 'persisted', path } }
}

/**
 * Mint the token, or adopt the one a concurrent start minted, under a
 * single-winner lock (#189).
 *
 * Both paths into here used to have their own protocol and neither was actually
 * single-winner.
 *
 * Replacing an *empty* file could not reuse `O_CREAT|O_EXCL` at all, because
 * `wx` on a path that exists only reports that it exists — so it minted and
 * truncated unconditionally, and two starts that both saw the empty file both
 * minted, both wrote, and each returned the token it had minted. The file then
 * authenticated exactly one of them: a gateway and an `@honmoon/api` holding
 * different credentials over the same audit data, with nothing on stderr.
 *
 * The fresh-create path looked safe and was not. `wx` *creates* the file and
 * the `writeSync` that follows fills it, so between those two syscalls the path
 * exists with nothing in it. A loser that takes `EEXIST` as its cue to re-read
 * lands in that window and reads zero bytes, and the old code turned that into
 * "empty after a lost create race" and threw — a plain concurrent first start,
 * failing.
 *
 * One lock covers both. A start that finds no usable token takes an `O_EXCL`
 * sentinel beside it, re-reads the token file *while holding it*, and mints only
 * if there is still nothing there; every other start waits for the sentinel and
 * re-reads rather than minting. A waiter never mints, which is what makes this
 * single-winner rather than merely serialised: minting is the only action that
 * can produce a second live token. Publishing under the lock also closes the
 * create-then-write window, because no other start reads the file until the lock
 * is released.
 *
 * **What the lock does not cover, stated rather than implied.** A sentinel is
 * advisory, so the exclusion is only as good as the agreement to use it — and
 * {@link breakAbandonedLock} deliberately breaks that agreement for a lock left
 * behind by a crashed holder, because a service that will not start until an
 * operator deletes a file is worse than the divergence being closed. That leaves
 * one window: a waiter observes an abandoned lock, and between its
 * `staleAfterMs` check and its rename another waiter breaks the same lock and
 * takes a fresh one, which the first then renames away. Both would mint. It
 * needs the holder to have been frozen inside a one-read-one-write critical
 * section for `staleAfterMs` *and* two waiters to interleave inside a rename —
 * against the original race, which needs only two starts in the same
 * millisecond. Narrowed by orders of magnitude, not eliminated; closing it fully
 * needs a real advisory lock (`flock`), which Bun does not expose and so cannot
 * be spelled the same way as the Rust side.
 */
function mintOrAdoptUnderLock(dir: string, path: string, timing: LockTiming): ResolvedToken {
  const lockPath = join(dir, LOCK_FILE_NAME)
  // Minted before the lock is taken, so the critical section is only the
  // re-read and the publish. A token that is never published costs nothing.
  const minted = randomBytes(TOKEN_BYTES).toString('hex')
  const started = Date.now()

  for (;;) {
    if (acquireLock(lockPath)) {
      try {
        // Re-read under the lock. A start that held it before us published
        // before it released, so anything here now is the winner's, and minting
        // over it would be the divergence itself.
        const underLock = readOnDisk(path)
        if (underLock.kind === 'token') {
          return underLock.resolved
        }
        if (underLock.kind === 'empty') {
          console.warn(`honmoon api: management token ${path} is empty — minting a new one`)
        }
        publishToken(path, minted)
      }
      finally {
        releaseLock(lockPath)
      }
      return { token: minted, source: 'generated', path }
    }

    // Lost the lock: wait for the winner rather than minting.
    const published = readOnDisk(path)
    if (published.kind === 'token') {
      return published.resolved
    }
    if (Date.now() - started >= timing.budgetMs) {
      throw new Error(
        `no management token in ${path} after waiting ${Math.round(timing.budgetMs / 1000)}s `
        + `for the start holding ${lockPath} — delete the lock if no other honmoon is running`,
      )
    }
    if (lockIsAbandoned(lockPath, timing.staleAfterMs)) {
      breakAbandonedLock(lockPath, timing.staleAfterMs)
      continue
    }
    sleepSync(timing.pollIntervalMs)
  }
}

/** Take the lock, or report that another start holds it. */
function acquireLock(lockPath: string): boolean {
  let fd: number
  try {
    fd = openSync(lockPath, 'wx', 0o600)
  }
  catch (error) {
    if (errorCode(error) === 'EEXIST') {
      return false
    }
    throw new Error(`cannot create the management token lock ${lockPath}: ${String(error)}`)
  }
  try {
    // Diagnostic only — for an operator reading a lock the budget message
    // named. Staleness is decided by the file's age and never by this pid: pids
    // are reused, and one from another container names a different process here
    // or no process at all.
    writeSync(fd, `${process.pid}\n`)
  }
  catch (error) {
    console.warn(
      `honmoon api: warning: could not record the holder of the management token lock ${lockPath}: ${String(error)}`,
    )
  }
  finally {
    closeSync(fd)
  }
  return true
}

/**
 * Release the lock. Called from a `finally`, so a failed publish does not leave
 * every other start waiting out the full budget.
 */
function releaseLock(lockPath: string): void {
  try {
    unlinkSync(lockPath)
  }
  catch (error) {
    console.warn(
      `honmoon api: warning: could not release the management token lock ${lockPath}: ${String(error)} `
      + '— other starts will wait for it to look abandoned',
    )
  }
}

/**
 * Write the minted token, under the lock.
 *
 * Exclusively first, so a *fresh* create neither follows nor clobbers a
 * pre-planted symlink or file. The fallback is for the one case `wx` cannot
 * express: replacing the empty file, where it would only report that the path
 * exists. The lock is what makes that truncation safe, and it is the whole
 * of #189.
 *
 * `fchmodSync` rather than the open's mode argument on that fallback, because
 * the mode applies only when the open *creates* the file: a pre-existing empty
 * `0644` placeholder would otherwise take a live credential at its old mode. It
 * runs before the bytes, so the token is never briefly readable beyond its
 * owner, and it goes through the descriptor rather than the path so it can only
 * affect the inode actually being written.
 */
function publishToken(path: string, token: string): void {
  let replacing = false
  let fd: number
  try {
    fd = openSync(path, 'wx', 0o600)
  }
  catch (error) {
    if (errorCode(error) !== 'EEXIST') {
      throw error
    }
    replacing = true
    fd = openSync(path, 'w', 0o600)
  }
  try {
    if (replacing) {
      fchmodSync(fd, 0o600)
    }
    writeSync(fd, token)
  }
  finally {
    closeSync(fd)
  }
}

/**
 * Whether the lock has been held past `staleAfterMs` — the signature of a holder
 * that crashed between taking it and releasing it.
 *
 * Wall-clock, because that is the only timestamp a second process can read. A
 * modification time in the future (a clock stepped backwards, a file copied off
 * a host that is ahead) gives a negative age, and that counts as *not*
 * abandoned: waiting is always safe, and breaking a live lock is the one thing
 * this must not do on a bad reading.
 */
function lockIsAbandoned(lockPath: string, staleAfterMs: number): boolean {
  let mtimeMs: number
  try {
    mtimeMs = statSync(lockPath).mtimeMs
  }
  catch {
    // Gone between the failed acquire and now, which is the holder releasing it.
    return false
  }
  return Date.now() - mtimeMs >= staleAfterMs
}

/**
 * Remove a lock whose holder is gone, so a crash mid-mint does not wedge every
 * later start.
 *
 * By rename rather than `unlinkSync`, because the waiters that judge one lock
 * abandoned all judge it abandoned at once: several unlinks would each delete
 * whatever is at the path, so the second would delete the *fresh* lock a faster
 * waiter had already taken and two starts would mint together. A path holds one
 * file, so of several renames exactly one moves it and the rest get `ENOENT` —
 * the removal becomes a claim. See {@link mintOrAdoptUnderLock} for the window
 * this still leaves open.
 */
function breakAbandonedLock(lockPath: string, staleAfterMs: number): void {
  const claimed = `${lockPath}.abandoned.${process.pid}`
  try {
    renameSync(lockPath, claimed)
  }
  catch (error) {
    // Another waiter claimed it first, which is the protocol working.
    if (errorCode(error) !== 'ENOENT') {
      console.warn(
        `honmoon api: warning: could not break the abandoned management token lock ${lockPath}: ${String(error)}`,
      )
    }
    return
  }
  console.warn(
    `honmoon api: warning: management token lock ${lockPath} had been held for over `
    + `${Math.round(staleAfterMs / 1000)}s — treating it as abandoned by a start that crashed while minting`,
  )
  try {
    unlinkSync(claimed)
  }
  catch (error) {
    console.warn(
      `honmoon api: warning: could not remove the broken management token lock ${claimed}: ${String(error)}`,
    )
  }
}

/**
 * Block this thread for `ms`.
 *
 * `resolveToken` is synchronous — it runs before the server exists and its
 * result is the server's constructor argument — so a waiter cannot `await`. This
 * is the only synchronous sleep the runtime offers; `Atomics.wait` on a value
 * that never changes simply times out.
 */
function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms)
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
