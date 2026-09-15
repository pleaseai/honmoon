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
import { Buffer } from 'node:buffer'
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { closeSync, fstatSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from 'node:fs'
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
   * The critical section it guards is one read and one write of ~65 bytes, with
   * no `fsync`, so ten seconds is four to five orders of magnitude of headroom
   * depending on what the filesystem charges for those two opens.
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

/** Compile-time exhaustiveness: an unhandled union member fails to type-check. */
function assertNever(value: never): never {
  throw new Error(`unhandled case: ${JSON.stringify(value)}`)
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
 * operator deletes a file is worse than the divergence being closed. Breaking is
 * therefore where every residual lives, and the precondition for all of them is
 * the same: a holder frozen past `staleAfterMs` inside a critical section that
 * is one read and one ~65-byte write. What a break costs, in the order the code
 * answers it:
 *
 * 1. **The broken holder resumes and publishes.** One waiter is enough — it ages
 *    the lock out, mints, publishes, and returns; the first holder then wakes
 *    with a token of its own and renames it over the successor's. Two services,
 *    two credentials, which is the bug this exists to close. Gated: the publish
 *    below runs only if {@link lockStillOurs} says the path still holds this
 *    start's lock, and the holder otherwise waits for the successor's token
 *    rather than overwriting it. The window is no longer the whole critical
 *    section, only the gap between that check and the `renameSync` inside
 *    {@link publishToken} — during which another start has to complete an entire
 *    break, mint and publish.
 * 2. **The broken holder resumes and releases.** Its unlink would remove the
 *    successor's live lock, and a third start could then acquire while the
 *    successor still believed it held exclusivity. Gated by the same comparison
 *    in {@link releaseLock}, with the same residue: POSIX has no
 *    compare-and-unlink, so the check and the unlink are two steps.
 * 3. **Two waiters break the same lock.** Between one waiter's `staleAfterMs`
 *    check and its rename, another breaks the lock and takes a fresh one, which
 *    the first then renames away. Both would mint. This needs the two waiters to
 *    interleave inside a rename on top of the frozen holder, so it is the
 *    narrowest of the three.
 *
 * None of the three is eliminated, and saying so is the point of this paragraph:
 * what the gates buy is that each window is now two adjacent syscalls rather
 * than a ten-second one, against an original race that needed only two starts in
 * the same millisecond. Closing them properly needs a real advisory lock
 * (`flock`), where the lock lives on the open file description and there is
 * nothing to check and nothing to unlink; Bun does not expose one, so it cannot
 * be spelled the same way as the Rust side, and a protocol that differs between
 * the two languages is the failure this exists to remove. Tracked as issue #257.
 */
function mintOrAdoptUnderLock(dir: string, path: string, timing: LockTiming): ResolvedToken {
  const lockPath = join(dir, LOCK_FILE_NAME)
  // Minted before the lock is taken, so the critical section is only the
  // re-read and the publish. A token that is never published costs nothing.
  const minted = randomBytes(TOKEN_BYTES).toString('hex')
  const started = Date.now()

  for (;;) {
    const attempt = attemptUnderLock(dir, path, lockPath, minted)
    switch (attempt.kind) {
      case 'adopted':
        return attempt.resolved
      case 'published':
        return { token: minted, source: 'generated', path }
      case 'broken':
        // The lock's new holder will publish a token to adopt, so wait for it
        // rather than failing. The sleep happens here and not inside
        // {@link attemptUnderLock} because this start no longer holds the lock
        // once that function has returned.
        if (Date.now() - started >= timing.budgetMs) {
          throw new Error(
            `no management token in ${path} after waiting ${Math.round(timing.budgetMs / 1000)}s `
            + `for the start holding ${lockPath} — delete the lock if no other honmoon is running`,
          )
        }
        sleepSync(timing.pollIntervalMs)
        continue
      case 'held-by-another':
        break
      default:
        // Same reason as the `OnDisk` arm below: a later outcome has to fail
        // the build rather than fall through to the waiter path.
        return assertNever(attempt)
    }

    // Lost the race to acquire: wait for the winner rather than minting.
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
    if (lockIsAbandoned(lockPath, timing.staleAfterMs)
      && breakAbandonedLock(lockPath, timing.staleAfterMs)) {
      continue
    }
    sleepSync(timing.pollIntervalMs)
  }
}

/**
 * How one pass at the critical section ended. `held-by-another` is the one
 * outcome where this start never had the lock at all.
 */
type LockAttempt
  = | { kind: 'held-by-another' }
    | { kind: 'adopted', resolved: ResolvedToken }
    | { kind: 'published' }
    | { kind: 'broken' }

/**
 * Take the lock, re-read the token file under it, and publish `minted` only if
 * there is still nothing to adopt.
 *
 * This is a function rather than the loop body it was written as so that the
 * `using` below has a scope that ends where the lock should be released. Leaving
 * that scope releases the lock because that is what a `using` declaration means
 * — the `return`s below, and a throw out of {@link readOnDisk} or
 * {@link publishToken}, need nothing written for them — where the `finally` this
 * replaces had to be positioned to cover each of them. The waiter's `sleepSync`
 * stays in the caller, because the lock is gone by the time it runs.
 *
 * `Symbol.dispose` changes when and how the release is invoked and not what it
 * does: {@link releaseLock} still compares the path's inode against the one this
 * start took before unlinking, so a lock broken out from under this start is
 * left to its new holder. The Rust CLI spells the same pair as `LockGuard` and
 * its `Drop`.
 */
function attemptUnderLock(dir: string, path: string, lockPath: string, minted: string): LockAttempt {
  using held = acquireLock(lockPath)
  if (held === null) {
    return { kind: 'held-by-another' }
  }
  // Re-read under the lock. A start that held it before us published before it
  // released, so anything here now is the winner's, and minting over it would
  // be the divergence itself.
  const underLock = readOnDisk(path)
  switch (underLock.kind) {
    case 'token':
      return { kind: 'adopted', resolved: underLock.resolved }
    case 'empty':
      console.warn(`honmoon api: management token ${path} is empty — minting a new one`)
      break
    case 'absent':
      break
    default:
      // Rust's `match` on `OnDisk` is exhaustive by construction; this is what
      // makes the TypeScript side fail the build rather than treat a later
      // variant as 'absent' and mint over it.
      return assertNever(underLock)
  }
  // Check the lock is still this start's before publishing. A holder suspended
  // between the read above and the publish below can be aged out by
  // {@link breakAbandonedLock}, after which another start mints and publishes;
  // publishing anyway would rename this token over that one and hand the two
  // services different credentials, which is #189 exactly. Not a fence — the
  // window moves to between this check and the rename, where the other start
  // now has to complete a whole break, mint and publish — but that is orders of
  // magnitude narrower than the whole critical section. Reported rather than
  // thrown, because the lock's new holder will publish a token to adopt.
  if (!held.stillOurs()) {
    console.warn(
      `honmoon api: warning: the management token lock ${lockPath} was taken by another start `
      + 'while this one held it — waiting for that start\'s token rather than publishing over it',
    )
    return { kind: 'broken' }
  }
  publishToken(dir, path, minted)
  return { kind: 'published' }
}

/**
 * The lock, held.
 *
 * The counterpart of the Rust CLI's `LockGuard`: `Symbol.dispose` here is what
 * `Drop` is there, so the release is the scope's to make in both languages
 * rather than the author's to remember. A guard is process-local, so this is
 * not part of what the two processes interlock on — that is still the lock
 * file's name, location and protocol — but it is one fewer way for the two
 * implementations to drift.
 */
interface LockGuard extends Disposable {
  /** Whether the lock path still holds the file {@link acquireLock} created. */
  stillOurs: () => boolean
}

/**
 * Take the lock, or report `null` if another start holds it.
 *
 * `ino` identifies the file this call created, so {@link releaseLock} only ever
 * unlinks that one. Without it a holder whose lock was broken — frozen past
 * `staleAfterMs`, then resumed — would unlink whatever now sits at the path,
 * which is the successor's live lock, and a third start could then acquire while
 * the successor still believed it held exclusivity. `null` where the inode could
 * not be read, which falls back to the unconditional unlink rather than leaking
 * the lock.
 *
 * `fd` stays open in the guard's closure, and that is what makes the `ino`
 * comparison mean anything: an inode number identifies a file only while the
 * inode is allocated, and ext4 and tmpfs hand a freed number straight back out,
 * so a successor created after a break routinely lands on the number recorded
 * here. An open descriptor keeps the inode allocated even after the break
 * unlinks its last name, so the successor cannot be given that number.
 * {@link releaseLock} closes it, which is why the acquire and the disposal are
 * halves of one thing. (APFS never reuses a number, which is why the Rust
 * counterpart of this was green on macOS and red on Linux CI.)
 */
function acquireLock(lockPath: string): LockGuard | null {
  let fd: number
  try {
    fd = openSync(lockPath, 'wx', 0o600)
  }
  catch (error) {
    if (errorCode(error) === 'EEXIST') {
      return null
    }
    throw new Error(`cannot create the management token lock ${lockPath}: ${String(error)}`)
  }
  let ino: number | null = null
  try {
    ino = fstatSync(fd).ino
  }
  catch (error) {
    // Not fatal — the lock is taken either way — but the release then cannot
    // tell this lock from a successor's, so say so.
    console.warn(
      `honmoon api: warning: could not identify the management token lock ${lockPath}: ${String(error)} `
      + '— releasing it will not be able to check it is still this start\'s',
    )
  }
  try {
    // Diagnostic only — for an operator reading a lock the budget message
    // named. Staleness is decided by the file's age and never by this pid: pids
    // are reused, and one from another container names a different process here
    // or no process at all. Written through {@link writeAll} anyway: a truncated
    // pid is harmless where a truncated token is not, but one write path is
    // easier to keep right than two.
    writeAll(fd, `${process.pid}\n`)
  }
  catch (error) {
    console.warn(
      `honmoon api: warning: could not record the holder of the management token lock ${lockPath}: ${String(error)}`,
    )
  }
  return {
    stillOurs: () => lockStillOurs(lockPath, ino),
    [Symbol.dispose]: () => releaseLock(lockPath, ino, fd),
  }
}

/**
 * Release the lock. Reached through the guard's `Symbol.dispose` rather than a
 * `finally`, so it runs wherever {@link attemptUnderLock}'s scope ends,
 * including on the throws out of it — a failed publish does not leave every
 * other start waiting out the full budget.
 *
 * `fd` is {@link acquireLock}'s still-open descriptor. It is closed last, after
 * the identity check and the unlink, because it is what keeps this lock's inode
 * from being handed to a successor while the check is deciding.
 */
function releaseLock(lockPath: string, ino: number | null, fd: number): void {
  try {
    releaseHeldLock(lockPath, ino)
  }
  finally {
    try {
      closeSync(fd)
    }
    catch {
      // Nothing left to do with it: the lock is already released or reported.
    }
  }
}

/**
 * Whether the lock path still holds the file {@link acquireLock} created.
 *
 * `true` where there is no inode to compare (the `fstatSync` at acquisition
 * failed), because the alternative — reading "cannot tell" as "lost" — would
 * refuse to publish and leak the lock on every start.
 */
function lockStillOurs(lockPath: string, ino: number | null): boolean {
  if (ino === null) {
    return true
  }
  try {
    // `lstatSync`, so a symlink dropped at the path is compared as itself rather
    // than as whatever it points at.
    return lstatSync(lockPath).ino === ino
  }
  catch {
    return false
  }
}

function releaseHeldLock(lockPath: string, ino: number | null): void {
  if (ino !== null && !lockStillOurs(lockPath, ino)) {
    console.warn(
      `honmoon api: warning: the management token lock ${lockPath} is no longer the one this start took `
      + '— another start treated it as abandoned, so this start\'s exclusivity did not hold',
    )
    return
  }
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
 * Write every byte of `text` to `fd`, or throw.
 *
 * `writeSync` may write fewer bytes than it was given and report the count
 * rather than throwing — a short write when the filesystem runs out of room is
 * the ordinary case, not an exotic one — so a single call can leave a prefix
 * behind and report success. For the token that is not a cosmetic truncation:
 * the publish below renames whatever the staging file holds into place, and a
 * waiter polling the token file adopts any non-empty read, so a prefix becomes a
 * live management credential with a fraction of the entropy it is supposed to
 * have. Rust publishes through `write_all`, which loops for exactly this reason;
 * this is its counterpart, and the two have to agree because they write the same
 * file.
 */
function writeAll(fd: number, text: string): void {
  const bytes = Buffer.from(text, 'utf8')
  let written = 0
  while (written < bytes.length) {
    const n = writeSync(fd, bytes, written, bytes.length - written)
    if (n <= 0) {
      throw new Error(
        `wrote ${written} of ${bytes.length} bytes and then stopped making progress`,
      )
    }
    written += n
  }
}

/**
 * Publish the minted token atomically, under the lock.
 *
 * Write-then-`rename`, not a write in place, because the lock does not keep
 * waiters out of the token file — they poll it on every iteration, by design, so
 * that they notice the moment it is published. An in-place write is visible to
 * those polls while it is still half-written: the truncating open empties the
 * file and the bytes land after it, and a waiter reading in between adopts
 * whatever prefix had arrived. The Rust side's race test caught exactly that,
 * one start holding a 63-character token while the file held 64. `wx` has the
 * same shape for the same reason: it creates the file and the write follows, so
 * a loser reading in between sees zero bytes.
 *
 * `rename` closes both, because it swaps a name rather than filling a file: a
 * waiter reads either what was there before or the whole token, never a prefix
 * of it. The lock and the rename answer different halves of #189 and neither
 * substitutes for the other — the lock makes exactly one start *decide* to mint,
 * the rename makes what it publishes visible all at once.
 *
 * The guarantee is over what honmoon publishes. A token written into place by
 * something else — an operator's `echo … > mgmt-token` during a start — is not
 * covered by it, and never was.
 *
 * It also settles the symlink question `wx` used to carry. `rename` resolves no
 * symlink on its destination, so a link another local user planted at
 * `mgmt-token` is replaced by this regular file rather than written through, and
 * the token cannot land on a path they chose. The staging file is created
 * exclusively at `0600` and is never a name anything else reads, so it needs no
 * `fchmodSync`: the mode argument applies precisely because the open creates it.
 */
function publishToken(dir: string, path: string, token: string): void {
  const staging = join(dir, `${FILE_NAME}.new.${process.pid}`)
  // A leftover from a crashed run that held this pid would fail the exclusive
  // create below. Safe to remove: the lock is held and the name is this
  // process's alone.
  try {
    unlinkSync(staging)
  }
  catch (error) {
    if (errorCode(error) !== 'ENOENT') {
      throw error
    }
  }
  const fd = openSync(staging, 'wx', 0o600)
  try {
    writeAll(fd, token)
  }
  finally {
    closeSync(fd)
  }
  try {
    renameSync(staging, path)
  }
  catch (error) {
    try {
      unlinkSync(staging)
    }
    catch (cleanup) {
      console.warn(
        `honmoon api: warning: could not remove the unpublished management token ${staging}: ${String(cleanup)}`,
      )
    }
    throw error
  }
}

/**
 * Whether the lock has been held past `staleAfterMs` — the signature of a holder
 * that crashed between taking it and releasing it.
 *
 * `lstatSync`, not `statSync`: the age this reads decides whether the lock may be
 * broken, and following a link would let whoever planted it choose that age. A
 * symlink to a file with a future modification time would then never look
 * abandoned, and since the `wx` acquire cannot succeed against it either, every
 * start would wait out its budget and refuse — permanently, on a host where
 * another local user can write this directory. A lock path that is not a regular
 * file was not written by this protocol, so it is broken rather than waited on;
 * {@link breakAbandonedLock} renames rather than unlinking and `rename` follows
 * neither operand, so breaking one is safe.
 *
 * Wall-clock, because that is the only timestamp a second process can read. A
 * modification time in the future (a clock stepped backwards, a file copied off a
 * host that is ahead) gives a negative age, and that counts as *not* abandoned:
 * waiting is always safe, and breaking a live lock is the one thing this must not
 * do on a bad reading.
 *
 * A stat that fails for any reason other than the lock being gone is reported
 * before that same `false` is returned. Silence would leave the waiter to spend
 * its whole budget and then blame "the start holding the lock" for something that
 * was never another process.
 */
function lockIsAbandoned(lockPath: string, staleAfterMs: number): boolean {
  let stats: ReturnType<typeof lstatSync>
  try {
    stats = lstatSync(lockPath)
  }
  catch (error) {
    // Released while we were looking, which is the protocol working.
    if (errorCode(error) !== 'ENOENT') {
      console.warn(
        `honmoon api: warning: could not read the management token lock ${lockPath}: ${String(error)}`,
      )
    }
    return false
  }
  if (!stats.isFile()) {
    return true
  }
  return Date.now() - stats.mtimeMs >= staleAfterMs
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
 *
 * Returns whether the lock is now somebody's to take: `true` when this call moved
 * it, `true` when another waiter had already moved it, and `false` only when it
 * is still there and still ours to wait on. The caller sleeps on `false`, so a
 * rename that keeps failing for a reason that will not clear costs one poll
 * interval per attempt instead of spinning and flooding the console for the whole
 * budget.
 */
function breakAbandonedLock(lockPath: string, staleAfterMs: number): boolean {
  const claimed = `${lockPath}.abandoned.${process.pid}`
  try {
    renameSync(lockPath, claimed)
  }
  catch (error) {
    // Another waiter claimed it first, which is the protocol working.
    if (errorCode(error) === 'ENOENT') {
      return true
    }
    console.warn(
      `honmoon api: warning: could not break the abandoned management token lock ${lockPath}: ${String(error)}`,
    )
    return false
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
  return true
}

/**
 * Block this thread for `ms`.
 *
 * `resolveToken` is synchronous — it runs before the server exists and its result
 * is the server's constructor argument — so a waiter cannot `await`. This package
 * is a Bun service (`Bun.serve` in `index.ts`, `Bun.file` in `audit.ts`), so its
 * built-in synchronous sleep is available and is what this uses.
 */
function sleepSync(ms: number): void {
  Bun.sleepSync(ms)
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
