import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { DEFAULT_LOCK_TIMING, defaultDir, isAuthorized, resolveToken } from './auth'

describe('isAuthorized', () => {
  test('accepts exactly the configured token as a bearer credential', () => {
    expect(isAuthorized('Bearer s3cr3t-token', 's3cr3t-token')).toBe(true)
  })

  test('rejects a missing, malformed, wrong or differently-sized credential', () => {
    expect(isAuthorized(null, 's3cr3t-token')).toBe(false)
    expect(isAuthorized(undefined, 's3cr3t-token')).toBe(false)
    expect(isAuthorized('s3cr3t-token', 's3cr3t-token')).toBe(false)
    expect(isAuthorized('Basic s3cr3t-token', 's3cr3t-token')).toBe(false)
    // Same length, one byte differs (`0` vs `o`).
    expect(isAuthorized('Bearer s3cr3t-t0ken', 's3cr3t-token')).toBe(false)
    // A matching prefix must not pass, and a length mismatch must not throw —
    // `timingSafeEqual` does when handed unequal-length buffers, which is why
    // both sides are folded through a fixed-width digest first.
    expect(isAuthorized('Bearer s3cr3t', 's3cr3t-token')).toBe(false)
    expect(isAuthorized('Bearer s3cr3t-token-extra', 's3cr3t-token')).toBe(false)
  })
})

describe('resolveToken', () => {
  let dir: string
  const envKeys = ['HONMOON_MGMT_TOKEN', 'HONMOON_HOOK_TOKEN'] as const
  const saved = new Map<string, string | undefined>()

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'honmoon-api-auth-'))
    for (const key of envKeys) {
      saved.set(key, process.env[key])
      delete process.env[key]
    }
  })

  afterEach(() => {
    for (const key of envKeys) {
      const value = saved.get(key)
      if (value === undefined) {
        delete process.env[key]
      }
      else {
        process.env[key] = value
      }
    }
    rmSync(dir, { recursive: true, force: true })
  })

  test('prefers the environment and never persists it', () => {
    process.env.HONMOON_MGMT_TOKEN = 'from-the-environment'
    expect(resolveToken(dir)).toEqual({ token: 'from-the-environment', source: 'environment' })
  })

  test('accepts the deprecated HONMOON_HOOK_TOKEN, with HONMOON_MGMT_TOKEN winning', () => {
    process.env.HONMOON_HOOK_TOKEN = 'deprecated'
    expect(resolveToken(dir).token).toBe('deprecated')
    process.env.HONMOON_MGMT_TOKEN = 'current'
    expect(resolveToken(dir).token).toBe('current')
  })

  test('mints an owner-only token on first use and reuses it afterwards', () => {
    const first = resolveToken(dir)
    expect(first.source).toBe('generated')
    expect(first.token).toMatch(/^[0-9a-f]{64}$/)

    const path = join(dir, 'mgmt-token')
    expect(readFileSync(path, 'utf8')).toBe(first.token)
    // A credential another local user can read is the exposure this closes.
    if (process.platform !== 'win32') {
      expect(statSync(path).mode & 0o777).toBe(0o600)
    }

    // The Rust gateway reads this same file, so a second resolution that minted
    // a different token would silently disagree with it.
    const second = resolveToken(dir)
    expect(second.token).toBe(first.token)
    expect(second.source).toBe('persisted')
  })

  test('replaces an empty token file rather than serving an empty credential', () => {
    const path = join(dir, 'mgmt-token')
    writeFileSync(path, '\n')
    const resolved = resolveToken(dir)
    expect(resolved.source).toBe('generated')
    expect(resolved.token).toMatch(/^[0-9a-f]{64}$/)
  })

  test.skipIf(process.platform === 'win32')(
    'tightens the mode when it replaces an empty token file',
    () => {
      // `openSync`'s mode argument applies only when the open creates the file,
      // so a pre-existing 0644 placeholder would keep that mode and hand a live
      // credential to every other local user on the host.
      const path = join(dir, 'mgmt-token')
      writeFileSync(path, '\n', { mode: 0o644 })
      chmodSync(path, 0o644)
      const resolved = resolveToken(dir)
      expect(resolved.source).toBe('generated')
      expect(statSync(path).mode & 0o777).toBe(0o600)
    },
  )

  test('falls back to a relative .honmoon when HOME is unset, as the Rust CLI does', () => {
    // The two processes read one file. `homedir()` would resolve the account
    // home from the passwd database here, disagreeing with the Rust side's
    // working-directory-relative fallback, and they would mint different
    // tokens from the same configuration.
    const home = process.env.HOME
    try {
      delete process.env.HOME
      expect(defaultDir()).toBe('.honmoon')
    }
    finally {
      if (home !== undefined) {
        process.env.HOME = home
      }
    }
  })

  test('refuses an explicitly empty environment token rather than falling back', () => {
    // The Rust CLI bails on the same input (`an_empty_explicit_token_is_refused`).
    // Falling back to the file here would give this service a different
    // credential from a gateway that refuses to start at all.
    const previous = process.env.HONMOON_MGMT_TOKEN
    try {
      process.env.HONMOON_MGMT_TOKEN = '   '
      expect(() => resolveToken(dir)).toThrow()
    }
    finally {
      if (previous === undefined) {
        delete process.env.HONMOON_MGMT_TOKEN
      }
      else {
        process.env.HONMOON_MGMT_TOKEN = previous
      }
    }
  })

  test.skipIf(process.platform === 'win32')(
    'warns when the persisted token is readable beyond its owner',
    () => {
      // The Rust CLI warns on this same file; surfacing it to one operator and
      // not the other is the asymmetry, since both processes read one token.
      const path = join(dir, 'mgmt-token')
      writeFileSync(path, 'a-persisted-token\n')
      chmodSync(path, 0o644)
      const warnings: string[] = []
      const original = console.warn
      console.warn = (...args: unknown[]) => warnings.push(args.join(' '))
      try {
        expect(resolveToken(dir).source).toBe('persisted')
      }
      finally {
        console.warn = original
      }
      expect(warnings.join(' ')).toContain('readable beyond its owner')
    },
  )

  test.skipIf(process.platform === 'win32')(
    'warns when the token directory is writable beyond its owner',
    () => {
      // The file's own mode cannot stand in for this: a local user who can
      // write the directory unlinks the token and installs a 0600 file of their
      // own, which the file check then approves. The Rust loader warns here, so
      // this one must too — the whole point of both is that one operator does
      // not see an exposure the other is shown.
      const path = join(dir, 'mgmt-token')
      writeFileSync(path, 'a-persisted-token\n')
      chmodSync(path, 0o600)
      chmodSync(dir, 0o777)
      const warnings: string[] = []
      const original = console.warn
      console.warn = (...args: unknown[]) => warnings.push(args.join(' '))
      try {
        expect(resolveToken(dir).source).toBe('persisted')
      }
      finally {
        console.warn = original
        chmodSync(dir, 0o700)
      }
      expect(warnings.join(' ')).toContain('writable beyond its owner')
    },
  )

  // Gated like the two mode tests above: on Windows this file falls through to
  // the guard that refuses to generate a token there, so it would throw rather
  // than reach the assertion.
  test.skipIf(process.platform === 'win32')(
    'replaces a padding-only token file the same way the Rust loader does',
    () => {
    // U+0085 is the case JavaScript's `\s` misses: it is Unicode White_Space,
    // so the Rust loader trims it away and mints a fresh token, while a bare
    // `.trim()` here left it intact and served it as a credential. The two
    // services would then hold different tokens from one file.
      for (const padding of ['\u0085', '\uFEFF', '\uFEFF \u0085\n']) {
        const path = join(dir, 'mgmt-token')
        writeFileSync(path, padding)
        const resolved = resolveToken(dir)
        expect(resolved.source).toBe('generated')
        expect(resolved.token).not.toBe('')
      }
    },
  )

  /**
   * `resolveToken` is synchronous, so two calls in one process cannot
   * interleave — the race only exists between processes, which is exactly the
   * shape of the bug (the gateway and this service starting together). Real
   * subprocesses are therefore the only way to drive it.
   */
  const AUTH_MODULE = new URL('./auth.ts', import.meta.url).pathname

  /**
   * Start a resolution in its own process, optionally held at `gate` until the
   * test creates that file.
   *
   * The gate is what makes the race reliable rather than incidental: without it
   * each child enters `resolveToken` whenever its interpreter happens to finish
   * booting, and the spread across eight of those is wide enough that the first
   * regularly finishes before the last begins — the collision the test exists to
   * produce then simply does not happen. Waiting on a file the parent creates
   * once every child is already spinning brings them into the resolver within
   * about a millisecond of each other.
   */
  function startResolution(target: string, gate?: string): Bun.Subprocess<'ignore', 'pipe', 'pipe'> {
    const script = [
      `const { resolveToken } = await import(${JSON.stringify(AUTH_MODULE)})`,
      ...(gate === undefined
        ? []
        : [
            `const { existsSync } = await import('node:fs')`,
            `const idle = new Int32Array(new SharedArrayBuffer(4))`,
            `while (!existsSync(${JSON.stringify(gate)})) Atomics.wait(idle, 0, 0, 1)`,
          ]),
      `const r = resolveToken(${JSON.stringify(target)})`,
      // The source decides whether honmoon may print the token, so an adopted
      // one mislabelled 'generated' is a real defect the token alone hides.
      `process.stdout.write(r.token + ' ' + r.source)`,
    ].join('\n')
    return Bun.spawn([process.execPath, '-e', script], { stdout: 'pipe', stderr: 'pipe' })
  }

  async function resolutionOf(
    started: Bun.Subprocess<'ignore', 'pipe', 'pipe'>,
  ): Promise<{ token: string, source: string }> {
    const [out, stderr] = await Promise.all([
      new Response(started.stdout).text(),
      new Response(started.stderr).text(),
    ])
    expect(await started.exited).toBe(0)
    // Surfaced rather than swallowed: a start that refused has its reason here,
    // and the bare token comparison below would say only "expected '' to be ...".
    if (out === '') {
      throw new Error(`a concurrent start produced no token: ${stderr}`)
    }
    const [token, source] = out.split(' ')
    return { token: token ?? '', source: source ?? '' }
  }

  async function tokenOf(started: Bun.Subprocess<'ignore', 'pipe', 'pipe'>): Promise<string> {
    return (await resolutionOf(started)).token
  }

  async function concurrentResolutions(starts: number): Promise<{ tokens: string[], onDisk: string }> {
    // Outside `dir`, so the resolver under test sees only the token file and
    // its lock.
    const gate = `${dir}.go`
    const running = Array.from({ length: starts }, () => startResolution(dir, gate))
    // Long enough for every interpreter to reach the gate; they then all leave
    // it together.
    await Bun.sleep(500)
    writeFileSync(gate, '')
    try {
      const tokens = await Promise.all(running.map(tokenOf))
      return { tokens, onDisk: readFileSync(join(dir, 'mgmt-token'), 'utf8').trim() }
    }
    finally {
      rmSync(gate, { force: true })
    }
  }

  /**
   * The race #189 is about. An empty file used to be replaced with an
   * unconditional truncating write, so every start that saw it minted, wrote,
   * and returned *its own* token. The file then authenticated exactly one of
   * them — a dashboard that works and an API that 401s, or the reverse.
   */
  test.skipIf(process.platform === 'win32')(
    'concurrent starts over an empty token file all hold the token on disk',
    async () => {
      writeFileSync(join(dir, 'mgmt-token'), '\n')

      const { tokens, onDisk } = await concurrentResolutions(8)

      expect(onDisk).toMatch(/^[0-9a-f]{64}$/)
      for (const token of tokens) {
        expect(token).toBe(onDisk)
      }
      expect(existsSync(join(dir, 'mgmt-token.lock'))).toBe(false)
    },
    30_000,
  )

  /**
   * The create race had no test either. `wx` creates the file and the write
   * that follows fills it, so a loser re-reading on EEXIST could land between
   * the two syscalls and read zero bytes — which the old code turned into
   * "empty after a lost create race" and threw.
   */
  test.skipIf(process.platform === 'win32')(
    'concurrent first starts all hold the token on disk',
    async () => {
      // Repeated: this window is a two-syscall gap rather than the whole
      // read-mint-write span the empty-file race opens, so one batch caught the
      // old behaviour on only some runs.
      for (let round = 0; round < 3; round++) {
        rmSync(dir, { recursive: true, force: true })
        mkdirSync(dir, { recursive: true, mode: 0o700 })

        const { tokens, onDisk } = await concurrentResolutions(8)

        expect(onDisk).toMatch(/^[0-9a-f]{64}$/)
        for (const token of tokens) {
          expect(token).toBe(onDisk)
        }
      }
    },
    60_000,
  )

  /**
   * A waiter adopts what the holder publishes. It must never mint: a second
   * token is the divergence, and waiting is the only safe thing to do with an
   * empty file somebody else has claimed.
   */
  test.skipIf(process.platform === 'win32')(
    'a waiter adopts the token the lock holder publishes',
    async () => {
      const path = join(dir, 'mgmt-token')
      const lock = join(dir, 'mgmt-token.lock')
      writeFileSync(path, '\n')
      // Stand in for a concurrent start that has taken the lock and not yet
      // published.
      writeFileSync(lock, '1\n')

      const waiter = startResolution(dir)
      await Bun.sleep(300)
      // Published by rename, the way publishToken does it. A plain writeFileSync
      // truncates and then fills, and the waiter — which polls the file on every
      // iteration by design — reads the prefix.
      const staging = join(dir, 'holder-staging')
      writeFileSync(staging, 'the-holders-token\n')
      renameSync(staging, path)
      rmSync(lock)

      const adopted = await resolutionOf(waiter)
      expect(adopted.token).toBe('the-holders-token')
      // An adopted token is not this start's to print.
      expect(adopted.source).toBe('persisted')
    },
    30_000,
  )

  /**
   * A lock nobody releases must not become a mint. Refusing names the lock and
   * leaves the file untouched, so the operator can see what to delete; minting
   * would hand this service a credential nothing else holds.
   */
  test.skipIf(process.platform === 'win32')(
    'a waiter refuses rather than minting when the lock is never released',
    () => {
      writeFileSync(join(dir, 'mgmt-token'), '\n')
      writeFileSync(join(dir, 'mgmt-token.lock'), '1\n')

      expect(() => resolveToken(dir, { ...DEFAULT_LOCK_TIMING, budgetMs: 100, pollIntervalMs: 5 }))
        .toThrow(/mgmt-token\.lock/)
      expect(readFileSync(join(dir, 'mgmt-token'), 'utf8')).toBe('\n')
    },
  )

  /**
   * A holder that crashes between taking the lock and releasing it leaves the
   * sentinel behind. Waiting for it forever would turn a rare divergence into a
   * service that never starts again, so an aged lock is broken.
   */
  test.skipIf(process.platform === 'win32')(
    'an abandoned lock is broken rather than wedging the next start',
    () => {
      const lock = join(dir, 'mgmt-token.lock')
      writeFileSync(join(dir, 'mgmt-token'), '\n')
      writeFileSync(lock, '999999\n')

      // `staleAfterMs: 0` makes the lock just written look like one a crashed
      // start left behind, without the test waiting out a real staleness bound.
      const warnings: string[] = []
      const original = console.warn
      console.warn = (...args: unknown[]) => warnings.push(args.join(' '))
      let resolved: ReturnType<typeof resolveToken>
      try {
        resolved = resolveToken(dir, { ...DEFAULT_LOCK_TIMING, staleAfterMs: 0, pollIntervalMs: 5 })
      }
      finally {
        console.warn = original
      }

      expect(resolved.source).toBe('generated')
      expect(resolved.token).toMatch(/^[0-9a-f]{64}$/)
      expect(existsSync(lock)).toBe(false)
      // Never silently: an operator whose gateway crashed mid-mint should see why
      // the lock they may have noticed is gone.
      expect(warnings.join(' ')).toContain('treating it as abandoned')
    },
  )

  /**
   * A symlink planted at the token path must not receive the token.
   *
   * `wx` refuses a symlink — a dangling one included, which it reports as
   * EEXIST like any other existing path — so an in-place publish that fell back
   * to a truncating write on that error wrote *through* the link: another local
   * user who can write this directory points `mgmt-token` at a path they chose
   * and the token lands there at 0600. Publishing by rename resolves no link on
   * its destination, so the planted link is replaced by the real file.
   */
  test.skipIf(process.platform === 'win32')(
    'replaces a symlink at the token path rather than writing through it',
    () => {
      const target = join(dir, 'a-path-the-attacker-chose')
      const path = join(dir, 'mgmt-token')
      symlinkSync(target, path)

      const resolved = resolveToken(dir)

      expect(existsSync(target)).toBe(false)
      expect(lstatSync(path).isSymbolicLink()).toBe(false)
      expect(readFileSync(path, 'utf8')).toBe(resolved.token)
      expect(existsSync(join(dir, 'mgmt-token.lock'))).toBe(false)
    },
  )

  /**
   * A lock path another local user planted as a symlink must not hold every
   * start off forever.
   *
   * `statSync` would report the target's age, so a link to a file with a future
   * mtime never looks abandoned while `wx` can never succeed against it either —
   * every start would wait out its budget and refuse, permanently.
   */
  test.skipIf(process.platform === 'win32')(
    'breaks a symlinked lock path rather than waiting on it forever',
    () => {
      writeFileSync(join(dir, 'mgmt-token'), '\n')
      // Dangling, so no target age could make it look fresh: what must decide is
      // that this is not a regular file.
      symlinkSync(join(dir, 'never-created'), join(dir, 'mgmt-token.lock'))

      // staleAfterMs far in the future, so only the not-a-regular-file rule can
      // break this lock.
      const resolved = resolveToken(dir, { ...DEFAULT_LOCK_TIMING, pollIntervalMs: 5 })

      expect(resolved.source).toBe('generated')
      expect(resolved.token).toMatch(/^[0-9a-f]{64}$/)
    },
  )

  /**
   * A publish that fails must still release the lock, or one failed start leaves
   * every later one to wait out staleAfterMs before it can even try.
   */
  test.skipIf(process.platform === 'win32')(
    'releases the lock when the publish fails',
    () => {
      const locked = join(dir, 'locked-down')
      mkdirSync(locked, { mode: 0o700 })
      writeFileSync(join(locked, 'mgmt-token'), '\n')
      // A directory sitting where the staging file has to be created, so the
      // publish fails *after* the lock is taken. Making the whole directory
      // read-only instead — which this test used to do — fails `acquireLock`
      // first, so the release it is named for is never reached and the
      // assertion below passes on a lock that was never created.
      mkdirSync(join(locked, `mgmt-token.new.${process.pid}`))

      expect(() => resolveToken(locked, { ...DEFAULT_LOCK_TIMING, pollIntervalMs: 5 })).toThrow()

      expect(existsSync(join(locked, 'mgmt-token.lock'))).toBe(false)
    },
  )

  /**
   * The release-side identity check, on the path that exists for it: a start
   * whose lock was broken out from under it must leave the successor's lock
   * alone. Unlinking unconditionally would take a live lock with it, and a
   * third start could then acquire while the successor still believed it held
   * exclusivity.
   *
   * `console.warn` is the seam that makes this deterministic in one process.
   * The empty-file warning is emitted under the lock and before the identity
   * check, so swapping the lock file there is exactly the state a break leaves
   * behind — without two interpreters having to interleave on it.
   */
  test.skipIf(process.platform === 'win32')(
    'leaves a successor\'s lock alone when its own was broken, and adopts its token',
    () => {
      const path = join(dir, 'mgmt-token')
      const lock = join(dir, 'mgmt-token.lock')
      writeFileSync(path, '\n')

      const warnings: string[] = []
      const original = console.warn
      console.warn = (...args: unknown[]) => {
        const line = args.join(' ')
        warnings.push(line)
        if (!line.includes('is empty')) {
          return
        }
        // Stand in for another start that aged this lock out, took its own, and
        // published under it. `rmSync` then `writeFileSync` rather than a write
        // in place, so the successor's lock is a different inode — which is the
        // only thing the identity check can see.
        rmSync(lock)
        writeFileSync(lock, '424242\n', { mode: 0o600 })
        const staging = join(dir, 'successor-staging')
        writeFileSync(staging, 'the-successors-token\n', { mode: 0o600 })
        renameSync(staging, path)
      }
      let resolved: ReturnType<typeof resolveToken>
      try {
        resolved = resolveToken(dir, { ...DEFAULT_LOCK_TIMING, pollIntervalMs: 5 })
      }
      finally {
        console.warn = original
      }

      // The successor's lock survived this start's release.
      expect(readFileSync(lock, 'utf8')).toBe('424242\n')
      // And this start adopted rather than publishing over the successor.
      expect(resolved).toEqual({ token: 'the-successors-token', source: 'persisted', path })
      const said = warnings.join(' ')
      expect(said).toContain('was taken by another start')
      expect(said).toContain('no longer the one this start took')
    },
  )

  /**
   * The other throw out of the critical section. `releases the lock when the
   * publish fails` covers the publish; nothing covered the re-read, because both
   * unreadable-token tests below fail at the *pre-lock* read and so never reach a
   * lock at all — the shape PR #255 had to restructure two tests for.
   *
   * The seam here is the directory-mode warning, which runs after the pre-lock
   * read and before the lock is taken. Corrupting the token file there leaves the
   * re-read under the lock as the first read that can fail, and the assertions
   * below are what distinguish the two reads: the file does not exist when the
   * pre-lock read runs, so a `not valid UTF-8` refusal can only have come from
   * the re-read, and the warning having fired is what says execution got that
   * far.
   */
  test.skipIf(process.platform === 'win32')(
    'releases the lock when the re-read under it fails',
    () => {
      const path = join(dir, 'mgmt-token')
      const lock = join(dir, 'mgmt-token.lock')
      // Group- and other-writable, so the directory check warns. No token file:
      // the pre-lock read has to succeed, or the lock is never taken.
      chmodSync(dir, 0o777)

      let corrupted = false
      const original = console.warn
      console.warn = (...args: unknown[]) => {
        if (corrupted || !args.join(' ').includes('writable beyond its owner')) {
          return
        }
        corrupted = true
        writeFileSync(path, new Uint8Array([0xFF, 0xFE, 0x41]), { mode: 0o600 })
      }
      try {
        expect(() => resolveToken(dir, { ...DEFAULT_LOCK_TIMING, pollIntervalMs: 5 }))
          .toThrow(/not valid UTF-8/)
      }
      finally {
        console.warn = original
        chmodSync(dir, 0o700)
      }

      // The seam fired, so the pre-lock read returned and the lock was reached.
      expect(corrupted).toBe(true)
      // And the guard released it on the way out of the throw.
      expect(existsSync(lock)).toBe(false)
    },
  )

  /**
   * The in-lock adopt branch (#265): a start that *wins* the `wx` race and then
   * finds a token already on disk under the lock. It won the lock but lost the
   * mint, because a rival published and released between this start's pre-lock
   * read and its acquisition. Minting there instead of adopting is #189 exactly
   * — two services, two credentials.
   *
   * Nothing pinned it. `a waiter adopts the token the lock holder publishes`
   * covers the *outer* fallback adopt, the re-read after a `held-by-another`
   * result, which is a different branch; the concurrent tests above reach this
   * one only by luck of real process timing and assert nothing about which path
   * any start took, so a regression to a mint here passed the suite.
   *
   * The seam is the directory-mode warning, the same one the test above uses,
   * for the same structural reason: it runs after the pre-lock read and before
   * the lock is taken, which is precisely the window this rival has to publish
   * in. Publishing there rather than corrupting leaves the lock free for this
   * start to win and a token under it to adopt — one process, no timing, and no
   * test-only surface on a module whose subject is a credential.
   */
  test.skipIf(process.platform === 'win32')(
    'adopts a token published under the lock it won, and publishes nothing of its own',
    () => {
      const path = join(dir, 'mgmt-token')
      // Group- and other-writable, so the directory check warns. No token file,
      // so the pre-lock read returns `absent` and this start goes on to take the
      // lock. What it must not return is `token`: `resolveToken` answers from
      // that read and never reaches a lock at all.
      chmodSync(dir, 0o777)

      let published = false
      // A sentinel rather than `undefined`, so the comparison below stays a real
      // inode check rather than one TypeScript has to be talked out of; the
      // `published` assertion is what rules out its ever reaching that check.
      let rivalIno = -1
      const warnings: string[] = []
      const original = console.warn
      console.warn = (...args: unknown[]) => {
        const line = args.join(' ')
        warnings.push(line)
        if (published || !line.includes('writable beyond its owner')) {
          return
        }
        published = true
        // Stand in for the rival: it took the lock, published, and released,
        // all between this start's pre-lock read and its acquisition. By rename
        // and at 0600, the way `publishToken` does it, so the mode check under
        // the lock stays quiet and the inode recorded here is the rival's own.
        const staging = join(dir, 'rival-staging')
        writeFileSync(staging, 'the-rivals-token\n', { mode: 0o600 })
        renameSync(staging, path)
        rivalIno = statSync(path).ino
      }
      let resolved: ReturnType<typeof resolveToken>
      try {
        resolved = resolveToken(dir, { ...DEFAULT_LOCK_TIMING, pollIntervalMs: 5 })
      }
      finally {
        console.warn = original
        chmodSync(dir, 0o700)
      }

      // The seam fired, so the pre-lock read returned `absent` and this start
      // went on to take the lock itself rather than waiting on a rival's.
      expect(published).toBe(true)
      // It adopted: the rival's token, labelled as somebody else's.
      expect(resolved).toEqual({ token: 'the-rivals-token', source: 'persisted', path })
      // And published nothing of its own. The return value alone would not say
      // that — a start that adopted *and* also wrote its mint would satisfy it
      // while leaving the rival, and the gateway, on a token this file no longer
      // holds. The bytes rule that out; the inode additionally rules out a
      // republish of what was adopted, since `publishToken` renames and so
      // cannot leave the rival's file in place.
      expect(readFileSync(path, 'utf8')).toBe('the-rivals-token\n')
      expect(statSync(path).ino).toBe(rivalIno)
      // Nothing else in the directory either: no staging file, and no lock —
      // the guard released the one this start took.
      expect(readdirSync(dir)).toEqual(['mgmt-token'])
      // And nothing else had anything to say. In particular no empty-file
      // warning, which is the other way into the mint below the adopt branch.
      expect(warnings).toEqual([expect.stringContaining('writable beyond its owner')])
    },
  )

  test('refuses a token file that is not valid UTF-8 instead of serving U+FFFD', () => {
    // Bun substitutes U+FFFD for malformed bytes rather than throwing, so a
    // corrupt file would otherwise become the ordinary-looking token "\uFFFD"
    // and be served as a credential. Rust's read_to_string refuses the same
    // file, so accepting it here would abort the gateway while @honmoon/api
    // started under a guessable token.
    writeFileSync(join(dir, 'mgmt-token'), new Uint8Array([0xFF, 0xFE, 0x41]))
    expect(() => resolveToken(dir)).toThrow(/not valid UTF-8/)
  })

  test('aborts on an unreadable token file instead of minting a second one', () => {
    // A directory where the file should be: the read fails with something other
    // than ENOENT, which must not be recovered from by generating a token that
    // disagrees with whatever holds the real one.
    mkdirSync(join(dir, 'mgmt-token'))
    expect(() => resolveToken(dir)).toThrow()
  })
})
