import { GlobalRegistrator } from '@happy-dom/global-registrator'
import { beforeEach, describe, expect, test } from 'bun:test'

// `session.ts` reads `window.location` and `sessionStorage`, so the DOM has to
// exist before it is imported; static imports are hoisted above this call.
// Registering twice throws, and `bun test` runs every file in one process, so
// each DOM-using test file registers only if an earlier one has not.
if (!('window' in globalThis)) {
  GlobalRegistrator.register()
}

const { SESSION_HEADER, captureSession, sessionHeaders } = await import('./session')

/** The shape `/login` actually emits: `hex(HMAC-SHA256(...))`, 64 hex chars. */
const VALID = `${'a'.repeat(63)}7`

function setHash(hash: string): void {
  window.location.hash = hash
}

/**
 * Run `body` with one `sessionStorage` method throwing, as a browser blocking
 * site data does.
 *
 * `defineProperty`, not assignment: happy-dom's `Storage` is a `Proxy`, so
 * `sessionStorage.setItem = fn` neither replaces the method nor stores an item
 * — it is silently dropped, and a test written that way exercises the ordinary
 * storage path while claiming to exercise the blocked one.
 */
function withBlockedStorage(method: 'getItem' | 'setItem', body: () => void): void {
  const original = Object.getOwnPropertyDescriptor(Storage.prototype, method)!
  Object.defineProperty(sessionStorage, method, {
    configurable: true,
    value: () => {
      throw new Error('storage blocked')
    },
  })
  try {
    body()
  }
  finally {
    Object.defineProperty(sessionStorage, method, { configurable: true, ...original })
  }
}

describe('the dashboard session credential', () => {
  beforeEach(() => {
    sessionStorage.clear()
    // `replaceState` with no fragment is how `captureSession` clears one, so it
    // is also how a test starts from a URL that carries none.
    window.history.replaceState(null, '', '/')
  })

  test('an unauthenticated tab sends no credential header', () => {
    expect(sessionHeaders()).toEqual({})
  })

  test('a route fragment is left alone and captures nothing', () => {
    // `App.tsx` routes on the fragment, so anything that is not a login
    // fragment must survive untouched.
    setHash('#/audit')
    captureSession()
    expect(window.location.hash).toBe('#/audit')
    expect(sessionHeaders()).toEqual({})
  })

  test('an empty login fragment captures nothing', () => {
    setHash('#session=')
    expect(window.location.hash).toBe('#session=')
    captureSession()
    expect(sessionHeaders()).toEqual({})
  })

  test('the login fragment is captured, stored, and cleared from the URL', () => {
    setHash(`#session=${VALID}`)
    captureSession()

    // Sent as a header the code sets itself — never as a cookie the browser
    // would also send to every other listener on 127.0.0.1 (#188).
    expect(sessionHeaders()).toEqual({ [SESSION_HEADER]: VALID })
    // Survives a reload of this tab.
    expect(sessionStorage.getItem('honmoon_session')).toBe(VALID)
    // Gone from the address bar, so a bookmark made now carries no credential
    // and the hash router sees no stray route.
    expect(window.location.hash).toBe('')
  })

  test('a fragment that is not a 64-char hex secret is refused', () => {
    // `/login` only ever emits `hex(HMAC-SHA256(...))`, so anything else came
    // from somewhere else — a hostile link, say. Storing it would put a value
    // in `sessionStorage` that `fetch` rejects as an illegal header value,
    // making every call throw until the operator logs in again; refusing it
    // lands on the recoverable "not signed in" path instead.
    for (const junk of [
      'not-hex',
      'ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
      `${VALID}0`,
      VALID.slice(0, 63),
      'abc\ndef',
    ]) {
      sessionStorage.clear()
      window.history.replaceState(null, '', '/')
      setHash(`#session=${junk}`)
      captureSession()
      expect(sessionHeaders()).toEqual({})
      expect(sessionStorage.getItem('honmoon_session')).toBeNull()
    }
  })

  test('a browser that blocks reads reports no credential rather than throwing', () => {
    // The reload case: `sessionHeaders()` goes to storage, and a browser that
    // blocks site data throws there. It must degrade to "no credential" —
    // `api.ts` calls this inside every `fetch`, so an escaping exception would
    // break every call instead of taking the 401 "not signed in" path.
    withBlockedStorage('getItem', () => {
      expect(sessionHeaders()).toEqual({})
    })
  })

  test('a browser that blocks writes keeps no credential and no secret in the URL', () => {
    // Nothing kept the secret, so the honest report is "no credential". The
    // fragment still goes: a browser that blocks storage blocks it on the next
    // load too, so keeping it would leave a live credential in the address bar
    // — bookmarks, copied links, screenshots — to buy a retry that cannot work.
    withBlockedStorage('setItem', () => {
      setHash(`#session=${VALID}`)
      captureSession()
      expect(sessionHeaders()).toEqual({})
      expect(window.location.hash).toBe('')
    })
  })
})
