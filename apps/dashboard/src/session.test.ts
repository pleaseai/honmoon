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

function setHash(hash: string): void {
  window.location.hash = hash
}

describe('the dashboard session credential', () => {
  beforeEach(() => {
    sessionStorage.clear()
    // `replaceState` with no fragment is how `captureSession` clears one, so it
    // is also how a test starts from a URL that carries none.
    window.history.replaceState(null, '', '/')
  })

  // Declared first on purpose: `session.ts` remembers a captured secret for the
  // life of the document (the storage-blocked fallback below), so the
  // no-session assertions have to run before anything captures one.
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
    setHash('#session=abc123')
    captureSession()

    // Sent as a header the code sets itself — never as a cookie the browser
    // would also send to every other listener on 127.0.0.1 (#188).
    expect(sessionHeaders()).toEqual({ [SESSION_HEADER]: 'abc123' })
    // Survives a reload of this tab.
    expect(sessionStorage.getItem('honmoon_session')).toBe('abc123')
    // Gone from the address bar, so a bookmark made now carries no credential
    // and the hash router sees no stray route.
    expect(window.location.hash).toBe('')
  })

  test('a browser that blocks storage still gets a working session', () => {
    // Storage access throws rather than returning null when a browser blocks
    // site data; the secret must still reach the header for this document.
    // A fresh value, so only the in-memory fallback can be answering.
    const original = sessionStorage.setItem.bind(sessionStorage)
    sessionStorage.setItem = () => {
      throw new Error('storage blocked')
    }
    try {
      setHash('#session=blocked-storage-secret')
      captureSession()
      expect(sessionHeaders()).toEqual({ [SESSION_HEADER]: 'blocked-storage-secret' })
    }
    finally {
      sessionStorage.setItem = original
    }
  })
})
