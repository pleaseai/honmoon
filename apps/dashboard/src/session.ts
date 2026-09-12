/**
 * The dashboard's management credential: how it arrives, where it is kept, and
 * why it is not a cookie.
 *
 * Every `/api/*` route requires the management token (#173). The browser gets a
 * derived session secret from `GET /login?token=…` — the URL `honmoon gateway`
 * prints at startup — and this module is the whole of the dashboard's side of
 * that exchange: read the secret out of the redirect's fragment, keep it in
 * `sessionStorage`, and hand it to `api.ts` as a request header.
 *
 * Not a cookie, and deliberately not one (#188): a cookie's scope has no port
 * component (RFC 6265 §8.5), so a session cookie on `127.0.0.1` is sent to every
 * other listener on that host: a second local user could stand one up, provoke
 * this browser into a request to it (`<img src="http://127.0.0.1:9999/x">`),
 * harvest the cookie and replay it off-browser for the whole management surface,
 * including the approval writes that gate egress. `sessionStorage` is keyed by
 * the full origin — scheme, host and port — so a sibling port cannot read it, and a
 * page that has rebound DNS to this listener gets its own origin's storage,
 * which is empty. A header is attached only because the code here sets it, so
 * no page can provoke a credentialled request either.
 *
 * The cost, stated because it is the one property the cookie had and this does
 * not: the old cookie was `HttpOnly`, so script could not read its value. This
 * secret is script-readable, so a script injection *in this origin* could
 * exfiltrate a replayable credential rather than only act while the page is
 * open. The bundle is first-party and embedded in the binary, and nothing here
 * renders API data as HTML — but the trade is real, so it is written down.
 *
 * A browser that blocks site data throws on `sessionStorage` rather than
 * returning `null`. Such a browser cannot hold a session, and this module says
 * so by keeping no credential at all: the calls below fail closed to "no
 * header", the API answers 401, and the views report "not signed in" with the
 * login URL to retry. Holding the secret in a module variable instead would
 * buy one page-load of working dashboard at the cost of a credential whose
 * lifetime nothing here can see; the honest report is worth more than that.
 */

/** The header `honmoon-mgmt` reads the session secret from (`SESSION_HEADER`). */
export const SESSION_HEADER = 'X-Honmoon-Session'

/** Where the secret lives between reloads of this tab. */
const STORAGE_KEY = 'honmoon_session'

/** What `GET /login?token=…` redirects to: `/#session=<hex>`. */
const FRAGMENT_PREFIX = '#session='

/**
 * The shape the management API's `session_secret` emits, and the only shape
 * accepted here: `hex(HMAC-SHA256(...))`, so 64 lowercase hex characters.
 *
 * Checked rather than trusted because the fragment is whatever the address bar
 * says, and a hostile link to this origin can put anything after `#session=`.
 * A value containing a character no header may carry (a newline, say) would be
 * stored and then make `fetch` throw on every call — a stuck dashboard, where
 * refusing it lands on the recoverable "not signed in" path instead. The Rust
 * side pins this shape with `the_login_secret_is_64_hex_characters`, so the two
 * cannot drift silently.
 */
const SECRET_SHAPE = /^[0-9a-f]{64}$/

function read(): string | null {
  try {
    return sessionStorage.getItem(STORAGE_KEY)
  }
  catch {
    // Blocked site data. No session, reported as one — see the module doc.
    return null
  }
}

/** Whether the secret was actually stored. */
function write(secret: string): boolean {
  try {
    sessionStorage.setItem(STORAGE_KEY, secret)
    return true
  }
  catch {
    return false
  }
}

/**
 * Take the session secret out of the URL fragment, if `/login` put one there.
 *
 * Call this before the app renders. A fragment is never sent to a server, so
 * this is the only place the secret can be read from — and dropping it from the
 * address bar with `replaceState` keeps it out of a bookmark made afterwards
 * and out of the hash router's way (`App.tsx` routes on the fragment, so
 * leaving `#session=…` there would also read as an unknown route).
 *
 * Anything that is not [`SECRET_SHAPE`] is ignored, and a route fragment such
 * as `#/audit` is left exactly as it was for the router to read.
 */
export function captureSession(): void {
  const hash = window.location.hash
  if (!hash.startsWith(FRAGMENT_PREFIX)) {
    return
  }
  const secret = hash.slice(FRAGMENT_PREFIX.length)
  if (!SECRET_SHAPE.test(secret)) {
    return
  }
  // Best effort: a browser that blocks site data keeps no session, and says so
  // through the 401 path rather than through a credential nothing can see.
  write(secret)
  clearFragment()
}

/**
 * Drop the fragment from the address bar, whether or not the secret was stored.
 *
 * Unconditionally, because the alternative — keeping it so a reload could retry
 * the store — retries a block that is still in force, while leaving a live
 * credential in the one place a bookmark, a copied link, a screenshot or a
 * shared screen picks it up. The retry is illusory; the exposure is not.
 *
 * Never fatal, because this runs before the app renders: `replaceState` throws
 * in an opaque origin (a sandboxed frame, where storage throws too, so there is
 * no session to protect and no address bar anyone reads), and an exception here
 * would blank the dashboard rather than leave a fragment behind.
 */
function clearFragment(): void {
  try {
    window.history.replaceState(
      null,
      '',
      window.location.pathname + window.location.search,
    )
  }
  catch {
    // Nothing to do but render.
  }
}

/**
 * The credential header for an API call, or nothing when this tab has no
 * session — in which case the call 401s and the views say "not signed in",
 * which is the honest report and recoverable by opening the login URL again.
 *
 * `sessionStorage` is per tab, so a dashboard opened in a *new* tab starts
 * without a session even while another tab has one. That is the same
 * one-click recovery as a first login, and it is the property that makes the
 * secret unreachable from anywhere but this document.
 */
export function sessionHeaders(): Record<string, string> {
  const secret = read()
  return secret === null || secret === '' ? {} : { [SESSION_HEADER]: secret }
}
