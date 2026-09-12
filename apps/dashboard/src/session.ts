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
 */

/** The header `honmoon-mgmt` reads the session secret from (`SESSION_HEADER`). */
export const SESSION_HEADER = 'X-Honmoon-Session'

/** Where the secret lives between reloads of this tab. */
const STORAGE_KEY = 'honmoon_session'

/** What `GET /login?token=…` redirects to: `/#session=<hex>`. */
const FRAGMENT_PREFIX = '#session='

/**
 * The secret for this document, when `sessionStorage` is unavailable.
 *
 * Storage access throws rather than returning `null` when a browser blocks it
 * (a site-data setting, some embedded webviews). Holding the captured value
 * here too means such a browser still gets a working dashboard for the life of
 * the page instead of an unexplained "not signed in".
 */
let captured: string | null = null

function read(): string | null {
  try {
    return sessionStorage.getItem(STORAGE_KEY)
  }
  catch {
    return null
  }
}

function write(secret: string): void {
  try {
    sessionStorage.setItem(STORAGE_KEY, secret)
  }
  catch {
    // Held in `captured` instead; see above.
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
 */
export function captureSession(): void {
  const hash = window.location.hash
  if (!hash.startsWith(FRAGMENT_PREFIX)) {
    return
  }
  const secret = hash.slice(FRAGMENT_PREFIX.length)
  if (secret === '') {
    return
  }
  captured = secret
  write(secret)
  window.history.replaceState(
    null,
    '',
    window.location.pathname + window.location.search,
  )
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
  const secret = captured ?? read()
  return secret === null || secret === '' ? {} : { [SESSION_HEADER]: secret }
}
