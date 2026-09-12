/**
 * Typed client for the Honmoon management API.
 *
 * Served by the Rust data-plane binary (`honmoon gateway`) at the same origin
 * the dashboard is embedded in; `vite dev` proxies these paths to a local
 * gateway (see `vite.config.ts`).
 *
 * Every `/api/*` route requires the management token (#173). The browser's
 * credential is the session secret `GET /login?token=…` hands over — the URL
 * `honmoon gateway` prints at startup — which `session.ts` keeps in
 * origin-scoped `sessionStorage` and every call here attaches as a header.
 *
 * It is deliberately not a cookie (#188): a cookie would be sent to every other
 * listener on `127.0.0.1` too, since cookie scope has no port, and a harvested
 * one replays off-browser. Setting the header explicitly is also what keeps a
 * cross-origin page from riding on this credential — a custom header forces a
 * CORS preflight the management API never answers.
 *
 * A 401 therefore means "not logged in", and saying so is the difference
 * between a dashboard an operator can get back into and one that just looks
 * broken.
 */
import type { AuditEvent, PendingApproval, Policy } from '@honmoon/policy'
import { sessionHeaders } from './session'

export interface PolicyResponse {
  yaml: string
  parsed: Policy
}

/**
 * The message a 401 gets, in place of an opaque status line.
 *
 * Exported so the views can tell "not signed in" from "the gateway is down".
 * `usePolling` keeps an error's `message` rather than the error itself, so this
 * constant — not an error subclass — is what survives to the render.
 */
export const NOT_SIGNED_IN
  = 'not signed in — open the dashboard URL `honmoon gateway` printed at startup '
    + '(http://<mgmt-addr>/login?token=…), or read the token from ~/.honmoon/mgmt-token'

function failure(path: string, res: Response): Error {
  return new Error(
    res.status === 401 ? NOT_SIGNED_IN : `${path} → ${res.status} ${res.statusText}`,
  )
}

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(path, { headers: sessionHeaders() })
  if (!res.ok) {
    throw failure(path, res)
  }
  return res.json() as Promise<T>
}

async function post(path: string): Promise<Response> {
  const res = await fetch(path, { method: 'POST', headers: sessionHeaders() })
  if (!res.ok) {
    throw failure(path, res)
  }
  return res
}

export function getAudit(limit = 200): Promise<AuditEvent[]> {
  return getJson<AuditEvent[]>(`/api/audit?limit=${limit}`)
}

export function getApprovals(): Promise<PendingApproval[]> {
  return getJson<PendingApproval[]>('/api/approvals')
}

export function getPolicy(): Promise<PolicyResponse> {
  return getJson<PolicyResponse>('/api/policy')
}

export function approve(id: number): Promise<Response> {
  return post(`/api/approvals/${id}/approve`)
}

export function reject(id: number): Promise<Response> {
  return post(`/api/approvals/${id}/reject`)
}
