/**
 * HTTP routing for `@honmoon/api`, separated from `index.ts` so the gate can be
 * tested.
 *
 * `index.ts` starts a listener the moment it is imported, so a test cannot
 * import it to check that `/api/audit` refuses an unauthenticated caller — and
 * an untested gate is exactly where "gated in the docs, open in the code" hides
 * (#173). The handler is built here from its two inputs and wired to `Bun.serve`
 * there.
 */
import type { AuditEvent } from '@honmoon/policy'
import { auditStats, queryAudit, queryFromParams } from './audit'
import { isAuthorized, unauthorized } from './auth'

export interface HandlerConfig {
  /** The management token every route but `/healthz` requires. */
  token: string
  /** The current audit events (cached by the caller). */
  loadEvents: () => Promise<AuditEvent[]>
}

export function createFetchHandler({ token, loadEvents }: HandlerConfig) {
  // `resolveToken` never yields an empty token, but `HandlerConfig` accepts any
  // string and this is the boundary where the gate is built. An empty token
  // authenticates `Authorization: Bearer ` and so reopens the unauthenticated
  // mode #173 closes — refuse to build a handler that would.
  if (token.trim() === '') {
    throw new Error('refusing to serve with an empty management token')
  }
  return async function handle(req: Request): Promise<Response> {
    const url = new URL(req.url)

    // `/healthz` stays open: it carries no data, and a liveness probe that
    // needed the credential would push the token into every supervisor config.
    if (url.pathname === '/healthz') {
      return Response.json({ status: 'ok' })
    }

    // Gate everything else, unknown paths included — a 404 an unauthenticated
    // caller can tell apart from a 401 reveals which routes exist.
    if (!isAuthorized(req.headers.get('authorization'), token)) {
      return unauthorized()
    }

    if (url.pathname === '/api/audit') {
      const events = await loadEvents()
      return Response.json(queryAudit(events, queryFromParams(url.searchParams)))
    }

    if (url.pathname === '/api/audit/stats') {
      const events = await loadEvents()
      return Response.json(auditStats(events))
    }

    return new Response('Not found', { status: 404 })
  }
}
