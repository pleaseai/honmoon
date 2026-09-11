import type { FactsSummary } from '@honmoon/policy'

/** One-line description of the request a decision was made on. */
export function describeFacts(f: FactsSummary): string {
  // A degraded event describes the engine, not a request, so it is checked
  // first: it has none of the protocol facts the branches below look for and
  // would otherwise render as an unexplained dash.
  if (f.redaction) {
    return `redaction key: ${f.redaction.key_source} (${f.redaction.transport}) — ${f.redaction.reason}`
  }
  if (f.sql && f.sql.verb) {
    return `SQL ${f.sql.verb} ${f.sql.table ?? ''}`.trim()
  }
  if (f.k8s && f.k8s.verb) {
    return `k8s ${f.k8s.verb} ${f.k8s.resource} in ${f.k8s.namespace}`
  }
  if (f.http && f.http.method) {
    return `${f.http.method} ${f.http.host}${f.http.path}`
  }
  if (f.domain) {
    return f.domain
  }
  if (f.endpoint) {
    return f.endpoint
  }
  return '—'
}

/** Render an RFC 3339 timestamp as a local, second-precision string. */
export function formatTime(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) {
    return iso
  }
  return d.toLocaleTimeString(undefined, { hour12: false })
}
