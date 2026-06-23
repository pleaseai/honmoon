/**
 * Typed client for the Honmoon management API.
 *
 * Served by the Rust data-plane binary (`honmoon gateway`) at the same origin
 * the dashboard is embedded in; `vite dev` proxies these paths to a local
 * gateway (see `vite.config.ts`).
 */
import type { AuditEvent, PendingApproval, Policy } from '@honmoon/policy'

export interface PolicyResponse {
  yaml: string
  parsed: Policy
}

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(path)
  if (!res.ok) {
    throw new Error(`${path} → ${res.status} ${res.statusText}`)
  }
  return res.json() as Promise<T>
}

async function post(path: string): Promise<Response> {
  const res = await fetch(path, { method: 'POST' })
  if (!res.ok) {
    throw new Error(`${path} → ${res.status} ${res.statusText}`)
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
