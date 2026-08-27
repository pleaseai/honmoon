/**
 * Honmoon dashboard demo shim.
 *
 * Loaded as a classic <script> ahead of the app bundle by `demo/build.ts`, which
 * injects it into a copy of the *stock* production build. The app source knows
 * nothing about the demo: this file patches `window.fetch` so the management-API
 * calls in `src/api.ts` resolve against in-memory fixtures instead of a gateway.
 *
 * Plain browser JS on purpose — no imports, no bundler, no framework. Everything
 * here is synthetic and resets on reload.
 */
(() => {
  const originalFetch = window.fetch.bind(window)

  /** Demo start; the seed history and the scripted timeline both hang off this. */
  const T0 = Date.now()
  /** Matches the management API's audit retention. */
  const MAX_EVENTS = 200
  /** Artificial round-trip, so the approve/deny busy state is actually visible. */
  const LATENCY_MS = 140

  const at = offsetMs => new Date(T0 + offsetMs).toISOString()
  const ago = seconds => at(-seconds * 1000)

  // ── Policy ────────────────────────────────────────────────────────────────
  // Mirrors `policies/agent.yaml`. The timeline below fires these exact rules,
  // so the audit log visibly corresponds to what the Policies tab shows.

  const POLICY_YAML = [
    '# Honmoon demo — synthetic policy. No gateway is attached.',
    'version: 1',
    '',
    'egress:',
    '  default: deny',
    '  allow:',
    '    - github.com',
    '    - \'*.githubusercontent.com\'',
    '    - api.anthropic.com',
    '    - registry.npmjs.org',
    '  deny:',
    '    - \'*.internal.corp\'',
    '',
    'rules:',
    '  - name: k8s-no-secret-delete',
    '    endpoint: k8s-prod',
    '    condition: "k8s.resource == \'secrets\' && k8s.verb == \'delete\'"',
    '    verdict: deny',
    '',
    '  - name: sql-no-prod-drop',
    '    endpoint: postgres-prod',
    '    condition: "sql.verb == \'DROP\' || sql.verb == \'TRUNCATE\'"',
    '    verdict: pause',
    '',
    '  - name: http-block-large-upload',
    '    endpoint: \'*\'',
    '    condition: "http.method == \'POST\' && http.body_size > 10485760"',
    '    verdict: deny',
    '',
    '  # Allow rules come last: the first matching rule wins, so the deny/pause',
    '  # rules above always get to see a request before these do.',
    '  - name: sql-allow-reads',
    '    endpoint: postgres-prod',
    '    condition: "sql.verb == \'SELECT\' || sql.verb == \'INSERT\'"',
    '    verdict: allow',
    '',
    '  - name: k8s-allow-reads',
    '    endpoint: k8s-prod',
    '    condition: "k8s.verb == \'get\' || k8s.verb == \'list\'"',
    '    verdict: allow',
    '',
  ].join('\n')

  const POLICY_PARSED = {
    version: 1,
    egress: {
      default: 'deny',
      allow: ['github.com', '*.githubusercontent.com', 'api.anthropic.com', 'registry.npmjs.org'],
      deny: ['*.internal.corp'],
    },
    rules: [
      {
        name: 'k8s-no-secret-delete',
        endpoint: 'k8s-prod',
        condition: 'k8s.resource == \'secrets\' && k8s.verb == \'delete\'',
        verdict: 'deny',
      },
      {
        name: 'sql-no-prod-drop',
        endpoint: 'postgres-prod',
        condition: 'sql.verb == \'DROP\' || sql.verb == \'TRUNCATE\'',
        verdict: 'pause',
      },
      {
        name: 'http-block-large-upload',
        endpoint: '*',
        condition: 'http.method == \'POST\' && http.body_size > 10485760',
        verdict: 'deny',
      },
      // Allow rules come last: the first matching rule wins, so the deny/pause
      // rules above always get to see a request before these do.
      {
        name: 'sql-allow-reads',
        endpoint: 'postgres-prod',
        condition: 'sql.verb == \'SELECT\' || sql.verb == \'INSERT\'',
        verdict: 'allow',
      },
      {
        name: 'k8s-allow-reads',
        endpoint: 'k8s-prod',
        condition: 'k8s.verb == \'get\' || k8s.verb == \'list\'',
        verdict: 'allow',
      },
    ],
  }

  // ── Seed history ──────────────────────────────────────────────────────────
  // Oldest first here; `events` is kept newest-first, like `GET /api/audit`.
  // Covers every Decision value and every facts shape (http / sql / k8s / domain).
  // `t` is seconds before load, so the log always reads as recent.

  const SEED = [
    { t: 1840, decision: 'allowed', verdict: 'allow', facts: { domain: 'github.com' } },
    {
      t: 1712,
      decision: 'allowed',
      verdict: 'allow',
      facts: {
        endpoint: 'anthropic',
        domain: 'api.anthropic.com',
        http: { method: 'POST', host: 'api.anthropic.com', path: '/v1/messages', body_size: 4211 },
      },
    },
    {
      t: 1604,
      decision: 'allowed',
      verdict: 'allow',
      rule: 'sql-allow-reads',
      facts: { endpoint: 'postgres-prod', sql: { verb: 'SELECT', table: 'orders' } },
    },
    { t: 1497, decision: 'denied', verdict: 'deny', facts: { domain: 'metrics.internal.corp' } },
    {
      t: 1388,
      decision: 'allowed',
      verdict: 'allow',
      rule: 'k8s-allow-reads',
      facts: { endpoint: 'k8s-prod', k8s: { verb: 'get', resource: 'pods', namespace: 'checkout' } },
    },
    {
      t: 1265,
      decision: 'denied',
      verdict: 'deny',
      rule: 'k8s-no-secret-delete',
      facts: {
        endpoint: 'k8s-prod',
        k8s: { verb: 'delete', resource: 'secrets', namespace: 'payments' },
      },
    },
    {
      t: 1150,
      decision: 'allowed',
      verdict: 'allow',
      facts: { domain: 'objects.githubusercontent.com' },
    },
    {
      t: 1032,
      decision: 'paused',
      verdict: 'pause',
      rule: 'sql-no-prod-drop',
      approval_id: 101,
      facts: { endpoint: 'postgres-prod', sql: { verb: 'TRUNCATE', table: 'sessions' } },
    },
    {
      t: 968,
      decision: 'approved',
      verdict: 'pause',
      rule: 'sql-no-prod-drop',
      approval_id: 101,
      facts: { endpoint: 'postgres-prod', sql: { verb: 'TRUNCATE', table: 'sessions' } },
    },
    {
      t: 861,
      decision: 'denied',
      verdict: 'deny',
      rule: 'http-block-large-upload',
      facts: {
        endpoint: 'artifacts',
        domain: 'uploads.example.com',
        http: {
          method: 'POST',
          host: 'uploads.example.com',
          path: '/v1/blobs',
          body_size: 27340288,
        },
      },
    },
    {
      t: 744,
      decision: 'allowed',
      verdict: 'allow',
      facts: {
        endpoint: 'npm',
        domain: 'registry.npmjs.org',
        http: { method: 'GET', host: 'registry.npmjs.org', path: '/react', body_size: 0 },
      },
    },
    {
      t: 629,
      decision: 'paused',
      verdict: 'pause',
      rule: 'sql-no-prod-drop',
      approval_id: 102,
      facts: { endpoint: 'postgres-prod', sql: { verb: 'DROP', table: 'legacy_invoices' } },
    },
    {
      t: 570,
      decision: 'rejected',
      verdict: 'pause',
      rule: 'sql-no-prod-drop',
      approval_id: 102,
      facts: { endpoint: 'postgres-prod', sql: { verb: 'DROP', table: 'legacy_invoices' } },
    },
    { t: 468, decision: 'denied', verdict: 'deny', facts: { domain: 'paste.internal.corp' } },
    {
      t: 355,
      decision: 'allowed',
      verdict: 'allow',
      rule: 'sql-allow-reads',
      facts: { endpoint: 'postgres-prod', sql: { verb: 'INSERT', table: 'audit_trail' } },
    },
    {
      t: 244,
      decision: 'allowed',
      verdict: 'allow',
      facts: {
        endpoint: 'github',
        domain: 'github.com',
        http: {
          method: 'GET',
          host: 'github.com',
          path: '/honmoon/honmoon.git/info/refs',
          body_size: 0,
        },
      },
    },
    {
      t: 138,
      decision: 'allowed',
      verdict: 'allow',
      rule: 'k8s-allow-reads',
      facts: {
        endpoint: 'k8s-prod',
        k8s: { verb: 'list', resource: 'configmaps', namespace: 'checkout' },
      },
    },
    {
      t: 52,
      decision: 'allowed',
      verdict: 'allow',
      facts: {
        endpoint: 'anthropic',
        domain: 'api.anthropic.com',
        http: { method: 'POST', host: 'api.anthropic.com', path: '/v1/messages', body_size: 9822 },
      },
    },
  ]

  // ── Mutable state ─────────────────────────────────────────────────────────

  /** Newest first. */
  const events = []
  const approvals = []
  /** Ids the visitor resolved themselves — excluded from the auto-resolve beat. */
  const resolvedByVisitor = new Set()
  let nextEventId = 1
  let nextApprovalId = 201

  for (const seed of SEED) {
    events.unshift({
      id: nextEventId++,
      timestamp: ago(seed.t),
      decision: seed.decision,
      verdict: seed.verdict,
      rule: seed.rule,
      facts: seed.facts,
      approval_id: seed.approval_id,
    })
  }

  function record(event) {
    events.unshift({ ...event, id: nextEventId++ })
    if (events.length > MAX_EVENTS) {
      events.length = MAX_EVENTS
    }
  }

  /** Hold a request for approval and log the matching `paused` event. */
  function hold(rule, facts, summary) {
    const approval = {
      id: nextApprovalId++,
      created_at: new Date().toISOString(),
      endpoint: facts.endpoint,
      rule,
      summary,
    }
    approvals.push(approval)
    record({
      timestamp: approval.created_at,
      decision: 'paused',
      verdict: 'pause',
      rule,
      facts,
      approval_id: approval.id,
    })
    return approval.id
  }

  /** Facts of the `paused` event an approval came from, so its resolution matches. */
  function heldFacts(id) {
    const paused = events.find(e => e.approval_id === id && e.decision === 'paused')
    return paused ? paused.facts : {}
  }

  /** Resolve a held request; false if the id is not pending. */
  function resolveApproval(id, decision) {
    const index = approvals.findIndex(a => a.id === id)
    if (index === -1) {
      return false
    }
    const [held] = approvals.splice(index, 1)
    record({
      timestamp: new Date().toISOString(),
      decision,
      // The policy verdict that drove the event, not its outcome: a held
      // request matched a `pause` rule, and `honmoon-core::audit` keeps `pause`
      // on the resolution too (`decision` carries approved/rejected).
      verdict: 'pause',
      rule: held.rule,
      facts: heldFacts(id),
      approval_id: id,
    })
    return true
  }

  // ── Scripted timeline ─────────────────────────────────────────────────────
  // Absolute offsets from load, so a cold visitor watches the full
  // deny → pause → resolve loop unattended. Every timer is owned here, once, at
  // load: the dashboard polls from four places and must not spawn its own.

  const scripted = { first: null, second: null }

  setTimeout(() => {
    record({
      timestamp: new Date().toISOString(),
      decision: 'denied',
      verdict: 'deny',
      rule: 'k8s-no-secret-delete',
      facts: {
        endpoint: 'k8s-prod',
        k8s: { verb: 'delete', resource: 'secrets', namespace: 'checkout' },
      },
    })
  }, 4000)

  setTimeout(() => {
    scripted.first = hold(
      'sql-no-prod-drop',
      { endpoint: 'postgres-prod', sql: { verb: 'DROP', table: 'stale_exports' } },
      'DROP TABLE stale_exports on postgres-prod',
    )
  }, 8000)

  setTimeout(() => {
    scripted.second = hold(
      'sql-no-prod-drop',
      { endpoint: 'postgres-prod', sql: { verb: 'TRUNCATE', table: 'sessions' } },
      'TRUNCATE sessions on postgres-prod',
    )
  }, 14000)

  setTimeout(() => {
    if (scripted.first !== null && !resolvedByVisitor.has(scripted.first)) {
      resolveApproval(scripted.first, 'approved')
    }
    if (scripted.second !== null && !resolvedByVisitor.has(scripted.second)) {
      resolveApproval(scripted.second, 'rejected')
    }
  }, 22000)

  // Slower background trickle, so the log keeps moving after the scripted beats.
  const TRICKLE = [
    {
      decision: 'allowed',
      verdict: 'allow',
      facts: {
        endpoint: 'anthropic',
        domain: 'api.anthropic.com',
        http: { method: 'POST', host: 'api.anthropic.com', path: '/v1/messages', body_size: 6104 },
      },
    },
    {
      decision: 'allowed',
      verdict: 'allow',
      rule: 'sql-allow-reads',
      facts: { endpoint: 'postgres-prod', sql: { verb: 'SELECT', table: 'orders' } },
    },
    { decision: 'denied', verdict: 'deny', facts: { domain: 'metrics.internal.corp' } },
    {
      decision: 'allowed',
      verdict: 'allow',
      rule: 'k8s-allow-reads',
      facts: { endpoint: 'k8s-prod', k8s: { verb: 'get', resource: 'pods', namespace: 'search' } },
    },
    { decision: 'allowed', verdict: 'allow', facts: { domain: 'objects.githubusercontent.com' } },
    {
      decision: 'denied',
      verdict: 'deny',
      rule: 'http-block-large-upload',
      facts: {
        endpoint: 'artifacts',
        domain: 'uploads.example.com',
        http: {
          method: 'POST',
          host: 'uploads.example.com',
          path: '/v1/blobs',
          body_size: 41943040,
        },
      },
    },
    {
      decision: 'allowed',
      verdict: 'allow',
      facts: {
        endpoint: 'npm',
        domain: 'registry.npmjs.org',
        http: { method: 'GET', host: 'registry.npmjs.org', path: '/vite', body_size: 0 },
      },
    },
    {
      decision: 'allowed',
      verdict: 'allow',
      rule: 'k8s-allow-reads',
      facts: {
        endpoint: 'k8s-prod',
        k8s: { verb: 'list', resource: 'configmaps', namespace: 'payments' },
      },
    },
  ]

  let trickleCursor = 0
  setInterval(() => {
    const template = TRICKLE[trickleCursor++ % TRICKLE.length]
    record({ ...template, timestamp: new Date().toISOString() })
  }, 6500)

  // ── fetch shim ────────────────────────────────────────────────────────────

  /** Resolve after an artificial round-trip, so in-flight UI states are visible. */
  const settle = response => new Promise(resolve => setTimeout(resolve, LATENCY_MS, response))

  const json = body => settle(
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }),
  )

  const APPROVAL_ACTION = /^\/api\/approvals\/(\d+)\/(approve|reject)$/

  /** Returns a Response promise for a handled route, or null to fall through. */
  function handle(url, method) {
    if (method === 'POST') {
      const action = APPROVAL_ACTION.exec(url.pathname)
      if (!action) {
        return null
      }
      const id = Number(action[1])
      if (!resolveApproval(id, action[2] === 'approve' ? 'approved' : 'rejected')) {
        return settle(new Response('no such pending approval', { status: 404, statusText: 'Not Found' }))
      }
      resolvedByVisitor.add(id)
      return json({ ok: true })
    }
    if (method !== 'GET') {
      return null
    }
    if (url.pathname === '/api/audit') {
      return json(events.slice(0, Number(url.searchParams.get('limit')) || MAX_EVENTS))
    }
    if (url.pathname === '/api/approvals') {
      return json([...approvals])
    }
    if (url.pathname === '/api/policy') {
      return json({ yaml: POLICY_YAML, parsed: POLICY_PARSED })
    }
    return null
  }

  window.fetch = (input, init) => {
    const raw = typeof input === 'string' ? input : (input && input.url) || String(input)
    const method = (init && init.method) || (input && input.method) || 'GET'
    let url
    try {
      url = new URL(raw, window.location.href)
    }
    catch {
      return originalFetch(input, init)
    }
    if (url.origin !== window.location.origin) {
      return originalFetch(input, init)
    }
    return handle(url, method.toUpperCase()) || originalFetch(input, init)
  }

  // ── Demo badge ────────────────────────────────────────────────────────────
  // The dashboard must never present a synthetic surface as functional.

  function mountBadge() {
    const badge = document.createElement('div')
    badge.textContent = 'demo · synthetic data, no gateway — resets on reload'
    badge.style.cssText = [
      'position:fixed',
      'right:12px',
      'bottom:12px',
      'z-index:2147483647',
      'padding:5px 10px',
      'border-radius:6px',
      'border:1px solid rgba(180,83,9,.45)',
      'background:rgba(251,191,36,.92)',
      'color:#451a03',
      'font:500 11px/1.4 ui-sans-serif,system-ui,sans-serif',
      'pointer-events:none',
      'box-shadow:0 1px 3px rgba(0,0,0,.2)',
    ].join(';')
    document.body.appendChild(badge)
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', mountBadge)
  }
  else {
    mountBadge()
  }
})()
