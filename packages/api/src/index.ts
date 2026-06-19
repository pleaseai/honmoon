/**
 * @honmoon/api — management & audit API server.
 *
 * Serves the audit log, approval queue, and policy endpoints consumed by the
 * dashboard. Runs on Bun's native HTTP server.
 */

const port = Number(process.env.HONMOON_API_PORT ?? 8443)

const server = Bun.serve({
  port,
  fetch(req) {
    const url = new URL(req.url)
    if (url.pathname === '/healthz') {
      return Response.json({ status: 'ok' })
    }
    // TODO: /api/audit, /api/approvals, /api/policy
    return new Response('Not found', { status: 404 })
  },
})

console.log(`honmoon api listening on http://localhost:${server.port}`)
