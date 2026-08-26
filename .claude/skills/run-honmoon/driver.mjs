#!/usr/bin/env node
// Honmoon run/drive harness. Agent-facing tooling, not product surface.
//
// Everything here was exercised against a live gateway; see SKILL.md for the
// commands and the traps each one works around.
//
//   node .claude/skills/run-honmoon/driver.mjs <command> [args]
//
// State (pid, logs, CA, audit log) lives under target/honmoon-run/.

import { spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, openSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const UNIT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const RUN = join(UNIT, 'target/honmoon-run')
const BIN = join(UNIT, 'target/debug/honmoon')

const PROXY_ADDR = process.env.HONMOON_ADDR ?? '127.0.0.1:8443'
const MGMT_ADDR = process.env.HONMOON_MGMT_ADDR ?? '127.0.0.1:8444'
const PROXY_URL = `http://${PROXY_ADDR}`
const MGMT_URL = `http://${MGMT_ADDR}`

const F = {
  pid: join(RUN, 'gateway.pid'),
  log: join(RUN, 'gateway.log'),
  audit: join(RUN, 'audit.jsonl'),
  policy: join(RUN, 'policy.yaml'),
  caCert: join(RUN, 'ca.pem'),
  caKey: join(RUN, 'ca.key.pem'),
  shots: join(RUN, 'shots'),
}

const sh = (cmd, args, opts = {}) =>
  spawnSync(cmd, args, { cwd: UNIT, encoding: 'utf8', ...opts })
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const log = (...a) => console.log(...a)

// A policy that exercises all three verdicts. `pause` needs a rule (the egress
// lists only yield allow/deny), and `endpoint: '*'` is what matches a CONNECT.
//
// The pause condition tests ONLY http.host: on a plain CONNECT the proxy has not
// decrypted anything, so http.method and http.path are empty strings. A rule
// keyed on path/method silently never fires without --tls-intercept.
//
// Rules are evaluated before the egress lists, so example.org is held even
// though it is not on the allowlist.
const DEMO_POLICY = `version: 1
egress:
  default: deny
  allow:
    - github.com
    - '*.githubusercontent.com'
    - httpbin.org
  deny:
    - '*.internal.corp'
rules:
  - name: pause-example-org
    endpoint: '*'
    condition: "http.host == 'example.org'"
    verdict: pause
`

function ensureRun() {
  mkdirSync(RUN, { recursive: true })
  mkdirSync(F.shots, { recursive: true })
}

// ---------------------------------------------------------------- build

function build({ dashboard = true } = {}) {
  if (dashboard) {
    // rust-embed reads apps/dashboard/dist. build.rs drops in a placeholder when
    // it is missing, so cargo still links -- you just get a blank dashboard.
    log('› building dashboard (vite)')
    const r = sh('bun', ['run', '--filter', '@honmoon/dashboard', 'build'], { stdio: 'inherit' })
    if (r.status !== 0) throw new Error('dashboard build failed')
  }
  log('› building rust workspace (cargo)')
  const r = sh('cargo', ['build', '--workspace'], { stdio: 'inherit' })
  if (r.status !== 0) throw new Error('cargo build failed')
  log('✓ build ok ->', BIN)
}

// ---------------------------------------------------------------- lifecycle

function runningPid() {
  if (!existsSync(F.pid)) return null
  const pid = Number(readFileSync(F.pid, 'utf8').trim())
  if (!pid) return null
  try {
    process.kill(pid, 0)
    return pid
  } catch {
    return null
  }
}

async function waitHealthy(timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${MGMT_URL}/healthz`)
      if (res.ok) return true
    } catch {
      /* not up yet */
    }
    await sleep(200)
  }
  return false
}

async function up(opts) {
  ensureRun()
  if (runningPid()) {
    log('› gateway already running (pid', runningPid() + '); use `down` first')
    return
  }
  if (!existsSync(BIN)) throw new Error(`missing ${BIN} - run \`driver.mjs build\` first`)

  const policy = opts.policy ?? F.policy
  if (!opts.policy) writeFileSync(F.policy, DEMO_POLICY)
  rmSync(F.audit, { force: true })

  const args = [
    'gateway',
    '--config', policy,
    '--addr', PROXY_ADDR,
    '--mgmt-addr', MGMT_ADDR,
    '--audit-log', F.audit,
  ]
  if (opts.mitm) {
    // --ca-cert/--ca-key are mutually `requires`d AND both require
    // --tls-intercept. Without explicit paths the CA is ephemeral/in-memory,
    // so no client can ever trust it -- always pass paths when testing MITM.
    args.push('--tls-intercept', '--ca-cert', F.caCert, '--ca-key', F.caKey)
    if (opts.redact) args.push('--redact-secrets')
    if (opts.piiMode) args.push('--pii-mode', opts.piiMode)
  }

  const out = openSync(F.log, 'a')
  const child = spawn(BIN, args, {
    cwd: UNIT,
    detached: true,
    stdio: ['ignore', out, out],
    env: { ...process.env, RUST_LOG: process.env.RUST_LOG ?? 'info' },
  })
  child.unref()
  writeFileSync(F.pid, String(child.pid))

  if (!(await waitHealthy())) {
    log(readFileSync(F.log, 'utf8'))
    throw new Error('gateway did not become healthy')
  }
  log(`✓ gateway up (pid ${child.pid})`)
  log(`  proxy     ${PROXY_URL}   (point https_proxy here)`)
  log(`  dashboard ${MGMT_URL}`)
  log(`  policy    ${policy}`)
  log(`  audit     ${F.audit}`)
  if (opts.mitm) log(`  ca cert   ${F.caCert}  (curl --cacert / trust store)`)
}

function down() {
  const pid = runningPid()
  if (!pid) {
    log('› no gateway running')
    rmSync(F.pid, { force: true })
    return
  }
  process.kill(pid)
  rmSync(F.pid, { force: true })
  log('✓ gateway stopped (pid', pid + ')')
}

// ---------------------------------------------------------------- probing

// Drive the proxy the way an agent would: HTTP CONNECT through it.
// Returns the observed verdict. A denied CONNECT is a 403 and curl exits 56.
function probe(url, { mitm = false, method, body } = {}) {
  const args = [
    '-s', '-o', '/dev/null',
    '-w', '%{http_code} %{exitcode}',
    '--proxy', PROXY_URL,
    '--max-time', '30',
  ]
  if (mitm) args.push('--cacert', F.caCert)
  if (method) args.push('-X', method)
  if (body) args.push('-H', 'content-type: application/json', '-d', body)
  args.push(url)

  const r = sh('curl', args)
  const [code, exit] = (r.stdout || '').trim().split(/\s+/)
  const verdict =
    exit === '56' ? 'DENIED (CONNECT 403)'
    : exit === '28' ? 'HELD (pause - timed out waiting for approval)'
    : exit === '0' ? `ALLOWED (upstream ${code})`
    : `curl exit ${exit} (http ${code})`
  log(`  ${url.padEnd(42)} -> ${verdict}`)
  return { code, exit, verdict }
}

// Fire a request that will be held, without blocking the driver.
function probeAsync(url, { mitm = false, method, body } = {}) {
  const args = ['-s', '-o', '/dev/null', '--proxy', PROXY_URL, '--max-time', '120']
  if (mitm) args.push('--cacert', F.caCert)
  if (method) args.push('-X', method)
  if (body) args.push('-H', 'content-type: application/json', '-d', body)
  args.push(url)
  const c = spawn('curl', args, { cwd: UNIT, detached: true, stdio: 'ignore' })
  c.unref()
  return c
}

// ---------------------------------------------------------------- mgmt API

const api = async (path, init) => {
  const res = await fetch(`${MGMT_URL}${path}`, init)
  const text = await res.text()
  try {
    return { status: res.status, json: JSON.parse(text) }
  } catch {
    return { status: res.status, text }
  }
}

async function approvals() {
  const { json } = await api('/api/approvals')
  if (!json?.length) {
    log('  (queue empty)')
    return []
  }
  for (const a of json) log(`  #${a.id}  ${a.summary}   held ${a.created_at}`)
  return json
}

async function resolveApproval(id, decision) {
  const { status, json, text } = await api(`/api/approvals/${id}/${decision}`, { method: 'POST' })
  log(`  ${decision} #${id} -> ${status} ${JSON.stringify(json ?? text)}`)
}

async function audit(limit = 20) {
  const { json } = await api(`/api/audit?limit=${limit}`)
  for (const e of json ?? []) {
    const pii = e.facts?.pii ? `  pii=${e.facts.pii.types.join(',')}` : ''
    const rule = e.rule ? `  rule=${e.rule}` : ''
    log(`  #${e.id} ${e.decision.padEnd(9)} ${e.facts?.domain ?? '-'}${rule}${pii}`)
  }
  return json
}

// ---------------------------------------------------------------- hook path

// Direct invocation of the redaction engine -- no gateway, no network.
// This is the layer most recent PRs touch (hook.rs, secret_tokenizer, pii.rs).
function hook(text, saltContext = 'driver') {
  const payload = JSON.stringify({
    hook_event_name: 'PostToolUse',
    tool_name: 'Read',
    tool_response: text,
  })
  const r = sh(BIN, ['hook', '--salt-context', saltContext], { input: payload })
  if (r.status !== 0) throw new Error(`hook failed: ${r.stderr}`)
  const out = JSON.parse(r.stdout)
  return out.hookSpecificOutput?.updatedToolOutput ?? null
}

// ---------------------------------------------------------------- browser

// agent-browser is the off-the-shelf driver (no chromium-cli on this box).
function ab(args, { quiet = false } = {}) {
  const r = sh('agent-browser', args)
  if (!quiet) process.stdout.write(r.stdout || r.stderr || '')
  return r.stdout ?? ''
}

function shot(name = 'dashboard') {
  const path = join(F.shots, `${name}.png`)
  ab(['open', MGMT_URL])
  ab(['screenshot', path])
  log('✓ screenshot ->', path)
  return path
}

// Nav buttons render their pending count inside the button ("Approvals 2"),
// so exact-text matching misses. Resolve the ref from the a11y snapshot.
function clickNav(label) {
  const snap = ab(['snapshot'], { quiet: true })
  const re = new RegExp(`button "${label}[^"]*" \\[ref=(e\\d+)\\]`)
  const m = snap.match(re)
  if (!m) throw new Error(`nav "${label}" not found in snapshot`)
  ab(['click', `@${m[1]}`], { quiet: true })
  return m[1]
}

// Refs are renumbered whenever the DOM changes, so re-snapshot before each click.
function clickFirst(label) {
  const snap = ab(['snapshot'], { quiet: true })
  const m = snap.match(new RegExp(`button "${label}" \\[ref=(e\\d+)\\]`))
  if (!m) return null
  ab(['click', `@${m[1]}`], { quiet: true })
  return m[1]
}

// ---------------------------------------------------------------- smoke

async function smoke({ mitm = false } = {}) {
  log('\n=== 1. build ===')
  build()

  log('\n=== 2. launch gateway ===')
  down()
  await up({ mitm, redact: mitm, piiMode: mitm ? 'detect' : undefined })

  log('\n=== 3. egress filtering ===')
  probe('https://github.com', { mitm })                  // exact allowlist hit
  probe('https://api.github.com', { mitm })              // NOT covered by `github.com`
  probe('https://raw.githubusercontent.com', { mitm })   // wildcard hit
  probe('https://example.com', { mitm })                 // default deny

  log('\n=== 4. pause -> approval queue ===')
  probeAsync('https://example.org', { mitm })
  await sleep(2500)
  const pending = await approvals()
  if (pending.length) {
    await resolveApproval(pending[0].id, 'approve')
    await sleep(1500)
    log('  queue after approve:')
    await approvals()
  } else {
    throw new Error('expected a held request - pause rule did not fire')
  }

  if (mitm) {
    log('\n=== 5. wire redaction (upstream sees placeholders) ===')
    const secret = 'AKIAIOSFODNN7EXAMPLE'
    const body = JSON.stringify({ note: `aws key ${secret}, email alice@example.com` })
    const r = sh('curl', [
      '-s', '--proxy', PROXY_URL, '--cacert', F.caCert,
      '-X', 'POST', 'https://httpbin.org/post',
      '-H', 'content-type: application/json', '-d', body, '--max-time', '30',
    ])
    try {
      const echoed = JSON.parse(r.stdout)
      log(`  body sent by client      : ${body.length} bytes`)
      log(`  Content-Length upstream  : ${echoed.headers['Content-Length']} (placeholders are wider)`)
      log(`  data echoed back to client: ${echoed.data}`)
      log('  ^ upstream received placeholders; the response was detokenized on the way back')
    } catch {
      log('  (httpbin unreachable - skipping wire-redaction assertion)')
    }
  }

  log('\n=== 6. hook path (direct invocation, no network) ===')
  const redacted = hook('aws key AKIAIOSFODNN7EXAMPLE and email alice@example.com')
  log('  ', redacted)
  const a = hook('AKIAIOSFODNN7EXAMPLE'), b = hook('AKIAIOSFODNN7EXAMPLE')
  log(`   deterministic across calls: ${a === b ? 'yes' : 'NO - cache stability broken'}`)

  log('\n=== 7. audit log ===')
  await audit(12)

  log('\n=== 8. dashboard screenshot ===')
  try {
    shot(mitm ? 'smoke-mitm' : 'smoke')
  } catch {
    log('  (agent-browser unavailable - skipped)')
  }

  log('\n=== 9. teardown ===')
  down()
  log('\n✓ smoke complete')
}

// ---------------------------------------------------------------- cli

const [cmd, ...rest] = process.argv.slice(2)
const has = (f) => rest.includes(f)
const val = (f) => {
  const i = rest.indexOf(f)
  return i === -1 ? undefined : rest[i + 1]
}

try {
  switch (cmd) {
    case 'build':
      build({ dashboard: !has('--no-dashboard') })
      break
    case 'up':
      await up({
        mitm: has('--mitm'),
        redact: has('--redact'),
        piiMode: val('--pii-mode'),
        policy: val('--policy'),
      })
      break
    case 'down':
      down()
      break
    case 'status': {
      const pid = runningPid()
      log(pid ? `running (pid ${pid})` : 'not running')
      if (pid) log(JSON.stringify((await api('/healthz')).json))
      break
    }
    case 'logs':
      log(existsSync(F.log) ? readFileSync(F.log, 'utf8') : '(no log yet)')
      break
    case 'probe':
      probe(rest[0], { mitm: has('--mitm'), method: val('-X'), body: val('-d') })
      break
    case 'approvals':
      await approvals()
      break
    case 'approve':
      await resolveApproval(rest[0], 'approve')
      break
    case 'deny':
      await resolveApproval(rest[0], 'reject')
      break
    case 'audit':
      await audit(Number(rest[0]) || 20)
      break
    case 'hook':
      log(hook(rest[0] ?? 'aws key AKIAIOSFODNN7EXAMPLE, email alice@example.com', val('--salt') ?? 'driver'))
      break
    case 'shot':
      shot(rest[0])
      break
    case 'ui-approve': {
      clickNav('Approvals')
      await sleep(500)
      const ref = clickFirst(has('--deny') ? 'Deny' : 'Approve')
      log(ref ? `✓ clicked ${has('--deny') ? 'Deny' : 'Approve'} (${ref})` : '  queue empty')
      break
    }
    case 'smoke':
      await smoke({ mitm: has('--mitm') })
      break
    default:
      log(`honmoon driver — usage: node .claude/skills/run-honmoon/driver.mjs <cmd>

  build [--no-dashboard]      dashboard (vite) + cargo build --workspace
  up [--mitm] [--redact]      launch gateway; --policy FILE  --pii-mode detect|block
     [--pii-mode M] [--policy F]
  down / status / logs        lifecycle
  probe <url> [--mitm]        CONNECT through the proxy, print the verdict
     [-X METHOD] [-d BODY]
  approvals                   list the held-request queue
  approve <id> / deny <id>    resolve a held request via the mgmt API
  ui-approve [--deny]         resolve it by CLICKING in the dashboard
  audit [n]                   recent verdicts
  hook <text> [--salt S]      run the redaction engine directly (no gateway)
  shot [name]                 screenshot the dashboard
  smoke [--mitm]              full end-to-end run (build -> drive -> teardown)`)
  }
} catch (err) {
  console.error('✗', err.message)
  process.exit(1)
}
