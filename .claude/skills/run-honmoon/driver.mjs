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
  } catch {
    return null
  }
  // pids are recycled and gateway.pid outlives crashes/reboots, so "some process
  // holds this pid" is not "our gateway holds this pid" -- confirm before `down()`
  // signals it, or we eventually SIGTERM an unrelated process. Match the binary
  // path we actually spawn: a bare "honmoon" substring also matches every
  // unrelated process launched from a checkout whose directory is named honmoon.
  const ps = sh('ps', ['-o', 'command=', '-p', String(pid)])
  if (ps.status === 0 && !(ps.stdout ?? '').includes(BIN)) return null
  return pid
}

const childAlive = (child) => child.exitCode === null && child.signalCode === null

// Is *something* already answering the management port? Used as a pre-flight:
// a foreign listener there makes every later health check meaningless.
async function mgmtAnswers() {
  try {
    return (await fetch(`${MGMT_URL}/healthz`)).ok
  } catch {
    return false
  }
}

// Healthy means "OUR child is serving", not "the port answers". Without the
// liveness check a gateway that failed to bind (port already held by an
// unrelated run) exits immediately while the *other* process keeps answering
// /healthz -- `up` then reports success for a pid that is already dead.
async function waitHealthy(child, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (!childAlive(child)) return false
    if (await mgmtAnswers()) {
      // Settle: a bind failure can land just after the foreign /healthz answered.
      await sleep(300)
      return childAlive(child)
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
  // Refuse to launch into an occupied management port. Beyond the doomed bind,
  // the setup below rewrites policy.yaml and unlinks audit.jsonl -- doing that
  // while another gateway (e.g. one started by hand) is still using them
  // destroys its audit log for a run that was never going to start.
  if (await mgmtAnswers()) {
    throw new Error(
      `${MGMT_URL} is already serving /healthz - another gateway is running. ` +
        'Stop it (`driver.mjs down`, or kill it) or set HONMOON_MGMT_ADDR/HONMOON_ADDR.',
    )
  }

  // Validate the flag combinations BEFORE touching any on-disk state. These
  // throws used to sit after the policy write and the audit unlink, so an
  // `up --pii-mode block` that never started a gateway still destroyed the
  // previous run's audit log on its way to being rejected.
  //
  // The gateway rejects --redact-secrets and `--pii-mode block` without
  // --tls-intercept. Say so instead of dropping the flag on the floor: silently
  // ignoring it starts a gateway with semantics the caller did not ask for
  // (`up --pii-mode block` would quietly run in `detect`).
  if (opts.redact && !opts.mitm) {
    throw new Error('--redact requires --mitm (--redact-secrets requires --tls-intercept)')
  }
  if (opts.piiMode === 'block' && !opts.mitm) {
    throw new Error('--pii-mode block requires --mitm (--tls-intercept)')
  }

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
  }
  if (opts.redact) args.push('--redact-secrets')
  if (opts.piiMode) args.push('--pii-mode', opts.piiMode)

  // Truncate rather than accumulate: the launch-failure path below dumps this
  // whole file to explain one failed start, and `logs` shows it verbatim --
  // carrying previous runs' output into either just buries the line that
  // matters. Matches the audit log, which `up` already resets.
  //
  // Truncate separately, then open O_APPEND rather than passing 'w': a plain
  // 'w' handle carries its own file offset, so if two `up` calls slip through
  // the port preflight together their children overwrite each other's records
  // instead of interleaving -- and the one that loses the bind race is exactly
  // the one whose diagnostic we need.
  writeFileSync(F.log, '')
  const out = openSync(F.log, 'a')
  const child = spawn(BIN, args, {
    cwd: UNIT,
    detached: true,
    stdio: ['ignore', out, out],
    env: { ...process.env, RUST_LOG: process.env.RUST_LOG ?? 'info' },
  })
  child.unref()
  writeFileSync(F.pid, String(child.pid))

  if (!(await waitHealthy(child))) {
    log(readFileSync(F.log, 'utf8'))
    // Never leave the process we started behind: an unreferenced gateway keeps
    // holding 8443/8444 and every later `up` then fails the same way.
    if (childAlive(child)) {
      try {
        process.kill(child.pid, 'SIGKILL')
      } catch {
        /* already gone */
      }
    }
    rmSync(F.pid, { force: true })
    throw new Error('gateway did not become healthy')
  }
  log(`✓ gateway up (pid ${child.pid})`)
  log(`  proxy     ${PROXY_URL}   (point https_proxy here)`)
  log(`  dashboard ${MGMT_URL}`)
  log(`  policy    ${policy}`)
  log(`  audit     ${F.audit}`)
  if (opts.mitm) log(`  ca cert   ${F.caCert}  (curl --cacert / trust store)`)
}

async function down() {
  const pid = runningPid()
  if (!pid) {
    log('› no gateway running')
    rmSync(F.pid, { force: true })
    return
  }
  // The gateway can exit between runningPid() and here (it is a separate
  // process, and a crash needs no cooperation from us), which makes SIGTERM
  // throw ESRCH and take the driver down with it. The SIGKILL path below
  // already guarded this; the first signal did not.
  try {
    process.kill(pid)
  } catch {
    /* already gone between the check and the signal */
  }
  // SIGTERM is asynchronous: `smoke` calls `down()` and then `up()` immediately,
  // and a gateway that has not finished dying still holds 8443/8444 -- the new
  // one then fails to bind and `up()` reports "did not become healthy".
  for (let i = 0; i < 100 && runningPid() === pid; i++) await sleep(100)
  if (runningPid() === pid) {
    log('  (SIGTERM ignored after 10s - sending SIGKILL)')
    try {
      process.kill(pid, 'SIGKILL')
    } catch {
      /* already gone */
    }
    await sleep(300)
  }
  rmSync(F.pid, { force: true })
  log('✓ gateway stopped (pid', pid + ')')
}

// ---------------------------------------------------------------- probing

// Drive the proxy the way an agent would: HTTP CONNECT through it.
// Returns the observed verdict. A denied CONNECT is a 403 and curl exits 56.
//
// Pass `expect: 'allow' | 'deny'` to assert the policy outcome. The two
// directions are not symmetric: a deny verdict is decided by the proxy alone,
// so anything else is a real regression, while an allow verdict still needs the
// upstream to be reachable -- so only a *policy* denial fails the run there, and
// an unreachable upstream is reported as the environmental noise it is.
function probe(url, { mitm = false, method, body, expect } = {}) {
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
  if (r.error) throw new Error(`curl could not be run: ${r.error.message}`)
  const [code, exit] = (r.stdout || '').trim().split(/\s+/)
  // No write-out at all means curl never reported a verdict (missing binary,
  // or a curl older than 7.75 that does not know %{exitcode}) -- reporting
  // `curl exit undefined` as if it were an observation hides that.
  if (exit === undefined) {
    throw new Error(
      `curl produced no write-out (exit ${r.status}): ${(r.stderr || '').trim() || 'no stderr'}`,
    )
  }
  const verdict =
    exit === '56' ? 'DENIED (CONNECT 403)'
    : exit === '28' ? 'HELD (pause - timed out waiting for approval)'
    : exit === '0' ? `ALLOWED (upstream ${code})`
    : `curl exit ${exit} (http ${code})`
  log(`  ${url.padEnd(42)} -> ${verdict}`)

  const denied = exit === '56'
  if (expect === 'deny' && !denied) {
    throw new Error(`${url}: policy was expected to DENY this host, got ${verdict}`)
  }
  if (expect === 'allow' && denied) {
    throw new Error(`${url}: policy DENIED a host the allowlist covers (${verdict})`)
  }
  if (expect === 'allow' && exit !== '0') {
    // Policy let it through; the upstream just did not answer. Not a regression.
    log('      (upstream unreachable - the policy allowed it, so not a policy regression)')
  }
  return { code, exit, verdict, denied }
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
  // An error payload parses as an object, not an array, and `{} ?? []` keeps
  // the object -- so a bare `for...of` would throw "is not iterable" and bury
  // the actual API error behind a TypeError.
  if (!Array.isArray(json)) {
    log(`  (audit API returned no list: ${JSON.stringify(json ?? null).slice(0, 200)})`)
    return []
  }
  for (const e of json) {
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
  if (r.error) throw new Error(`could not run ${BIN}: ${r.error.message} - \`driver.mjs build\` first?`)
  if (r.status !== 0) throw new Error(`hook failed (exit ${r.status}): ${r.stderr ?? ''}`)
  // `honmoon hook` writes NOTHING when the verdict is `{}` -- i.e. the payload
  // held nothing to redact. That is a normal outcome, so JSON.parse('') here
  // would turn "clean text" into `Unexpected end of JSON input`.
  const stdout = (r.stdout ?? '').trim()
  if (!stdout) return null
  const out = JSON.parse(stdout)
  return out.hookSpecificOutput?.updatedToolOutput ?? null
}

// ---------------------------------------------------------------- browser

// agent-browser is the off-the-shelf driver (no chromium-cli on this box).
function ab(args, { quiet = false } = {}) {
  const r = sh('agent-browser', args)
  // agent-browser exits non-zero on failure (and spawn sets `error` when it is
  // not installed). Ignoring both made `shot()` print "✓ screenshot -> path"
  // for a file that was never written.
  if (r.error) throw new Error(`agent-browser could not be run: ${r.error.message}`)
  if (r.status !== 0) {
    throw new Error(
      `agent-browser ${args[0]} failed (exit ${r.status}): ${(r.stderr || r.stdout || '').trim()}`,
    )
  }
  if (!quiet) process.stdout.write(r.stdout || r.stderr || '')
  return r.stdout ?? ''
}

function shot(name = 'dashboard') {
  // `shot` is reachable without ever having run `up` (e.g. against a
  // hand-started gateway), and agent-browser does not create the directory.
  ensureRun()
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
  await down()
  await up({ mitm, redact: mitm, piiMode: mitm ? 'detect' : undefined })

  // Everything past launch runs under a finally: a failed assertion used to
  // abort before step 9, leaving the gateway holding 8443/8444.
  try {
    await drive({ mitm })
  } finally {
    log('\n=== 9. teardown ===')
    await down()
  }
  log('\n✓ smoke complete')
}

async function drive({ mitm }) {
  log('\n=== 3. egress filtering ===')
  probe('https://github.com', { mitm, expect: 'allow' })                // exact allowlist hit
  probe('https://api.github.com', { mitm, expect: 'deny' })             // NOT covered by `github.com`
  probe('https://raw.githubusercontent.com', { mitm, expect: 'allow' }) // wildcard hit
  probe('https://example.com', { mitm, expect: 'deny' })                // default deny

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
    // Distinguish "the echo service is down" from "the proxy/redaction broke".
    // A blanket catch reported a 5xx from the gateway, a truncated body, or a
    // redaction regression as `httpbin unreachable` -- exactly the regressions
    // this step exists to surface.
    if (r.error || r.status !== 0) {
      log(`  (curl failed: ${r.error?.message ?? `exit ${r.status}`} - skipping wire-redaction assertion)`)
    } else {
      let echoed
      try {
        echoed = JSON.parse(r.stdout)
      } catch {
        log(`  (non-JSON response - skipping: ${(r.stdout || '').slice(0, 200).trim() || '<empty>'})`)
      }
      if (echoed) {
        const upstreamLen = echoed.headers?.['Content-Length']
        if (upstreamLen === undefined) {
          throw new Error(`httpbin echo carried no Content-Length header: ${r.stdout.slice(0, 200)}`)
        }
        log(`  body sent by client      : ${body.length} bytes`)
        log(`  Content-Length upstream  : ${upstreamLen} (placeholders are wider)`)
        log(`  data echoed back to client: ${echoed.data}`)
        if (Number(upstreamLen) <= body.length) {
          throw new Error(
            `upstream Content-Length ${upstreamLen} <= client body ${body.length} - nothing was tokenized on the wire`,
          )
        }
        log('  ^ upstream received placeholders; the response was detokenized on the way back')
      }
    }
  }

  log('\n=== 6. hook path (direct invocation, no network) ===')
  const redacted = hook('aws key AKIAIOSFODNN7EXAMPLE and email alice@example.com')
  if (redacted === null) throw new Error('hook returned no verdict - redaction did not fire')
  log('  ', redacted)
  const a = hook('AKIAIOSFODNN7EXAMPLE'), b = hook('AKIAIOSFODNN7EXAMPLE')
  // Guard the nulls: `null === null` would report "deterministic" for an engine
  // that redacted nothing at all.
  if (a === null || b === null) throw new Error('hook minted no placeholder for a known AWS key')
  // Throw rather than log: cache-stable redaction is the property this step
  // exists to prove, so a drift here has to fail the run, not narrate itself
  // inside a smoke that still exits 0.
  if (a !== b) {
    throw new Error(`hook placeholders differ across calls - cache stability broken (${a} vs ${b})`)
  }
  log('   deterministic across calls: yes')

  log('\n=== 7. audit log ===')
  await audit(12)

  log('\n=== 8. dashboard screenshot ===')
  try {
    shot(mitm ? 'smoke-mitm' : 'smoke')
  } catch {
    log('  (agent-browser unavailable - skipped)')
  }
}

// ---------------------------------------------------------------- cli

const [cmd, ...rest] = process.argv.slice(2)
const has = (f) => rest.includes(f)
// Flags that consume the following argument -- needed so `pos` does not mistake
// a flag value for a positional.
const VALUED = new Set(['--pii-mode', '--policy', '--salt', '-X', '-d'])
const val = (f) => {
  const i = rest.indexOf(f)
  return i === -1 ? undefined : rest[i + 1]
}
// Positional arguments only. Reading `rest[0]` directly made `probe --mitm URL`
// probe the string "--mitm" and `hook --salt s` redact the string "--salt".
const pos = (() => {
  const out = []
  for (let i = 0; i < rest.length; i++) {
    if (VALUED.has(rest[i])) i++
    else if (!rest[i].startsWith('-')) out.push(rest[i])
  }
  return out
})()

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
      await down()
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
      probe(pos[0], { mitm: has('--mitm'), method: val('-X'), body: val('-d') })
      break
    case 'approvals':
      await approvals()
      break
    case 'approve':
      await resolveApproval(pos[0], 'approve')
      break
    case 'deny':
      await resolveApproval(pos[0], 'reject')
      break
    case 'audit':
      await audit(Number(pos[0]) || 20)
      break
    case 'hook':
      log(
        hook(pos[0] ?? 'aws key AKIAIOSFODNN7EXAMPLE, email alice@example.com', val('--salt') ?? 'driver') ??
          '(nothing to redact)',
      )
      break
    case 'shot':
      shot(pos[0])
      break
    case 'ui-approve': {
      // agent-browser holds no page until something opens one, so a standalone
      // `ui-approve` would fail with `nav "Approvals" not found in snapshot`.
      ab(['open', MGMT_URL], { quiet: true })
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
  up [--mitm] [--redact]      launch gateway; --redact and --pii-mode block
     [--pii-mode M] [--policy F]   both require --mitm (--tls-intercept)
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
