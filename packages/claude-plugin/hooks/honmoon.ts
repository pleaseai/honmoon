// honmoon-redact — Claude Code function-hooks module (early access).
//
// Runs the same `honmoon` redaction engine the command hooks shell out to, but
// from inside the hook chain, so it can (a) rewrite a prompt instead of blocking
// it and (b) fail *closed*: a transport failure denies the tool output rather
// than letting raw bytes through. Enable with CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1;
// see the README section "Function hooks (early access)".
//
// Transports (option `transport`): "process" (default) runs `honmoon hook`,
// "http" POSTs to the management API. Both speak the hook payload/verdict JSON
// of crates/honmoon-cli/src/hook.rs and honmoon-core's claude_code_hook.rs.
//
// `$` may never be passed as an argument (the host's module validator rejects
// it), so each hook hands the shared logic small closures over its own `$`.
import type { Hook, HttpInit, HttpResponse, MatchedHook, PluginOptions, Register } from 'claude-code'

/** Engine budget. The host skips a hook that runs past 10 s, so stay under it. */
const ENGINE_TIMEOUT_MS = 8_000
/** Placeholder shape minted by honmoon-core's tokenizer. */
const PLACEHOLDER = /<<hs:[^>]*>>/g
/** Tools whose output is scanned. Read is additionally checked before it runs. */
const TOOL_MATCHER = { tool: ['Read', 'Bash', 'Grep', 'WebFetch'] } as const

type Json = Record<string, unknown>
/** A parsed hook verdict, or why the engine could not produce one. */
type Answer = { ok: true, verdict: Json } | { ok: false, cause: string }
interface Config { bin: string, url: string, token: string, failClosed: boolean }
type Runner = (
  argv: readonly string[],
  init: { stdin: string, timeoutMs: number },
) => Promise<{ exitCode: number, stdout: string }>
type Fetcher = (url: string, init: HttpInit) => Promise<HttpResponse>
type Sleeper = (ms: number, options?: { signal?: AbortSignal }) => Promise<void>
type Ask = (payload: Json) => Promise<Answer>

export function configure(options: PluginOptions): Config {
  const url = typeof options.hookUrl === 'string' ? options.hookUrl.trim() : ''
  // Unset (the manifest declares no default for it, deliberately): `hookUrl`
  // alone selects the http transport, as the README documents.
  const transport = String(options.transport ?? (url ? 'http' : 'process')).trim().toLowerCase()
  return {
    bin: String(options.honmoonBin ?? 'honmoon'),
    url: transport === 'http' ? url : '',
    token: String(options.hookToken ?? ''),
    failClosed: String(options.failMode ?? 'closed').trim().toLowerCase() !== 'open',
  }
}

/** An empty body is the engine's documented no-op; anything else must be JSON. */
function parseVerdict(body: string): Answer {
  const text = body.trim()
  if (!text) {
    return { ok: true, verdict: {} }
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  }
  catch {
    return { ok: false, cause: 'engine output is not JSON' }
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { ok: false, cause: 'engine output is not a JSON object' }
  }
  return { ok: true, verdict: parsed as Json }
}

/**
 * Ask the engine, never throwing and never outstaying the budget: every failure
 * mode (spawn error, timeout, non-zero exit, bad JSON, HTTP error) comes back as
 * `{ ok: false }` so the caller can make the fail-closed decision.
 */
export function engineAsk(
  config: Config,
  run: Runner,
  fetch: Fetcher,
  sleep: Sleeper,
): Ask {
  const call = async (payload: Json): Promise<Answer> => {
    const body = JSON.stringify(payload)
    if (config.url) {
      const headers: Record<string, string> = { 'content-type': 'application/json' }
      if (config.token) {
        headers.authorization = `Bearer ${config.token}`
      }
      const response = await fetch(config.url, { method: 'POST', headers, body })
      if (!response.ok) {
        return { ok: false, cause: `HTTP ${response.status}` }
      }
      return parseVerdict(response.text)
    }
    const result = await run([config.bin, 'hook'], { stdin: body, timeoutMs: ENGINE_TIMEOUT_MS })
    if (result.exitCode !== 0) {
      return { ok: false, cause: `${config.bin} hook exited ${result.exitCode}` }
    }
    return parseVerdict(result.stdout)
  }
  return async (payload) => {
    // The deadline timer is the hook's own; abort it once the race settles so a
    // fast answer does not leave an 8 s timer (and this closure) pending per
    // tool call — `$.clock.sleep` takes the signal for exactly this.
    const abort = new AbortController()
    const answer = call(payload)
    // The race only reads whichever promise settles first; mark the other one
    // handled so a late rejection is not an unhandled rejection.
    answer.catch(() => {})
    const deadline = sleep(ENGINE_TIMEOUT_MS, { signal: abort.signal }).then(
      (): Answer => ({ ok: false, cause: 'engine timed out' }),
      // Aborted because `call` already answered: never settle the race.
      () => new Promise<Answer>(() => {}),
    )
    try {
      return await Promise.race([answer, deadline])
    }
    catch (error) {
      return { ok: false, cause: error instanceof Error ? error.message : String(error) }
    }
    finally {
      abort.abort()
    }
  }
}

function hookSpecific(verdict: Json): Json {
  const output = verdict.hookSpecificOutput
  return output && typeof output === 'object' ? (output as Json) : {}
}

/** The engine's `PreToolUse` deny reason, or undefined when it allowed the call. */
function denyReason(verdict: Json): string | undefined {
  const output = hookSpecific(verdict)
  if (output.permissionDecision !== 'deny') {
    return undefined
  }
  const reason = output.permissionDecisionReason
  return typeof reason === 'string' && reason ? reason : 'honmoon: blocked by policy'
}

/**
 * The redacted form of what was sent, or undefined when nothing was redacted.
 * honmoon-core returns `updatedToolOutput` shaped exactly like what it was
 * given, so a tool record comes back that record and a string comes back a string.
 */
function updatedOutput(verdict: Json): unknown {
  return hookSpecific(verdict).updatedToolOutput
}

/**
 * Count the placeholders the model is about to read. Counting the *result*
 * rather than a before/after delta keeps the number true when something else
 * redacted first (the command hooks run inside `next()` and mint the same
 * token shape), where a delta would be 0 and have to be faked.
 */
function redactionNote(after: unknown): string {
  const count = (JSON.stringify(after ?? null).match(PLACEHOLDER) ?? []).length
  return `honmoon: ${count} value(s) redacted with stable placeholders; treat <<hs:…>> tokens as opaque`
}

function unavailable(cause: string): string {
  return `honmoon: redaction engine unavailable (${cause}); tool output withheld`
}

/**
 * The engine gates `PostToolUse` redaction on `tool_name` ∈ {Read, Bash, Grep}
 * (honmoon-core `handle_post_tool_use`). WebFetch output and prompt text reach
 * the same content-driven redactor by being presented under `Read`, for which
 * the field is only a gate.
 */
function engineToolName(tool: string): string {
  return tool === 'Bash' || tool === 'Grep' ? tool : 'Read'
}

/**
 * The plugin's options, applied by `register`. The host requires every hook to
 * be a top-level function, so the configuration reaches them through module
 * state rather than a closure; the unit tests call this before driving a hook.
 */
let config: Config = configure({})
/** The session id keys the engine's placeholder salt (stable across turns). */
let sessionId: Promise<string> | undefined
/** The session cwd, which the engine anchors relative `file_path`s against. */
let sessionCwd: Promise<string> | undefined

export function applyOptions(options: PluginOptions): void {
  config = configure(options)
  sessionId = undefined
  sessionCwd = undefined
}

/**
 * Memoize a session lookup, but never memoize a *rejection*: a cached rejected
 * promise would make the rest of the session run with an empty session id, and
 * the empty id is a shared salt — placeholders would stop being unforgeable and
 * would collide across sessions.
 */
async function once(
  cached: Promise<string> | undefined,
  load: () => Promise<string>,
  store: (p: Promise<string> | undefined) => void,
): Promise<string> {
  if (!cached) {
    cached = load()
    store(cached)
  }
  try {
    return await cached
  }
  catch {
    store(undefined)
    return ''
  }
}

/** Both session facts the engine payloads carry, resolved once per session. */
async function sessionFacts($: Parameters<typeof promptHook>[0]): Promise<{ session_id: string, cwd: string }> {
  const [session_id, cwd] = await Promise.all([
    once(sessionId, () => $.session.id(), p => (sessionId = p)),
    once(sessionCwd, () => $.session.cwd(), p => (sessionCwd = p)),
  ])
  return { session_id, cwd }
}

export const toolHook: MatchedHook<'tool.call', typeof TOOL_MATCHER> = async ($, e, next) => {
  const ask = engineAsk(
    config,
    (argv, init) => $.process.run(argv, init),
    (url, init) => $.http.fetch(url, init),
    (ms, options) => $.clock.sleep(ms, options),
  )
  const { session_id, cwd } = await sessionFacts($)

  if (e.tool === 'Read') {
    const pre = await ask({
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: e.file_path },
      // The http transport resolves a relative `file_path` against this and
      // denies the read as "unresolved" without it (honmoon-mgmt
      // `resolve_agent_path`); the command hooks get it from the host payload.
      cwd,
      session_id,
    })
    if (!pre.ok) {
      if (config.failClosed) {
        return { deny: unavailable(pre.cause) }
      }
    }
    else {
      const reason = denyReason(pre.verdict)
      if (reason) {
        return { deny: reason }
      }
    }
  }

  const r = await next(e)
  // A refusal or an errored call carries no tool record to redact, and core's
  // own messages are what the model should read.
  if (r.deny !== undefined || r.isError) {
    return r
  }
  // Only the variants the detectors can read. An image or pdf record holds
  // base64 bytes, and rewriting it would corrupt it; a notebook record is plain
  // JSON cells, so it is scanned like any other text.
  if (e.tool === 'Read') {
    const type = (r.result as { type?: string } | undefined)?.type
    if (type !== 'text' && type !== 'notebook') {
      return r
    }
  }

  const post = await ask({
    hook_event_name: 'PostToolUse',
    tool_name: engineToolName(e.tool),
    tool_input: {},
    tool_response: r.result,
    session_id,
  })
  if (!post.ok) {
    return config.failClosed ? { deny: unavailable(post.cause) } : r
  }
  const updated = updatedOutput(post.verdict)
  // Nothing redacted: hand back exactly what `next` resolved to, so core reuses
  // the messages it already built (`ref`/`text`).
  if (updated === undefined) {
    return r
  }
  return {
    result: updated as typeof r.result,
    context: [...(r.context ?? []), redactionNote(updated)],
  }
}

/**
 * Redact and forward rather than block: the prompt is dropped only when the
 * transport failed (or, defensively, if a future engine answers this payload
 * with a `decision:"block"` verdict — today's `handle_post_tool_use` only ever
 * answers with `hookSpecificOutput`).
 *
 * Note the threshold this path uses: presenting the prompt as tool output runs
 * it through `redact_json_value` at `DEFAULT_MIN_PII_SEVERITY` (2), not the
 * `PII_SEVERITY_HIGH` (3) floor `handle_user_prompt_submit` applies. Medium
 * severity PII — an email address, a phone number — is therefore rewritten in
 * prompts here where the command hook let it through untouched.
 */
export const promptHook: Hook<'prompt.submit'> = async ($, e, next) => {
  const ask = engineAsk(
    config,
    (argv, init) => $.process.run(argv, init),
    (url, init) => $.http.fetch(url, init),
    (ms, options) => $.clock.sleep(ms, options),
  )
  const { session_id } = await sessionFacts($)
  const answer = await ask({
    hook_event_name: 'PostToolUse',
    tool_name: 'Read',
    tool_input: {},
    tool_response: e.text,
    session_id,
  })
  if (!answer.ok) {
    if (!config.failClosed) {
      return next(e)
    }
    return { drop: `honmoon: redaction engine unavailable (${answer.cause}); prompt not sent` }
  }
  const updated = updatedOutput(answer.verdict)
  if (typeof updated !== 'string') {
    if (answer.verdict.decision === 'block') {
      const reason = answer.verdict.reason
      return { drop: typeof reason === 'string' && reason ? reason : 'honmoon: prompt blocked' }
    }
    return next(e)
  }
  const r = await next({ ...e, text: updated })
  if (r.drop !== undefined) {
    return r
  }
  return { ...r, context: [...(r.context ?? []), redactionNote(updated)] }
}

export const register: Register = (on, options) => {
  applyOptions(options)
  // One registration covers both placements: on 2.1.263 a second
  // `on("tool.call", …)` from the same plugin silently replaces the first, so
  // the before-check (PreToolUse on Read) and the after-redaction share a hook.
  on('tool.call', TOOL_MATCHER, toolHook)
  on('prompt.submit', promptHook)
}
