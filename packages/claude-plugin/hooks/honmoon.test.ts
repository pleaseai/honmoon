import type { EngineInterface } from 'claude-code'
import { describe, expect, test } from 'bun:test'
import { applyOptions, promptHook, toolHook } from './honmoon'

interface Payload { hook_event_name: string, tool_name?: string, tool_response?: unknown }
interface Reply { stdout?: string, exitCode?: number, throws?: string }
type ToolArgs = Parameters<typeof toolHook>
type PromptArgs = Parameters<typeof promptHook>

/** A fake `$`: `honmoon hook` is answered from `reply`, and time never passes. */
function engine(reply: (payload: Payload) => Reply, http?: (url: string, init: unknown) => unknown) {
  const calls: { argv: readonly string[], payload: Payload }[] = []
  const fetches: { url: string, init: unknown }[] = []
  const $ = {
    process: {
      run: async (argv: readonly string[], init: { stdin: string }) => {
        const payload = JSON.parse(init.stdin) as Payload
        calls.push({ argv, payload })
        const answer = reply(payload)
        if (answer.throws) {
          throw new Error(answer.throws)
        }
        return { exitCode: answer.exitCode ?? 0, stdout: answer.stdout ?? '', stderr: '' }
      },
    },
    http: {
      fetch: async (url: string, init: unknown) => {
        fetches.push({ url, init })
        return http?.(url, init) ?? { ok: true, status: 200, headers: {}, text: '' }
      },
    },
    clock: { sleep: () => new Promise<void>(() => {}) },
    session: { id: async () => 'session-1' },
  }
  return { $: $ as unknown as EngineInterface, calls, fetches }
}

function redacted(output: unknown): string {
  return JSON.stringify({ hookSpecificOutput: { hookEventName: 'PostToolUse', updatedToolOutput: output } })
}

const readEvent = { tool: 'Read', file_path: '/tmp/notes.txt' }
const readRecord = { type: 'text', file: { filePath: '/tmp/notes.txt', content: 'key=sk-live-1', numLines: 1, startLine: 1, totalLines: 1 } }
const readResult = { ref: 7, text: 'key=sk-live-1', result: readRecord }

function runTool(fake: unknown, e: unknown, next: unknown) {
  return toolHook(fake as ToolArgs[0], e as ToolArgs[1], next as ToolArgs[2])
}

function runPrompt(fake: unknown, e: unknown, next: unknown) {
  return promptHook(fake as PromptArgs[0], e as PromptArgs[1], next as PromptArgs[2])
}

describe('tool.call', () => {
  test('denies a PreToolUse deny without running the tool', async () => {
    applyOptions({})
    const deny = JSON.stringify({
      hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: 'honmoon: blocked path' },
    })
    const { $ } = engine(p => (p.hook_event_name === 'PreToolUse' ? { stdout: deny } : {}))
    let ran = false
    const r = await runTool($, readEvent, async () => {
      ran = true
      return readResult
    })
    expect(r).toEqual({ deny: 'honmoon: blocked path' })
    expect(ran).toBe(false)
  })

  test('rewrites a redacted result, appends a context note and drops ref/text', async () => {
    applyOptions({})
    const scrubbed = { ...readRecord, file: { ...readRecord.file, content: 'key=<<hs:abc123>>' } }
    const { $ } = engine(p => (p.hook_event_name === 'PostToolUse' ? { stdout: redacted(scrubbed) } : {}))
    const r = await runTool($, readEvent, async () => readResult)
    expect(r.result).toEqual(scrubbed)
    expect(r.context).toEqual(['honmoon: 1 value(s) redacted with stable placeholders; treat <<hs:…>> tokens as opaque'])
    expect(r.ref).toBeUndefined()
    expect(r.text).toBeUndefined()
  })

  test('returns the identical object when nothing was redacted', async () => {
    applyOptions({})
    const { $ } = engine(() => ({ stdout: '' }))
    const r = await runTool($, readEvent, async () => readResult)
    expect(r).toBe(readResult)
  })

  test('passes a deny or an errored result straight through', async () => {
    applyOptions({})
    const { $, calls } = engine(p => (p.hook_event_name === 'PreToolUse' ? {} : { stdout: redacted(readRecord) }))
    const denied = { deny: 'permission refused' }
    const errored = { isError: true as const, result: 'boom', text: 'boom' }
    expect(await runTool($, readEvent, async () => denied)).toBe(denied)
    expect(await runTool($, { tool: 'Bash', command: 'ls' }, async () => errored)).toBe(errored)
    expect(calls.every(c => c.payload.hook_event_name === 'PreToolUse')).toBe(true)
  })

  test('scans WebFetch output through the engine\'s Read gate', async () => {
    applyOptions({})
    const fetched = { bytes: 3, code: 200, codeText: 'OK', result: 'token sk-live-1', durationMs: 5, url: 'https://example.com' }
    const scrubbed = { ...fetched, result: 'token <<hs:abc123>>' }
    const { $, calls } = engine(() => ({ stdout: redacted(scrubbed) }))
    const r = await runTool($, { tool: 'WebFetch', url: 'https://example.com', prompt: 'summarise' }, async () => ({ ref: 1, text: 'x', result: fetched }))
    expect(calls[0]?.payload.tool_name).toBe('Read')
    expect(r.result).toEqual(scrubbed)
  })

  test('denies the output when the engine cannot be reached', async () => {
    applyOptions({})
    const { $ } = engine(() => ({ throws: 'spawn honmoon ENOENT' }))
    const r = await runTool($, readEvent, async () => readResult)
    expect(r.deny).toBe('honmoon: redaction engine unavailable (spawn honmoon ENOENT); tool output withheld')
  })

  test('denies the output when the engine exits non-zero', async () => {
    applyOptions({ honmoonBin: 'honmoon' })
    const { $ } = engine(p => (p.hook_event_name === 'PostToolUse' ? { exitCode: 3 } : {}))
    const r = await runTool($, readEvent, async () => readResult)
    expect(r.deny).toBe('honmoon: redaction engine unavailable (honmoon hook exited 3); tool output withheld')
  })

  test('denies the output when the engine writes unparseable stdout', async () => {
    applyOptions({})
    const { $ } = engine(p => (p.hook_event_name === 'PostToolUse' ? { stdout: 'not json' } : {}))
    const r = await runTool($, readEvent, async () => readResult)
    expect(r.deny).toBe('honmoon: redaction engine unavailable (engine output is not JSON); tool output withheld')
  })

  test('denies the output when the http transport answers non-ok', async () => {
    applyOptions({ transport: 'http', hookUrl: 'http://127.0.0.1:7777/api/hooks/claude-code', hookToken: 't0ken' })
    const { $, fetches } = engine(() => ({}), () => ({ ok: false, status: 503, headers: {}, text: '' }))
    const r = await runTool($, readEvent, async () => readResult)
    expect(r.deny).toBe('honmoon: redaction engine unavailable (HTTP 503); tool output withheld')
    expect((fetches[0]?.init as { headers: Record<string, string> }).headers.authorization).toBe('Bearer t0ken')
  })

  test('passes the result through unredacted when failMode is open', async () => {
    applyOptions({ failMode: 'open' })
    const { $ } = engine(() => ({ throws: 'spawn honmoon ENOENT' }))
    const r = await runTool($, readEvent, async () => readResult)
    expect(r).toBe(readResult)
  })
})

describe('prompt.submit', () => {
  test('rewrites the prompt and notes the redaction', async () => {
    applyOptions({})
    const { $ } = engine(() => ({ stdout: redacted('my key is <<hs:abc123>>') }))
    const seen: string[] = []
    const r = await runPrompt($, { text: 'my key is sk-live-1', wait: false, origin: 'user' }, async (e: { text: string }) => {
      seen.push(e.text)
      return { text: e.text }
    })
    expect(seen).toEqual(['my key is <<hs:abc123>>'])
    expect(r.text).toBe('my key is <<hs:abc123>>')
    expect(r.context).toEqual(['honmoon: 1 value(s) redacted with stable placeholders; treat <<hs:…>> tokens as opaque'])
  })

  test('drops the prompt when the engine blocks it with no redacted text', async () => {
    applyOptions({})
    const { $ } = engine(() => ({ stdout: JSON.stringify({ decision: 'block', reason: 'honmoon: prompt carries a secret' }) }))
    const r = await runPrompt($, { text: 'sk-live-1', wait: false, origin: 'user' }, async () => ({ text: 'sk-live-1' }))
    expect(r).toEqual({ drop: 'honmoon: prompt carries a secret' })
  })

  test('drops the prompt when the engine cannot be reached', async () => {
    applyOptions({})
    const { $ } = engine(() => ({ throws: 'spawn honmoon ENOENT' }))
    const r = await runPrompt($, { text: 'hello', wait: false, origin: 'user' }, async () => ({ text: 'hello' }))
    expect(r.drop).toBe('honmoon: redaction engine unavailable (spawn honmoon ENOENT); prompt not sent')
  })
})
