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
    session: { id: async () => 'session-1', cwd: async () => '/repo' },
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

  test('passes a deny, or an errored result with nothing to redact, straight through', async () => {
    applyOptions({})
    const { $, calls } = engine(p => (p.hook_event_name === 'PreToolUse' ? {} : { stdout: '{}' }))
    const denied = { deny: 'permission refused' }
    const errored = { isError: true as const, result: 'boom', text: 'boom' }
    expect(await runTool($, readEvent, async () => denied)).toBe(denied)
    expect(calls).toHaveLength(1)
    expect(await runTool($, { tool: 'Bash', command: 'ls' }, async () => errored)).toBe(errored)
    expect(calls[1]?.payload).toMatchObject({ hook_event_name: 'PostToolUse', tool_name: 'Read', tool_response: { text: 'boom', result: 'boom' } })
  })

  test('an errored result that carries a secret becomes an error the model reads redacted', async () => {
    applyOptions({})
    const { $, calls } = engine(p => (p.hook_event_name === 'PostToolUse' ? { stdout: redacted({ text: 'Exit 3: auth failed for key <<hs:k1>>', result: 'auth failed for key <<hs:k1>>' }) } : {}))
    const errored = { isError: true as const, ref: 3, result: 'auth failed for key sk-live-1', text: 'Exit 3: auth failed for key sk-live-1' }
    const r = await runTool($, { tool: 'Bash', command: 'curl' }, async () => errored)
    expect(calls[0]?.payload.tool_response).toEqual({ text: errored.text, result: errored.result })
    expect(r.deny).toStartWith('Exit 3: auth failed for key <<hs:k1>>')
    expect(JSON.stringify(r)).not.toContain('sk-live-1')
  })

  test('an errored result is withheld when the engine cannot be reached', async () => {
    applyOptions({})
    const { $ } = engine(p => (p.hook_event_name === 'PostToolUse' ? { throws: 'spawn honmoon ENOENT' } : {}))
    const errored = { isError: true as const, result: 'key sk-live-1', text: 'key sk-live-1' }
    const r = await runTool($, { tool: 'Bash', command: 'curl' }, async () => errored)
    expect(r).toEqual({ deny: 'honmoon: redaction engine unavailable (spawn honmoon ENOENT); tool output withheld' })
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

  test('denies the output when a 200 JSON body is not a hook verdict', async () => {
    applyOptions({ transport: 'http', hookUrl: 'http://127.0.0.1:9/api/hooks/claude-code' })
    const { $ } = engine(() => ({}), () => ({ ok: true, status: 200, headers: {}, text: '{"error":"upstream unavailable"}' }))
    const r = await runTool($, readEvent, async () => readResult)
    expect(r.deny).toBe('honmoon: redaction engine unavailable (engine output is not a hook verdict (unexpected key "error")); tool output withheld')
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

  test('sends the session cwd, which the engine anchors a relative file_path against', async () => {
    applyOptions({})
    const { $, calls } = engine(() => ({}))
    await runTool($, { tool: 'Read', file_path: 'src/main.rs' }, async () => readResult)
    const pre = calls.find(c => c.payload.hook_event_name === 'PreToolUse')
    expect((pre?.payload as { cwd?: string }).cwd).toBe('/repo')
  })

  test('redacts a notebook record — its cells are plain JSON, not opaque bytes', async () => {
    applyOptions({})
    const notebook = { type: 'notebook', file: { filePath: '/repo/a.ipynb', cells: [{ source: 'KEY = "sk-live-1"' }] } }
    const scrubbed = { ...notebook, file: { ...notebook.file, cells: [{ source: 'KEY = "<<hs:abc123>>"' }] } }
    const { $ } = engine(p => (p.hook_event_name === 'PostToolUse' ? { stdout: redacted(scrubbed) } : {}))
    const r = await runTool($, { tool: 'Read', file_path: '/repo/a.ipynb' }, async () => ({ ref: 2, text: 'x', result: notebook }))
    expect(r.result).toEqual(scrubbed)
  })

  test('leaves an image record alone — the detectors cannot read base64 bytes', async () => {
    applyOptions({})
    const image = { type: 'image', file: { base64: 'AAAA', type: 'image/png' } }
    const given = { ref: 3, text: 'x', result: image }
    const { $, calls } = engine(() => ({ stdout: redacted({ scrubbed: true }) }))
    expect(await runTool($, { tool: 'Read', file_path: '/repo/a.png' }, async () => given)).toBe(given)
    expect(calls.every(c => c.payload.hook_event_name === 'PreToolUse')).toBe(true)
  })

  test('hookUrl alone selects the http transport (no transport option set)', async () => {
    applyOptions({ hookUrl: 'http://127.0.0.1:7777/api/hooks/claude-code' })
    const { $, fetches, calls } = engine(() => ({}))
    await runTool($, readEvent, async () => readResult)
    expect(fetches.length).toBeGreaterThan(0)
    expect(calls).toEqual([])
  })

  test('an explicit transport of process ignores hookUrl', async () => {
    applyOptions({ transport: 'process', hookUrl: 'http://127.0.0.1:7777/api/hooks/claude-code' })
    const { $, fetches, calls } = engine(() => ({}))
    await runTool($, readEvent, async () => readResult)
    expect(fetches).toEqual([])
    expect(calls.length).toBeGreaterThan(0)
  })

  test('a rejected session id denies the call and is retried, never replaced by an empty salt', async () => {
    applyOptions({})
    const calls: { payload: Payload }[] = []
    let attempts = 0
    let ran = 0
    const $ = {
      process: {
        run: async (_argv: readonly string[], init: { stdin: string }) => {
          calls.push({ payload: JSON.parse(init.stdin) as Payload })
          return { exitCode: 0, stdout: '', stderr: '' }
        },
      },
      http: { fetch: async () => ({ ok: true, status: 200, headers: {}, text: '' }) },
      clock: { sleep: () => new Promise<void>(() => {}) },
      session: {
        id: async () => {
          attempts += 1
          if (attempts === 1) {
            throw new Error('not ready')
          }
          return 'session-1'
        },
        cwd: async () => '/repo',
      },
    } as unknown as ToolArgs[0]
    const next = async () => {
      ran += 1
      return readResult
    }
    const first = await runTool($, readEvent, next)
    expect(first).toEqual({ deny: 'honmoon: redaction engine unavailable (session lookup failed: not ready); tool output withheld' })
    expect(ran).toBe(0)
    expect(calls).toHaveLength(0)
    await runTool($, readEvent, next)
    const ids = calls.map(c => (c.payload as { session_id?: string }).session_id)
    expect(ids).toEqual(['session-1', 'session-1'])
  })

  test('the budget covers the session lookup, so a hung lookup fails closed instead of running past the host', async () => {
    applyOptions({})
    const { $, calls } = engine(() => ({}))
    const $hung = {
      ...$,
      clock: { sleep: async () => {} },
      session: { id: () => new Promise<string>(() => {}), cwd: async () => '/repo' },
    }
    const r = await runTool($hung, readEvent, async () => readResult)
    expect(r).toEqual({ deny: 'honmoon: redaction engine unavailable (session lookup failed: hook budget exhausted); tool output withheld' })
    expect(calls).toHaveLength(0)
  })

  test('a slow tool does not spend the budget of its own redaction', async () => {
    applyOptions({})
    const { $ } = engine(p => (p.hook_event_name === 'PostToolUse' ? { stdout: redacted({ ...readRecord, file: { ...readRecord.file, content: 'key=<<hs:1>>' } }) } : {}))
    // The first budget expires while the tool runs; any later one never does.
    let expire = () => {}
    let armed = false
    const $slow = {
      ...$,
      clock: {
        sleep: () => {
          if (armed) {
            return new Promise<void>(() => {})
          }
          armed = true
          return new Promise<void>((resolve) => {
            expire = resolve
          })
        },
      },
    }
    const r = await runTool($slow, readEvent, async () => {
      expire()
      await Promise.resolve()
      return readResult
    })
    expect(r).toMatchObject({ result: { file: { content: 'key=<<hs:1>>' } } })
  })

  test('transport http without a hookUrl is a configuration error, not a fallback to the binary', async () => {
    applyOptions({ transport: 'http' })
    const { $, calls, fetches } = engine(() => ({}))
    const r = await runTool($, readEvent, async () => readResult)
    expect(r).toEqual({ deny: 'honmoon: redaction engine unavailable (transport "http" needs a hookUrl); tool output withheld' })
    expect(calls).toHaveLength(0)
    expect(fetches).toHaveLength(0)
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

  test('a block decision wins over rewritten text in the same verdict', async () => {
    applyOptions({})
    const { $ } = engine(() => ({
      stdout: JSON.stringify({
        decision: 'block',
        reason: 'honmoon: prompt carries a secret',
        hookSpecificOutput: { hookEventName: 'PostToolUse', updatedToolOutput: 'my key is <<hs:abc123>>' },
      }),
    }))
    let forwarded = false
    const r = await runPrompt($, { text: 'sk-live-1', wait: false, origin: 'user' }, async () => {
      forwarded = true
      return { text: 'sk-live-1' }
    })
    expect(r).toEqual({ drop: 'honmoon: prompt carries a secret' })
    expect(forwarded).toBe(false)
  })

  test('drops the prompt when the engine cannot be reached', async () => {
    applyOptions({})
    const { $ } = engine(() => ({ throws: 'spawn honmoon ENOENT' }))
    const r = await runPrompt($, { text: 'hello', wait: false, origin: 'user' }, async () => ({ text: 'hello' }))
    expect(r.drop).toBe('honmoon: redaction engine unavailable (spawn honmoon ENOENT); prompt not sent')
  })
})
