import Prism from 'prismjs'
import { useEffect, useState } from 'react'
import Editor from 'react-simple-code-editor'
import { getPolicy } from '../api'
import 'prismjs/components/prism-yaml'
import 'prismjs/themes/prism-tomorrow.css'

export function PolicyView() {
  const [yaml, setYaml] = useState('')
  const [active, setActive] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loaded, setLoaded] = useState(false)

  function load() {
    getPolicy()
      .then((res) => {
        setYaml(res.yaml)
        setActive(res.yaml)
        setError(null)
      })
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoaded(true))
  }

  useEffect(load, [])

  const dirty = yaml !== active

  return (
    <section>
      <header className="mb-4 flex items-baseline justify-between gap-3">
        <h2 className="text-base font-semibold">Policy</h2>
        {dirty && (
          <button
            type="button"
            onClick={() => setYaml(active)}
            className="text-xs text-zinc-500 underline hover:text-zinc-700 dark:hover:text-zinc-300"
          >
            Reset to active
          </button>
        )}
      </header>

      {error && (
        <p className="mb-3 rounded border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-700 dark:border-rose-900 dark:bg-rose-950 dark:text-rose-300">
          {error}
        </p>
      )}

      {loaded && (
        <div className="overflow-hidden rounded-lg border border-zinc-300 dark:border-zinc-700">
          <Editor
            value={yaml}
            onValueChange={setYaml}
            highlight={code => Prism.highlight(code, Prism.languages.yaml, 'yaml')}
            padding={16}
            textareaClassName="focus:outline-none"
            className="min-h-[24rem] font-mono text-[13px] leading-relaxed"
            style={{ backgroundColor: '#1d1f21', color: '#c5c8c6' }}
          />
        </div>
      )}

      <p className="mt-3 text-xs text-zinc-500">
        Edits are local. Live policy hot-reload lands in Phase 5; today the
        gateway loads policy from its
        {' '}
        <code className="rounded bg-zinc-100 px-1 dark:bg-zinc-800">--config</code>
        {' '}
        file.
      </p>
    </section>
  )
}
