import type { Policy, Verdict } from '@honmoon/policy'
import { DEFAULT_EGRESS_VERDICT } from '@honmoon/policy'
import Prism from 'prismjs'
import { useEffect, useState } from 'react'
import EditorModule from 'react-simple-code-editor'
import { getPolicy } from '../api'
import { ErrorNote, PageHead, Panel, PanelState } from './ui'
import 'prismjs/components/prism-yaml'

// `react-simple-code-editor` ships CJS only — no `exports`/`module` field, and
// 0.14.1 is the latest release — so Vite's dep optimizer double-wraps its default
// export: `import Editor from …` resolves to `{ default: Component }` instead of
// the component, and React rejects that with "Element type is invalid … got:
// object", blanking the whole view. Unwrap the extra layer, falling through when
// a future Vite (or an ESM release) hands us the component directly.
const Editor = (EditorModule as unknown as { default?: typeof EditorModule }).default ?? EditorModule

const GUTTER = 48

const VERDICT_PAST: Record<Verdict, string> = {
  allow: 'allowed',
  deny: 'denied',
  pause: 'paused',
}

/** Prism YAML highlighting plus a gutter line number per line. */
function highlight(code: string): string {
  return Prism.highlight(code, Prism.languages.yaml, 'yaml')
    .split('\n')
    .map((line, i) => `<span class="line-no">${i + 1}</span>${line}`)
    .join('\n')
}

export function PolicyView() {
  const [yaml, setYaml] = useState('')
  // The policy the gateway reported; `null` until the first successful load.
  const [active, setActive] = useState<string | null>(null)
  const [parsed, setParsed] = useState<Policy | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [settled, setSettled] = useState(false)

  function load() {
    getPolicy()
      .then((res) => {
        setYaml(res.yaml)
        setActive(res.yaml)
        setParsed(res.parsed)
        setError(null)
      })
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setSettled(true))
  }

  useEffect(load, [])

  const dirty = active !== null && yaml !== active

  return (
    <section className="mx-auto max-w-[1440px] px-10 pt-[30px] pb-11 max-md:px-6">
      <PageHead
        eyebrow="Active gateway configuration"
        title="Policy"
        description="Inspect and edit the YAML locally without changing the running gateway."
        meta={parsed?.version !== undefined ? `version ${parsed.version}` : undefined}
      />

      {error && <ErrorNote message={error} />}

      <div className="grid grid-cols-[minmax(0,1fr)_310px] gap-3.5 max-lg:grid-cols-1">
        <Panel className="reveal" glassClassName="overflow-hidden">
          <header className="flex min-h-[58px] items-center gap-2.5 bg-[var(--surface-soft)] px-[18px]">
            <span className="font-mono text-[10px] font-semibold">Active policy</span>
            {dirty && (
              <span className="font-mono text-[8.5px] font-semibold tracking-[0.08em] text-warn-ink uppercase">
                Local changes
              </span>
            )}
            {dirty && (
              <button
                type="button"
                onClick={() => setYaml(active)}
                className="action action-quiet ml-auto"
              >
                Reset to active
              </button>
            )}
          </header>

          {active === null
            ? (
                settled
                  ? <PanelState glyph="✕" tone="error">The active policy could not be loaded.</PanelState>
                  : <PanelState glyph="…">Loading…</PanelState>
              )
            : (
                <div className="policy-editor max-h-[62vh] min-h-[24rem] overflow-auto">
                  <label htmlFor="policy-yaml" className="sr-only">Policy YAML editor</label>
                  <Editor
                    value={yaml}
                    onValueChange={setYaml}
                    highlight={highlight}
                    padding={{ top: 16, right: 18, bottom: 16, left: GUTTER + 10 }}
                    tabSize={2}
                    insertSpaces
                    textareaId="policy-yaml"
                    className="min-h-[24rem]"
                  />
                </div>
              )}

          <footer className="px-[18px] py-[13px] text-[10.5px] leading-relaxed text-muted">
            Edits are local. Live policy hot-reload lands in Phase 5; today the
            gateway loads policy from its
            {' '}
            <code className="rounded-[5px] bg-[var(--surface-soft)] px-1.5 py-0.5 font-mono text-[9.5px] font-medium text-fg">
              --config
            </code>
            {' '}
            file.
          </footer>
        </Panel>

        <Panel className="reveal" glassClassName="p-[19px]">
          <p className="eyebrow tracking-[0.12em] text-dim">Active posture</p>
          <Posture policy={parsed} />
          <div className="mt-[18px] rounded-[13px] bg-warn-soft p-[13px] text-[10px] leading-relaxed text-muted">
            <b className="text-warn-ink">Local editing only.</b>
            {' '}
            This surface does not save, deploy, or hot-reload policy.
          </div>
        </Panel>
      </div>
    </section>
  )
}

/** Facts about the policy the gateway reported — not the local edits. */
function Posture({ policy }: { policy: Policy | null }) {
  if (!policy) {
    return <p className="mt-3 text-[11px] leading-relaxed text-muted">Active policy not loaded.</p>
  }
  const fallback = policy.egress?.default ?? DEFAULT_EGRESS_VERDICT
  const facts = [
    ['Default', fallback],
    ['Allow hosts', String(policy.egress?.allow?.length ?? 0)],
    ['Deny hosts', String(policy.egress?.deny?.length ?? 0)],
    ['Rules', String(policy.rules?.length ?? 0)],
  ]
  return (
    <>
      <h2 className="mt-3 font-display text-lg font-semibold tracking-[-0.015em]">
        {fallback === 'deny' ? 'Fail closed by default.' : `Unmatched egress is ${VERDICT_PAST[fallback]}.`}
      </h2>
      <p className="mt-2 text-[11px] leading-relaxed text-muted">
        Egress not on the allow list gets the default verdict; protocol rules run
        first-match-wins before a request reaches its destination.
      </p>
      <dl className="mt-5 rounded-[14px] bg-[var(--surface-soft)] px-[13px] py-1">
        {facts.map(([label, value]) => (
          <div key={label} className="flex min-h-12 items-center not-first:shadow-[inset_0_1px_0_var(--hair)]">
            <dt className="font-mono text-[8.5px] font-medium tracking-[0.08em] text-dim uppercase">{label}</dt>
            <dd className="ml-auto font-mono text-[9.5px] font-medium tabular-nums">{value}</dd>
          </div>
        ))}
      </dl>
    </>
  )
}
