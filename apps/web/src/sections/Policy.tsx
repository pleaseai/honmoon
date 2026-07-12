import { useRef, useState } from 'react'

export function Policy() {
  const preRef = useRef<HTMLPreElement>(null)
  const resetTimerRef = useRef<ReturnType<typeof setTimeout>>(undefined)
  const [label, setLabel] = useState('Copy')

  async function onCopy() {
    try {
      await navigator.clipboard.writeText(preRef.current?.textContent ?? '')
      setLabel('Copied ✓')
    }
    catch {
      setLabel('Failed')
    }
    // Clear any pending reset so rapid clicks don't race the label back early.
    clearTimeout(resetTimerRef.current)
    resetTimerRef.current = setTimeout(setLabel, 1600, 'Copy')
  }

  return (
    <section className="section lp" id="policy">
      <div className="container">
        <div className="split">
          <div>
            <p className="eyebrow"><span className="ix">03</span>Policy · CEL</p>
            <h2>A verdict before it lands.</h2>
            <ul className="verdicts">
              <li><span className="pill allow">allow</span> matches the allowlist — passes untouched</li>
              <li><span className="pill deny">deny</span> dangerous payloads never reach prod</li>
              <li><span className="pill pause">pause</span> ambiguous calls wait for a human</li>
            </ul>
          </div>
          <div className="code-card">
            <div className="code-head">
              <span className="meta">policies/agent.yaml</span>
              <button className="copy-btn" id="copy-policy" onClick={onCopy} aria-label="Copy policy example">{label}</button>
            </div>
            <pre id="policy-src" ref={preRef}>
              <span className="c-key">version:</span>{' 1\n'}
              <span className="c-key">egress:</span>{'\n'}
              {'  '}<span className="c-key">default:</span>{' '}<span className="c-deny">deny</span>{'\n'}
              {'  '}<span className="c-key">allow:</span>{'\n'}
              {'    - '}<span className="c-str">github.com</span>{'\n'}
              {'    - '}<span className="c-str">api.anthropic.com</span>{'\n\n'}
              <span className="c-key">rules:</span>{'\n'}
              {'  - '}<span className="c-key">name:</span>{' '}<span className="c-str">sql-no-prod-drop</span>{'\n'}
              {'    '}<span className="c-key">endpoint:</span>{' '}<span className="c-str">postgres-prod</span>{'\n'}
              {'    '}<span className="c-key">condition:</span>{' '}<span className="c-str">{`"sql.verb == 'DROP' || sql.verb == 'TRUNCATE'"`}</span>{'\n'}
              {'    '}<span className="c-key">verdict:</span>{' '}<span className="c-warn">pause</span>{'  '}<span className="c-cmt"># hold for a human</span>{'\n\n'}
              {'  - '}<span className="c-key">name:</span>{' '}<span className="c-str">k8s-no-secret-delete</span>{'\n'}
              {'    '}<span className="c-key">endpoint:</span>{' '}<span className="c-str">k8s-prod</span>{'\n'}
              {'    '}<span className="c-key">condition:</span>{' '}<span className="c-str">{`"k8s.resource == 'secrets' && k8s.verb == 'delete'"`}</span>{'\n'}
              {'    '}<span className="c-key">verdict:</span>{' '}<span className="c-deny">deny</span>
            </pre>
          </div>
        </div>
      </div>
    </section>
  )
}
