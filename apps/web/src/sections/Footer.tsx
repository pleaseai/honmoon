import { DOCS_URL, GITHUB_URL, README_URL } from '../lib/links'

export function Footer() {
  return (
    <footer className="pagefoot">
      <div className="container foot-grid">
        <div className="foot-brand">
          <a className="logo" href="#"><span className="mark" aria-hidden="true"></span>honmoon</a>
          <span className="foot-meta">Open-core policy firewall · Apache-2.0</span>
        </div>
        <nav className="foot-cols" aria-label="Footer">
          <div className="foot-col">
            <span className="foot-h">Product</span>
            <a href="#how">How it works</a>
            <a href="#policy">Policy engine</a>
            <a href="#modes">Operating modes</a>
            <a href="#open-core">Open core</a>
          </div>
          <div className="foot-col">
            <span className="foot-h">Resources</span>
            <a href={GITHUB_URL} target="_blank" rel="noopener">GitHub ↗</a>
            <a href={DOCS_URL} target="_blank" rel="noopener">Docs ↗</a>
            <a href={README_URL} target="_blank" rel="noopener">Readme ↗</a>
          </div>
        </nav>
      </div>
      <div className="container foot-base">
        <span>© 2026 Honmoon</span>
        <span className="stat">data plane never locked</span>
      </div>
    </footer>
  )
}
