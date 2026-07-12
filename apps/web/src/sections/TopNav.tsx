import { useScrollFlag } from '../hooks/useScrollFlag'
import { GITHUB_URL } from '../lib/links'
import { scrollToPolicy } from '../lib/scrollToPolicy'

export function TopNav() {
  const scrolled = useScrollFlag(24)

  return (
    <header className={scrolled ? 'topnav scrolled' : 'topnav'}>
      <div className="container topnav-inner">
        <a className="logo" href="/"><span className="mark" aria-hidden="true"></span>honmoon</a>
        <div className="nav-right">
          <nav>
            <a href="#how">How it works</a>
            <a href="#policy">Policy</a>
            <a href="#modes">Modes</a>
            <a href="#open-core">Open core</a>
          </nav>
          <a
            className="icon-btn"
            href={GITHUB_URL}
            target="_blank"
            rel="noopener"
            aria-label="Honmoon on GitHub"
          >
            <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 .5C5.73.5.75 5.48.75 11.75c0 4.98 3.23 9.2 7.71 10.69.56.1.77-.24.77-.54v-1.9c-3.13.68-3.79-1.5-3.79-1.5-.51-1.3-1.25-1.65-1.25-1.65-1.02-.7.08-.68.08-.68 1.13.08 1.72 1.16 1.72 1.16 1 1.72 2.64 1.22 3.28.93.1-.73.39-1.22.71-1.5-2.5-.28-5.13-1.25-5.13-5.57 0-1.23.44-2.24 1.16-3.03-.12-.28-.5-1.42.11-2.96 0 0 .94-.3 3.09 1.16.9-.25 1.86-.37 2.82-.38.96 0 1.92.13 2.82.38 2.15-1.46 3.09-1.16 3.09-1.16.61 1.54.23 2.68.11 2.96.72.79 1.16 1.8 1.16 3.03 0 4.33-2.64 5.28-5.15 5.56.4.35.76 1.04.76 2.1v3.11c0 .3.2.65.78.54 4.48-1.5 7.7-5.71 7.7-10.69C23.25 5.48 18.27.5 12 .5Z" /></svg>
          </a>
          <button className="btn btn-secondary" id="nav-cta" onClick={scrollToPolicy}>Get started</button>
        </div>
      </div>
    </header>
  )
}
