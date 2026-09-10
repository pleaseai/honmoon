import { GITHUB_URL } from '../lib/links'
import { scrollToPolicy } from '../lib/scrollToPolicy'

export function Hero() {
  return (
    <section
      className="hero-bleed"
      aria-label="Honmoon barrier: requests are checked at the barrier and judged"
    >
      <div className="hero-scrim"></div>

      <div className="container">
        <div className="hero-copy">
          <p className="eyebrow">Runtime Security for AI Agents</p>
          <h1>The <span className="hl-accent">barrier</span> between<br />your AI agents and production systems</h1>
          <p className="lead">Every outbound action is checked at the barrier. Only what your policy allows gets through. Everything else is <span className="hl-mask">masked</span>, <span className="hl-pause">held</span>, or <span className="hl-deny">blocked</span> before it reaches production.</p>
          <div className="hero-cta">
            <button className="btn btn-primary" id="hero-cta" onClick={scrollToPolicy}>See the policy engine</button>
            <a className="btn btn-ghost" href={GITHUB_URL} target="_blank" rel="noopener">GitHub ↗</a>
          </div>
        </div>
      </div>
    </section>
  )
}
