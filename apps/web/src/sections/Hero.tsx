import { GITHUB_URL } from '../lib/links'
import { scrollToPolicy } from '../lib/scrollToPolicy'

export function Hero() {
  return (
    <section
      className="hero-bleed"
      aria-label="Honmoon membrane — requests pierce the barrier wall and ripple as they are judged"
    >
      <div className="hero-scrim"></div>

      <div className="container">
        <div className="hero-copy">
          <p className="eyebrow">Runtime Security for AI Agents</p>
          <h1>The <span className="hl-accent">gate</span> between<br />your AI agents and production</h1>
          <p className="lead">Every outbound action pierces the barrier. What crosses is what your policy allows — <span className="hl-mask">masked</span>, <span className="hl-pause">held</span>, or <span className="hl-deny">bounced</span> before it lands.</p>
          <div className="hero-cta">
            <button className="btn btn-primary" id="hero-cta" onClick={scrollToPolicy}>See the policy engine</button>
            <a className="btn btn-ghost" href={GITHUB_URL} target="_blank" rel="noopener">GitHub ↗</a>
          </div>
        </div>
      </div>
    </section>
  )
}
