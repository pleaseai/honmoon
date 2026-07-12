import { scrollToPolicy } from '../lib/scrollToPolicy'

const GITHUB_URL = 'https://github.com/pleaseai/honmoon'

export function Hero() {
  return (
    <section
      className="hero-bleed"
      aria-label="Honmoon membrane — requests pierce the barrier wall and ripple as they are judged"
    >
      <div className="hero-scrim"></div>

      <div className="container">
        <div className="hero-copy">
          <p className="eyebrow">Policy-based Firewall Gateway for AI Agents</p>
          <h1>The firewall between<br />your AI agents and production</h1>
          <p className="lead">Every outbound request pierces the barrier. What ripples through is what your policy allows — masked, held, or bounced before it lands.</p>
          <div className="hero-cta">
            <button className="btn btn-primary" id="hero-cta" onClick={scrollToPolicy}>See the policy engine</button>
            <a className="btn btn-ghost" href={GITHUB_URL} target="_blank" rel="noopener">GitHub ↗</a>
          </div>
        </div>
      </div>
    </section>
  )
}
