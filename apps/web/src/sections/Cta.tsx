const GITHUB_URL = 'https://github.com/pleaseai/honmoon'
const DOCS_URL = 'https://github.com/pleaseai/honmoon/tree/master/docs'

export function Cta() {
  return (
    <section className="section lp" id="start">
      <div className="container">
        <div className="cta-final">
          <p className="eyebrow" style={{ textAlign: 'center' }}><span className="ix">06</span>Raise the barrier</p>
          <h2>Put a firewall between your agents and production.</h2>
          <div className="hero-cta">
            <a className="btn btn-primary" href={GITHUB_URL} target="_blank" rel="noopener">Get started on GitHub</a>
            <a className="btn btn-secondary" href={DOCS_URL} target="_blank" rel="noopener">Docs ↗</a>
          </div>
        </div>
      </div>
    </section>
  )
}
