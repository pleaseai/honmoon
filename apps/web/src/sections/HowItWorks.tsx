export function HowItWorks() {
  return (
    <section className="section lp" id="how">
      <div className="container">
        <div className="lp-mini">
          <p className="eyebrow"><span className="ix">02</span>How it works</p>
          <h2>Two layers. One gateway.</h2>
        </div>
        <div className="flow">
          <div className="flow-node endcap"><span className="n-t">Source</span><span className="n-l">AI agent</span></div>
          <span className="flow-arrow">→</span>
          <div className="flow-node layer"><span className="n-t">Layer 1</span><span className="n-l">Egress filter</span><span className="n-s">domain allow / deny</span></div>
          <span className="flow-arrow">→</span>
          <div className="flow-node layer"><span className="n-t">Layer 2</span><span className="n-l">Protocol engine</span><span className="n-s">SQL · K8s · HTTP + CEL</span></div>
          <span className="flow-arrow">→</span>
          <div className="flow-node endcap"><span className="n-t">Destination</span><span className="n-l">APIs · DB · K8s</span></div>
        </div>
        <div className="facts-strip"><b>parsed at the wire</b><code>sql.verb</code><code>sql.table</code><code>k8s.resource</code><code>k8s.verb</code><code>http.method</code><code>http.path</code></div>
      </div>
    </section>
  )
}
