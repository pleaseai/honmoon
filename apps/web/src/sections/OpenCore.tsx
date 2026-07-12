export function OpenCore() {
  return (
    <section className="section lp" id="open-core">
      <div className="container">
        <div className="lp-mini">
          <p className="eyebrow"><span className="ix">05</span>Open core</p>
          <h2>Free on a node. Built for a fleet.</h2>
        </div>
        <div className="oc-grid">
          <div className="panel oc core">
            <span className="oc-tag">◆ OSS core · Apache-2.0</span>
            <div className="price">Free — never locked</div>
            <ul>
              <li>Full proxy, parsers &amp; CEL engine</li>
              <li>Single-node YAML policy</li>
              <li>Local audit log + dashboard</li>
              <li>Basic <code className="meta" style={{ color: 'inherit' }}>pause</code> approval</li>
            </ul>
          </div>
          <div className="panel oc paid">
            <span className="oc-tag">▲ Team &amp; Cloud</span>
            <div className="price">Fleet · compliance · SSO</div>
            <ul>
              <li>Fleet-wide policy &amp; rollout</li>
              <li>Retention + compliance reports</li>
              <li>Approval routing, Slack, RBAC / SSO</li>
              <li>Hosted SaaS · multi-tenancy · SLA</li>
            </ul>
          </div>
        </div>
      </div>
    </section>
  )
}
