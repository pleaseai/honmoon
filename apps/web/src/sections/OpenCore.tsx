export function OpenCore() {
  return (
    <section className="section lp" id="open-core">
      <div className="container">
        <div className="lp-mini">
          <p className="eyebrow"><span className="ix">05</span>Open core</p>
          <h2>Open source for a single node. Built to scale across a fleet.</h2>
        </div>
        <div className="oc-grid">
          <div className="panel oc core">
            <span className="oc-tag">◆ OSS core · Apache-2.0</span>
            <div className="price">Free and open source</div>
            <ul>
              <li>Proxy, protocol parsers &amp; CEL policy engine</li>
              <li>Single-node YAML policy</li>
              <li>Local audit log + dashboard</li>
              <li>Basic approval for <code className="meta" style={{ color: 'inherit' }}>pause</code>d calls</li>
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
