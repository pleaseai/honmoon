export function Modes() {
  return (
    <section className="section lp" id="modes">
      <div className="container">
        <div className="lp-mini">
          <p className="eyebrow"><span className="ix">04</span>Operating modes</p>
          <h2>One process, or a whole fleet.</h2>
        </div>
        <div className="mode-rows">
          <div className="mode-row"><code>honmoon run -- &lt;cmd&gt;</code><span className="m-n">Process wrapper</span><span className="m-w">one agent, one machine</span></div>
          <div className="mode-row"><code>honmoon gateway --config p.yaml</code><span className="m-n">Gateway</span><span className="m-w">a shared, always-on barrier</span></div>
          <div className="mode-row"><code>honmoon join --gateway host</code><span className="m-n">Join</span><span className="m-w">a fleet behind one gateway</span></div>
        </div>
      </div>
    </section>
  )
}
