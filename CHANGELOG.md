# Changelog

## [0.1.1](https://github.com/pleaseai/honmoon/compare/v0.1.0...v0.1.1) (2026-09-16)


### Bug Fixes

* **proxy:** bound the egress head read by supplying hyper a timer ([#273](https://github.com/pleaseai/honmoon/issues/273)) ([5f3b7dd](https://github.com/pleaseai/honmoon/commit/5f3b7ddacaa19301bb50f1c02dc674ba8f90d59c)), closes [#267](https://github.com/pleaseai/honmoon/issues/267)
* **proxy:** escape a space or '=' tag byte out of an unquoted log field ([#277](https://github.com/pleaseai/honmoon/issues/277)) ([85e5d51](https://github.com/pleaseai/honmoon/commit/85e5d5105b1a41def986615f97e1f2d5779e1e86))

## 0.1.0 (2026-09-15)


### ⚠ BREAKING CHANGES

* **core:** `Policy::from_yaml` now returns `Error::UncompilableRuleConditions` for a rule whose `condition` the CEL compiler rejects. A gateway whose policy carries such a rule started yesterday and does not start today.
* **mgmt:** the browser credential is the X-Honmoon-Session header, not the honmoon_session cookie, and pub const SESSION_COOKIE is now SESSION_HEADER. Any session a browser still holds from 0.1.0 also ends on upgrade: the session secret's derivation key is now honmoon-mgmt-session-v2, because 0.1.0 minted the cookie from the same derivation keyed v1 — a value byte-identical to what the new header accepts, so without the bump a cookie harvested before an upgrade would have replayed in the new header afterwards and bridged the hole this change closes. Recovery is one visit to the printed login URL.
* **mgmt:** require the management token on every management API route ([#186](https://github.com/pleaseai/honmoon/issues/186))

### Features

* **audit:** record a degraded redaction key instead of only announcing it ([#137](https://github.com/pleaseai/honmoon/issues/137)) ([27d79a4](https://github.com/pleaseai/honmoon/commit/27d79a4e975b364c9a7ed5fbff5650cf9208bfbf)), closes [#131](https://github.com/pleaseai/honmoon/issues/131)
* **ci:** tag-triggered release workflow with prebuilt binaries for v0.1.0 ([#78](https://github.com/pleaseai/honmoon/issues/78)) ([70593ba](https://github.com/pleaseai/honmoon/commit/70593bab4612a816c0424ca58a0bf39195f70dbc))
* **claude-plugin:** add Claude Code function-hooks module with fail-closed redaction ([#90](https://github.com/pleaseai/honmoon/issues/90)) ([b101c10](https://github.com/pleaseai/honmoon/commit/b101c10219d265b6a41d04b9b9399e141a94c9fe))
* **cli,plugin:** hook-based secret/PII redaction for Claude Code transcripts ([#27](https://github.com/pleaseai/honmoon/issues/27)) ([c078133](https://github.com/pleaseai/honmoon/commit/c078133862358ab4ea3cd13662bf58153991a0fd))
* **cli:** check a policy without starting a gateway ([#201](https://github.com/pleaseai/honmoon/issues/201)) ([99cdd86](https://github.com/pleaseai/honmoon/commit/99cdd867e27b1256a12bc40061fef15fe429c34b))
* **cli:** enforce `honmoon run` isolation with a Seatbelt profile on macOS (ADR-0005) ([#73](https://github.com/pleaseai/honmoon/issues/73)) ([3ea2879](https://github.com/pleaseai/honmoon/commit/3ea2879f21c6d310fd3b09aef174d2602af5fb86))
* **cli:** enforce `honmoon run` isolation with an empty netns on Linux (ADR-0005) ([#71](https://github.com/pleaseai/honmoon/issues/71)) ([df6957c](https://github.com/pleaseai/honmoon/commit/df6957c94a7ce84e2c8cb57529d7a71af68757e8))
* **cli:** name the filter that shows stall diagnostics at startup ([#241](https://github.com/pleaseai/honmoon/issues/241)) ([36a214b](https://github.com/pleaseai/honmoon/commit/36a214b38eecdb8b5988ee49ed087b0e0b4943d0))
* **cli:** warn that `honmoon run` is advisory, and design enforced isolation (ADR-0004/0005) ([#70](https://github.com/pleaseai/honmoon/issues/70)) ([632098a](https://github.com/pleaseai/honmoon/commit/632098a74787e346c3c92615262545d6ac7e3123))
* **core:** Phase 2 — CEL policy engine + HTTP facts ([#2](https://github.com/pleaseai/honmoon/issues/2)) ([ad2fc39](https://github.com/pleaseai/honmoon/commit/ad2fc3976ce37ea9bfeeb55309bffe616eb27865))
* **core:** refuse to load a policy whose rule condition does not compile ([#197](https://github.com/pleaseai/honmoon/issues/197)) ([2c10a8d](https://github.com/pleaseai/honmoon/commit/2c10a8d74be8b9b0645a1c92288da0e6a67f84f0)), closes [#191](https://github.com/pleaseai/honmoon/issues/191)
* **core:** reversible secret tokenization primitive ([#15](https://github.com/pleaseai/honmoon/issues/15)) ([5777da2](https://github.com/pleaseai/honmoon/commit/5777da2f76de7cb09606c9241b33135623a122b7))
* **core:** Tier-1 deterministic PII detector (Phase 5 M1) ([#9](https://github.com/pleaseai/honmoon/issues/9)) ([95cf912](https://github.com/pleaseai/honmoon/commit/95cf9121279c20fb1a1e4956a9cefba2e0bf53e8))
* **core:** warn when an unconditional rule shadows later rules ([#152](https://github.com/pleaseai/honmoon/issues/152)) ([c45036c](https://github.com/pleaseai/honmoon/commit/c45036c8b32bcb3372272b169410e6fcec2b00c5))
* **dashboard:** apply G2 Barrier Membrane redesign to all routes ([#75](https://github.com/pleaseai/honmoon/issues/75)) ([778d87a](https://github.com/pleaseai/honmoon/commit/778d87a31f61de2a2d845e9b6ef12677de0da10b))
* **dashboard:** fixture-backed demo on Cloudflare Pages + hash routing ([#65](https://github.com/pleaseai/honmoon/issues/65)) ([47587c5](https://github.com/pleaseai/honmoon/commit/47587c532cdf1ad48febb7e8fe3783a4482949f2))
* honmoon hook CLI + /api/hooks/claude-code hook transports ([#53](https://github.com/pleaseai/honmoon/issues/53)) ([d3e37f0](https://github.com/pleaseai/honmoon/commit/d3e37f039bbe739080961351fcde372dfa17c8d9))
* **mgmt:** bound what a script in the dashboard origin can do, not just who may frame it ([#199](https://github.com/pleaseai/honmoon/issues/199)) ([4a33c05](https://github.com/pleaseai/honmoon/commit/4a33c050e80b2364b52699a010aeb6ec5df2f20b))
* **mgmt:** hand the dashboard an origin-scoped session secret, not a harvestable cookie ([#194](https://github.com/pleaseai/honmoon/issues/194)) ([0e8c91a](https://github.com/pleaseai/honmoon/commit/0e8c91a822f424171e2fa1975cb39ea7142e5272)), closes [#188](https://github.com/pleaseai/honmoon/issues/188)
* **mgmt:** require the management token on every management API route ([#186](https://github.com/pleaseai/honmoon/issues/186)) ([adbfac7](https://github.com/pleaseai/honmoon/commit/adbfac73e7ff839b49a1e3974f863070cd5d4874))
* Phase 1 HTTP egress MVP + CI/Codecov + eslint-config ([#1](https://github.com/pleaseai/honmoon/issues/1)) ([cb0c8c5](https://github.com/pleaseai/honmoon/commit/cb0c8c5cba7ca04013c59f139bc966ea0679d9e0))
* Phase 3 — SQL/K8s protocol parsers ([#3](https://github.com/pleaseai/honmoon/issues/3)) ([e5130ce](https://github.com/pleaseai/honmoon/commit/e5130ce0d23c7925d8346574f2abf0954075c8a5))
* Phase 4 — pause verdict, audit log & embedded dashboard ([#6](https://github.com/pleaseai/honmoon/issues/6)) ([b87b49c](https://github.com/pleaseai/honmoon/commit/b87b49c79a1bf1a54eda59ead42112123ed621c0))
* **policy:** endpoints map and Kubernetes facts on the HTTPS MITM path ([#88](https://github.com/pleaseai/honmoon/issues/88)) ([2708519](https://github.com/pleaseai/honmoon/commit/27085197e137c91dee57701563a9d893c59edf4c))
* **proxy:** block or fail open on body-signed requests under wire redaction ([#80](https://github.com/pleaseai/honmoon/issues/80)) ([9694f56](https://github.com/pleaseai/honmoon/commit/9694f56a06f94008bda8a31fe861d07041760483))
* **proxy:** decode gzip/deflate bodies before PII inspection ([#13](https://github.com/pleaseai/honmoon/issues/13)) ([e55ec50](https://github.com/pleaseai/honmoon/commit/e55ec507219020db0d252586d1f330302f9b0621))
* **proxy:** enforcing PII mode — deny/pause on pii facts ([#52](https://github.com/pleaseai/honmoon/issues/52)) ([aba06e5](https://github.com/pleaseai/honmoon/commit/aba06e55820e69b92165d61c1e291a6971d0a530))
* **proxy:** say which tag left the flush unsettled when a refusal stalls ([#247](https://github.com/pleaseai/honmoon/issues/247)) ([ac33b76](https://github.com/pleaseai/honmoon/commit/ac33b76f47657762c3e7f499a1a2ad371025d91b)), closes [#214](https://github.com/pleaseai/honmoon/issues/214)
* **proxy:** SOCKS5 listener and inline PostgreSQL protocol runtime ([#89](https://github.com/pleaseai/honmoon/issues/89)) ([a87b303](https://github.com/pleaseai/honmoon/commit/a87b3034e818876d151ed4e30333d1af1ae2442a))
* **proxy:** TLS termination via hudsucker for content-aware PII (Phase 5) ([#11](https://github.com/pleaseai/honmoon/issues/11)) ([9679a9e](https://github.com/pleaseai/honmoon/commit/9679a9e471d5e68f12d82e565c5ba3f0ad336d9b))
* **proxy:** tokenize secrets on the wire with cache-stable determinism ([#56](https://github.com/pleaseai/honmoon/issues/56)) ([8731c22](https://github.com/pleaseai/honmoon/commit/8731c225c28c0d23eda7bac65e6da2fb85e30a5a))
* **scripts:** follow the emitted module graph in the dashboard bundle guard ([#231](https://github.com/pleaseai/honmoon/issues/231)) ([5af5dcf](https://github.com/pleaseai/honmoon/commit/5af5dcfa724db3792b5d2c89c210c3266eba2f1d)), closes [#227](https://github.com/pleaseai/honmoon/issues/227)
* **web:** Honmoon 마케팅 랜딩페이지 (apps/web) ([#18](https://github.com/pleaseai/honmoon/issues/18)) ([0445656](https://github.com/pleaseai/honmoon/commit/04456569f2fba96585d16ab3bdb8fc780daa9c12))
* **web:** refresh landing copy to the v5 wording ([#107](https://github.com/pleaseai/honmoon/issues/107)) ([91778d8](https://github.com/pleaseai/honmoon/commit/91778d87fc43ab4c31d756f4121ed87e224c0004))


### Bug Fixes

* **agent-memory:** generate the per-agent memory index instead of tracking it ([#156](https://github.com/pleaseai/honmoon/issues/156)) ([bdfd924](https://github.com/pleaseai/honmoon/commit/bdfd9241e38418b365f7226bc25342ef2a803be0)), closes [#129](https://github.com/pleaseai/honmoon/issues/129)
* **cli:** refuse a mapping that declares no policy field ([#239](https://github.com/pleaseai/honmoon/issues/239)) ([25394e5](https://github.com/pleaseai/honmoon/commit/25394e57ba5b02d1f8f7b6808c95474b39dfad5e))
* **cli:** withhold a non-policy file's contents from every command that reads one ([#217](https://github.com/pleaseai/honmoon/issues/217)) ([d24dabf](https://github.com/pleaseai/honmoon/commit/d24dabff73f655bd7f265bc1f2ae0b6c31ae0bc0)), closes [#202](https://github.com/pleaseai/honmoon/issues/202)
* **core:** bound MappingStore retention with recency-based eviction ([#59](https://github.com/pleaseai/honmoon/issues/59)) ([3dd3d0d](https://github.com/pleaseai/honmoon/commit/3dd3d0d664cf2e2ad7bc40cc1ff6061e7285a300))
* **core:** harden the operator-supplied audit sink open ([#163](https://github.com/pleaseai/honmoon/issues/163)) ([1937e33](https://github.com/pleaseai/honmoon/commit/1937e3363350b934df25cc9154f5cef03ebf1387)), closes [#138](https://github.com/pleaseai/honmoon/issues/138)
* **core:** migrate to cel 0.14, closing the CEL compile panic class ([#164](https://github.com/pleaseai/honmoon/issues/164)) ([eed055c](https://github.com/pleaseai/honmoon/commit/eed055c1c51f78ac0f41e8f03ff024e594d4227e))
* **core:** refuse a symlinked audit-path parent whose macOS ACL hides who can write ([#213](https://github.com/pleaseai/honmoon/issues/213)) ([d00b576](https://github.com/pleaseai/honmoon/commit/d00b576c4f7c89ec57d19ce0f156e7d548d8e6ca))
* **core:** reject a blank rule condition instead of panicking on it ([#155](https://github.com/pleaseai/honmoon/issues/155)) ([3ff34bd](https://github.com/pleaseai/honmoon/commit/3ff34bdc83c3d640707d03ad543626d0b0f5e793)), closes [#151](https://github.com/pleaseai/honmoon/issues/151)
* **core:** report an audit sink reachable beyond its owner instead of leaving it silent ([#183](https://github.com/pleaseai/honmoon/issues/183)) ([7d0e363](https://github.com/pleaseai/honmoon/commit/7d0e363dec2abf5db78e7ce433aee400cab64345))
* **core:** walk the audit sink path refusing a symlink at every component ([#179](https://github.com/pleaseai/honmoon/issues/179)) ([6c47f99](https://github.com/pleaseai/honmoon/commit/6c47f994ee6a8a1b20786994d16119c17d429a5c))
* **hook:** derive the management hook salt from the payload's session ([#122](https://github.com/pleaseai/honmoon/issues/122)) ([997d799](https://github.com/pleaseai/honmoon/commit/997d79993465b9ab69f71248a5b2394b706e5568))
* **hook:** record a readable-but-unrestrictable salt as a degraded key ([#142](https://github.com/pleaseai/honmoon/issues/142)) ([c8c3994](https://github.com/pleaseai/honmoon/commit/c8c39945683137c4ff87dc701713881dcb15ed75))
* **hook:** record a salt found loose and successfully tightened ([#170](https://github.com/pleaseai/honmoon/issues/170)) ([94a3713](https://github.com/pleaseai/honmoon/commit/94a37131190625f9c97564e1524c1c02f24e0399))
* **hook:** record the salt file a failed read replaces unseen ([#185](https://github.com/pleaseai/honmoon/issues/185)) ([d5069db](https://github.com/pleaseai/honmoon/commit/d5069db16f27f9c4ec2a33572e1cfcf89cb02ae2))
* **hook:** report a refused audit sink on the hook response ([#182](https://github.com/pleaseai/honmoon/issues/182)) ([3f117ce](https://github.com/pleaseai/honmoon/commit/3f117cee02de3b233f2e4e334b641ca8ab376ea9))
* **hook:** resolve the salt path before it reaches the audit record ([#174](https://github.com/pleaseai/honmoon/issues/174)) ([2c5cf57](https://github.com/pleaseai/honmoon/commit/2c5cf570fcf068bba03b2050a58fb2f74dda6c08))
* **mgmt:** harden HTTP hook transport against agent-relative symlink paths ([#60](https://github.com/pleaseai/honmoon/issues/60)) ([9cb18b4](https://github.com/pleaseai/honmoon/commit/9cb18b45e7685e1ee787d4f27829b0d7c383aa5d))
* mint the management token under a single-winner lock ([#255](https://github.com/pleaseai/honmoon/issues/255)) ([bf9b057](https://github.com/pleaseai/honmoon/commit/bf9b0570b3f6c84594a4ab6744b47ce24b5d0706)), closes [#189](https://github.com/pleaseai/honmoon/issues/189)
* **policy:** attribute PII-caused verdicts per rule in detect mode ([#108](https://github.com/pleaseai/honmoon/issues/108)) ([cc87a4f](https://github.com/pleaseai/honmoon/commit/cc87a4f2819060be9124069e25d0bcb06f235250))
* **proxy:** cancel an approval hold when the paused postgres client disconnects ([#109](https://github.com/pleaseai/honmoon/issues/109)) ([9c6624a](https://github.com/pleaseai/honmoon/commit/9c6624acad64867efe97f867f1aff819543d1e7c)), closes [#102](https://github.com/pleaseai/honmoon/issues/102)
* **proxy:** drop trailer fields forbidden in a trailer section ([#175](https://github.com/pleaseai/honmoon/issues/175)) ([9286f6a](https://github.com/pleaseai/honmoon/commit/9286f6ada34202fc63a446cf983e52b600d65c92)), closes [#134](https://github.com/pleaseai/honmoon/issues/134)
* **proxy:** order an injected postgres refusal behind earlier responses ([#112](https://github.com/pleaseai/honmoon/issues/112)) ([47ea8d4](https://github.com/pleaseai/honmoon/commit/47ea8d41ab7a29d9ca5bc417424361c4ab9abf29))
* **proxy:** order an injected refusal behind a Flush-driven batch ([#147](https://github.com/pleaseai/honmoon/issues/147)) ([4fb15ed](https://github.com/pleaseai/honmoon/commit/4fb15ed27efdf74149c0b70cae99f953a4b65ae8))
* **proxy:** preserve request trailers through the buffered forward path ([#130](https://github.com/pleaseai/honmoon/issues/130)) ([023cf54](https://github.com/pleaseai/honmoon/commit/023cf549d5990c6c3e208a16833041a0586a8c1a)), closes [#82](https://github.com/pleaseai/honmoon/issues/82)
* **proxy:** re-arm the refusal stall window on every byte the database sends ([#216](https://github.com/pleaseai/honmoon/issues/216)) ([0775ca0](https://github.com/pleaseai/honmoon/commit/0775ca0609c4558aef35f91be865cfd6276a2aa0)), closes [#209](https://github.com/pleaseai/honmoon/issues/209)
* **proxy:** re-frame a request so its trailer section survives an h1 upstream ([#180](https://github.com/pleaseai/honmoon/issues/180)) ([879d303](https://github.com/pleaseai/honmoon/commit/879d3034c010da7c130ca3dcf0ba6a90115eadef))
* **proxy:** require payload-covering evidence for a SigV4 body signature ([#120](https://github.com/pleaseai/honmoon/issues/120)) ([f188d56](https://github.com/pleaseai/honmoon/commit/f188d562381cb2b5779b9888658a7e2729cc8588)), closes [#81](https://github.com/pleaseai/honmoon/issues/81)
* **proxy:** scope CONNECT authorization to the accepted connection ([#111](https://github.com/pleaseai/honmoon/issues/111)) ([576b874](https://github.com/pleaseai/honmoon/commit/576b874af7516825647f0656b708d3f531e64f71))
* **proxy:** settle a flush only after a tag that can end a flushed batch ([#212](https://github.com/pleaseai/honmoon/issues/212)) ([89045f8](https://github.com/pleaseai/honmoon/commit/89045f844927a482eb08bde8ac966f445648ba31)), closes [#211](https://github.com/pleaseai/honmoon/issues/211)
* **proxy:** take the signed-body decision for signature-covered framing headers ([#115](https://github.com/pleaseai/honmoon/issues/115)) ([30a21d0](https://github.com/pleaseai/honmoon/commit/30a21d03a16e54d611ad3439f0928f724ebcf6f8))
* **proxy:** take the signed-header decision on stripped body digests too ([#146](https://github.com/pleaseai/honmoon/issues/146)) ([31d5b48](https://github.com/pleaseai/honmoon/commit/31d5b4814a8abf8f5eabf9a814ad0b1a3c8b6db5)), closes [#116](https://github.com/pleaseai/honmoon/issues/116)
* **proxy:** warn when an oversized-payload copy goes quiet mid-frame ([#225](https://github.com/pleaseai/honmoon/issues/225)) ([e37dccd](https://github.com/pleaseai/honmoon/commit/e37dccdefb82ff53767d65c0d2db8d9d15f2ca64)), closes [#218](https://github.com/pleaseai/honmoon/issues/218)
* **proxy:** warn when the client stops taking an oversized payload mid-frame ([#236](https://github.com/pleaseai/honmoon/issues/236)) ([4a2a282](https://github.com/pleaseai/honmoon/commit/4a2a282ef59cbdf2077eb947e8baba85585a2b80))
* **release:** publish the GitHub Release only after its binaries upload ([#237](https://github.com/pleaseai/honmoon/issues/237)) ([3561465](https://github.com/pleaseai/honmoon/commit/35614650159e8fb87dd606820217d8379e692886)), closes [#230](https://github.com/pleaseai/honmoon/issues/230)
* **scripts:** bound the dashboard guards on the real path, not the specifier ([#249](https://github.com/pleaseai/honmoon/issues/249)) ([1804989](https://github.com/pleaseai/honmoon/commit/18049897ba620f3e331e5683fc037bad64dd2b79))
* **scripts:** look the named references up in a Map, not down a prototype chain ([#235](https://github.com/pleaseai/honmoon/issues/235)) ([d68a646](https://github.com/pleaseai/honmoon/commit/d68a6468ba7521c4c4b356346738712eee832837)), closes [#226](https://github.com/pleaseai/honmoon/issues/226)


### Performance Improvements

* **core:** compile CEL rule conditions once at policy load ([#193](https://github.com/pleaseai/honmoon/issues/193)) ([d6fedb2](https://github.com/pleaseai/honmoon/commit/d6fedb22e0471c82d819f8a2dee7d187c664195d))
* **web:** render membrane nebula at 1/4 resolution to kill load jank ([#29](https://github.com/pleaseai/honmoon/issues/29)) ([84e340c](https://github.com/pleaseai/honmoon/commit/84e340c7802986d3fd2d0fdac3cb58c14c62b68c))
