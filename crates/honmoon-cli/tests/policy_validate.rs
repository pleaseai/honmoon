//! `honmoon policy validate` — the load-and-exit check (#198) — plus the
//! no-quoting claim it shares with every other command that reads a policy from
//! a path (#201, then #202).
//!
//! Four claims are asserted against the *shipped binary* rather than the
//! loader, because all four are about what running a command does rather
//! than about what `Policy::from_yaml` returns:
//!
//! 1. The exit code is the interface. Zero on a policy the gateway would
//!    accept, non-zero on one it would refuse, with every offending rule named
//!    on stderr — this runs in CI, where nobody reads prose.
//! 2. Checking a policy has **no side effects**. `honmoon gateway` resolves the
//!    management token before it loads the policy, so today the only way to
//!    find out whether a policy is acceptable can create `$HOME/.honmoon` —
//!    including on the run where the policy is what fails. The control below
//!    runs the gateway on the same bad file under its own `HOME` and shows it
//!    doing exactly that, so "validate created nothing" is measured against a
//!    path that demonstrably does.
//! 3. The two paths cannot drift. `validate` accepting a policy the gateway
//!    then refuses would make the command worse than useless, so both are run
//!    on one bad file and required to report the same thing.
//! 4. No command prints the file it was pointed at. A path that resolves to
//!    something other than a policy has to be named, not quoted, and that is a
//!    property of the shared read rather than of any one subcommand — so it is
//!    asserted for `policy validate`, `run --policy` and, on Unix, for
//!    `gateway --config`, which cannot reach the read on a host where it cannot
//!    mint a management token (the same gating claims 2 and 3 carry). It lives
//!    here because this is where the harness for running the binary under a
//!    scratch `HOME` already is.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn honmoon() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_honmoon"))
}

/// A scratch `HOME` a subprocess can write into, removed when the test ends.
///
/// Hand-rolled rather than pulled from a crate: a new workspace dependency is
/// an "ask first" change in `crates/AGENTS.md`, and `tests/hook_transports.rs`
/// already solves this the same way.
///
/// Uniqueness is derived, not entrusted to the caller. `process::id()` alone
/// does not separate two tests — libtest runs the whole binary in one process,
/// on threads — so the thread name carries it, which libtest sets to the test
/// function's own name. `label` then only has to be unique *within* one test,
/// which is the scope a reader can actually check. Get it wrong and two
/// `TempHome`s share a directory, one of them deleting the other's `HOME`
/// mid-run: a flaky failure a long way from its cause.
struct TempHome(PathBuf);

impl TempHome {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "honmoon-policy-validate-{}-{}-{label}",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create the scratch HOME");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    /// The directory honmoon persists local material in, under this `HOME`.
    fn honmoon_dir(&self) -> PathBuf {
        self.0.join(".honmoon")
    }

    fn write_policy(&self, name: &str, yaml: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, yaml).expect("write the policy fixture");
        path
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Run the binary with a scratch `HOME` and an environment that cannot leak the
/// developer's own settings in.
///
/// `HONMOON_MGMT_TOKEN` / `HONMOON_HOOK_TOKEN` are removed because clap reads
/// them: with either set, the gateway control would resolve an operator token
/// and never write the file whose absence this suite is about. `RUST_LOG` is
/// removed because these tests assert what an ordinary run prints.
fn run(home: &TempHome, args: &[&str]) -> Output {
    Command::new(honmoon())
        .args(args)
        .env("HOME", home.path())
        .env_remove("HONMOON_MGMT_TOKEN")
        .env_remove("HONMOON_HOOK_TOKEN")
        .env_remove("RUST_LOG")
        .output()
        .expect("run the honmoon binary")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A policy the gateway loads. The endpoint name and host are distinctive so
/// the output can be searched for them.
const GOOD_POLICY: &str = r#"
version: 1
egress:
  default: deny
  allow:
    - github.com
endpoints:
  crown-jewels: {host: jewels.internal, port: 5432, protocol: postgres}
rules:
  - name: sql-no-drop
    endpoint: crown-jewels
    condition: "sql.verb == 'DROP'"
    verdict: deny
"#;

/// An address no interface owns, used to stop a `gateway` run that got past
/// the policy.
///
/// `gateway` on a policy it accepts serves until interrupted, so "it exits 0"
/// is not a thing a test can wait for. Binding is the first step after the
/// load, though, so a bind that cannot succeed turns "the policy was accepted"
/// into an immediate exit — no port taken, no process left running, and the
/// error names which of the two stages it reached.
///
/// It has to be an IP literal to be that. A hostname would send `bind` through
/// `getaddrinfo` first, which is a resolver round trip this test would then
/// depend on: measured at ~1.5s here even with a resolver answering, a stall
/// for the lookup timeout where one does not, and — if something ever answered
/// for the name with an address this host owns — a gateway that binds, serves,
/// and hangs the suite, because nothing here puts a timeout on a child.
/// `192.0.2.1` is TEST-NET-1 (RFC 5737): reserved for documentation, so no
/// interface carries it and `bind` fails locally with `EADDRNOTAVAIL` in ~25ms,
/// having asked nothing outside the kernel.
const UNBINDABLE_ADDR: &str = "192.0.2.1:8443";

/// Three rules the CEL compiler rejects, so "every one of them" has something
/// to mean.
const THREE_BAD_RULES: &str = r#"
version: 1
egress:
  default: deny
rules:
  - name: first-bad
    endpoint: '*'
    condition: "&&"
    verdict: deny
  - name: second-bad
    endpoint: '*'
    condition: "@"
    verdict: deny
  - name: third-bad
    endpoint: '*'
    condition: "http.method =="
    verdict: deny
"#;

#[test]
fn a_policy_the_gateway_would_accept_exits_zero_without_echoing_it() {
    let home = TempHome::new("good");
    let policy = home.write_policy("good.yaml", GOOD_POLICY);

    let output = run(&home, &["policy", "validate", policy.to_str().unwrap()]);

    assert!(
        output.status.success(),
        "a policy the gateway loads must validate; stderr: {}",
        stderr(&output)
    );
    // Pinned for the same reason the bad-policy test pins its rule name: exit 0
    // is also what a `policy_validate` that never called the loader would
    // return, and the counts can only come from a policy that parsed.
    assert!(
        stderr(&output).contains("policy is valid (1 rules, 1 endpoints)"),
        "the run must have reached the loader and counted what it loaded; got: {}",
        stderr(&output)
    );
    // The no-side-effect property is not conditioned on the verdict — the
    // rejected path is checked below, and this is the accepted one.
    assert!(
        !home.honmoon_dir().exists(),
        "an accepted policy must not write anything either"
    );
    let printed = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        !printed.contains("crown-jewels") && !printed.contains("jewels.internal"),
        "validating a good policy must not echo its contents — a CI log is not \
         the place for an operator's endpoint names; got: {printed}"
    );
}

#[test]
fn a_policy_the_gateway_would_refuse_exits_non_zero_naming_every_bad_rule() {
    let home = TempHome::new("bad");
    let policy = home.write_policy("bad.yaml", THREE_BAD_RULES);

    let output = run(&home, &["policy", "validate", policy.to_str().unwrap()]);

    assert!(
        !output.status.success(),
        "a policy the gateway refuses must fail the check"
    );
    let stderr = stderr(&output);
    for rule in ["first-bad", "second-bad", "third-bad"] {
        assert!(
            stderr.contains(rule),
            "every offending rule must be named, not just the first — \
             `{rule}` is missing from: {stderr}"
        );
    }
    assert!(
        stdout(&output).is_empty(),
        "diagnostics belong on stderr; stdout must stay clean for CI"
    );
}

/// The point of the command, and the reason it is not merely a convenience.
#[test]
fn validating_a_bad_policy_creates_nothing_under_home() {
    let home = TempHome::new("no-side-effects");
    let policy = home.write_policy("bad.yaml", THREE_BAD_RULES);

    let output = run(&home, &["policy", "validate", policy.to_str().unwrap()]);
    assert!(!output.status.success(), "the policy is bad");
    // Pinned so the claim below cannot pass by the command never having checked
    // anything: a binary with no such subcommand also exits non-zero and also
    // creates nothing.
    assert!(
        stderr(&output).contains("first-bad"),
        "the run must have reached the loader; got: {}",
        stderr(&output)
    );

    assert!(
        !home.honmoon_dir().exists(),
        "checking a policy must not touch {} — a run whose only purpose was to \
         find out whether a policy is acceptable has no business minting a \
         credential, least of all on the run where the policy is what failed",
        home.honmoon_dir().display()
    );

    // The control: the same bad policy through the only path that exists today.
    // Without it "nothing was created" could just mean nothing ever is.
    //
    // Unix-only, because minting is: `mgmt_token::random_bytes` reads
    // `/dev/urandom` and its `cfg(not(unix))` twin refuses outright rather than
    // invent a credential, so on a non-Unix host `gateway` fails *at* token
    // resolution and never reaches the policy. That leaves nothing for the
    // control to demonstrate there. The claim above is not gated with it: it is
    // about what `validate` does, it holds on every platform, and the
    // `first-bad` assertion is what keeps it from passing vacuously.
    #[cfg(unix)]
    {
        let control = TempHome::new("gateway-control");
        let control_policy = control.write_policy("bad.yaml", THREE_BAD_RULES);
        let gateway = run(
            &control,
            &["gateway", "--config", control_policy.to_str().unwrap()],
        );
        assert!(
            !gateway.status.success(),
            "the gateway refuses this policy too"
        );
        assert!(
            control.honmoon_dir().join("mgmt-token").exists(),
            "the control must show the side effect being avoided: `honmoon gateway` \
             resolves the management token before it loads the policy, so it mints \
             one even on the run the policy fails. If this ever stops holding, the \
             assertion above stops measuring anything."
        );
    }
}

/// A `validate` that accepted what the gateway refuses would be worse than
/// nothing, so both are run on one file and required to agree.
///
/// Unix-only for the reason the control above is: on a non-Unix host `gateway`
/// stops at token minting, so it never reaches the loader and there is no
/// second verdict to agree with. Gating beats asserting a weaker claim there —
/// the drift this guards against is in the loader, and a host that cannot run
/// one of the two paths cannot observe it either way.
#[cfg(unix)]
#[test]
fn validate_and_the_gateway_report_the_same_refusal() {
    let validate_home = TempHome::new("drift-validate");
    let gateway_home = TempHome::new("drift-gateway");
    let validate_policy = validate_home.write_policy("bad.yaml", THREE_BAD_RULES);
    let gateway_policy = gateway_home.write_policy("bad.yaml", THREE_BAD_RULES);

    let validated = run(
        &validate_home,
        &["policy", "validate", validate_policy.to_str().unwrap()],
    );
    let started = run(
        &gateway_home,
        &["gateway", "--config", gateway_policy.to_str().unwrap()],
    );

    assert_eq!(
        validated.status.success(),
        started.status.success(),
        "the two paths must reach the same verdict"
    );
    assert!(!validated.status.success());

    // The loader's own message, which both paths surface verbatim because both
    // get it from `Policy::from_yaml` rather than re-deriving a check.
    let clause =
        r#"rule "second-bad" (rules[1]) has a `condition` that is not a valid CEL expression"#;
    assert!(
        stderr(&validated).contains(clause),
        "validate must report the loader's own diagnosis; got: {}",
        stderr(&validated)
    );
    assert!(
        stderr(&started).contains(clause),
        "…and it must be the same one the gateway reports; got: {}",
        stderr(&started)
    );
}

/// The command is documented for CI, where the path it is handed comes from the
/// repository under test. serde quotes a top-level type mismatch — and when the
/// top level is a scalar, what it quotes is the whole file — so a mistyped path,
/// or a branch pointing `policy.yaml` at a credential, would print that file
/// into the log.
#[test]
fn a_file_that_is_not_a_policy_is_named_rather_than_quoted() {
    let home = TempHome::new("not-a-policy");
    // Stands in for whatever the path actually resolved to: a token file, an
    // SSH key, a `.env`. One line, no YAML structure — the shape that makes
    // serde quote the document whole.
    let secret = "ghp_thisisnotapolicyitisacredential";
    let policy = home.write_policy("mistyped.txt", &format!("{secret}\n"));

    let output = run(&home, &["policy", "validate", policy.to_str().unwrap()]);

    assert!(!output.status.success(), "this is not a policy");
    let printed = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        !printed.contains(secret),
        "the file's contents must not reach the log; got: {printed}"
    );
    assert!(
        printed.contains("not a policy document"),
        "…and the operator must be told what is actually wrong; got: {printed}"
    );

    // The gateway refuses the same file. Read for what it still shows, not for
    // what it used to: when #201 put the guard in `policy validate` alone, this
    // was the independent verdict — the gateway reached `Policy::from_yaml`
    // without the guard and refused anyway, so "the guard only changes the
    // wording" was measured rather than asserted. #202 lifted the guard into the
    // read both commands share, so both now run it and neither can witness the
    // other. What survives here is parity of *behaviour* across the two
    // commands; the claim that no verdict moved is checked against the loader
    // directly, in `every_shape_the_guard_refuses_is_one_the_loader_refuses_anyway`
    // (`src/main.rs`).
    #[cfg(unix)]
    {
        let control = TempHome::new("not-a-policy-gateway");
        let control_policy = control.write_policy("mistyped.txt", &format!("{secret}\n"));
        let gateway = run(
            &control,
            &["gateway", "--config", control_policy.to_str().unwrap()],
        );
        assert!(
            !gateway.status.success(),
            "the gateway refuses this file too"
        );
        // Pinned to the stage it reached, like every other gateway control in
        // this file. `honmoon gateway` exits non-zero for plenty of reasons that
        // never reach the policy read — an unwritable scratch HOME, a failed
        // token mint, a renamed flag — so the exit code alone would let this
        // block pass with the guard gone.
        assert!(
            stderr(&gateway).contains("not a policy document"),
            "…and it must have got as far as the guard to refuse it for that \
             reason; got: {}",
            stderr(&gateway)
        );
    }

    // The other edge of the same claim, and the one that caught a real bug: a
    // *tag* does not change what a document is. serde looks through it, so the
    // loader accepts `!Foo {version: 1}` — and a guard that refused every
    // tagged node would refuse a policy the gateway runs, which is this
    // command's worst failure wearing the opposite sign.
    let tagged = home.write_policy("tagged.yaml", "!Foo {version: 1}\n");
    let output = run(&home, &["policy", "validate", tagged.to_str().unwrap()]);
    assert!(
        output.status.success(),
        "a tagged mapping is a mapping — the loader takes it, so this must too; got: {}",
        stderr(&output)
    );

    // The other pass-through arm, and the one two reviewers read backwards: an
    // empty document is a *valid* policy. Every `Policy` field carries
    // `#[serde(default)]`, so a document with no fields in it deserializes to
    // deny-by-default with no rules — `honmoon gateway --config` starts on one.
    // Pinned here because it is the boundary of the guard above: refusing it
    // would refuse a policy the gateway runs.
    let empty = home.write_policy("empty.yaml", "");
    let output = run(&home, &["policy", "validate", empty.to_str().unwrap()]);
    assert!(
        output.status.success(),
        "an empty document is a policy with every field at its default; got: {}",
        stderr(&output)
    );
}

/// The refusal side of parity is the easy half. This is the other one, and it is
/// the worse failure: a `validate` that passed a policy the gateway will not
/// boot on sends an operator to production believing they checked.
///
/// Unix-only for the reason the other parity test is — `gateway` mints a
/// management token before it loads anything, and cannot on a non-Unix host.
#[cfg(unix)]
#[test]
fn validate_and_the_gateway_accept_the_same_policy() {
    let validate_home = TempHome::new("parity-validate");
    let gateway_home = TempHome::new("parity-gateway");
    let validate_policy = validate_home.write_policy("good.yaml", GOOD_POLICY);
    let gateway_policy = gateway_home.write_policy("good.yaml", GOOD_POLICY);

    let validated = run(
        &validate_home,
        &["policy", "validate", validate_policy.to_str().unwrap()],
    );
    assert!(
        validated.status.success(),
        "validate accepts it; stderr: {}",
        stderr(&validated)
    );

    let started = run(
        &gateway_home,
        &[
            "gateway",
            "--config",
            gateway_policy.to_str().unwrap(),
            "--addr",
            UNBINDABLE_ADDR,
        ],
    );
    let stderr = stderr(&started);
    assert!(
        stderr.contains("binding proxy"),
        "the gateway must have got past the loader and failed at the bind — \
         anything about a rule or an endpoint here means it refused a policy \
         `validate` had just accepted, which is the drift that matters most; \
         got: {stderr}"
    );
}

/// A warning is not a refusal: the gateway starts on this policy, so `validate`
/// accepts it. But it is a problem the loader found, and `tracing::warn!` is
/// silent at the binary's default filter — so the check that exists to report
/// what the loader found has to turn it up.
#[test]
fn an_unreachable_rule_is_reported_without_failing_the_check() {
    let home = TempHome::new("shadowed");
    let policy = home.write_policy(
        "shadowed.yaml",
        r#"
version: 1
endpoints:
  db: {host: db.internal, port: 5432, protocol: postgres}
rules:
  - name: postgres-connect
    endpoint: db
    condition: "true"
    verdict: allow
  - name: sql-no-drop
    endpoint: db
    condition: "sql.verb == 'DROP'"
    verdict: deny
"#,
    );

    let output = run(&home, &["policy", "validate", policy.to_str().unwrap()]);

    assert!(
        output.status.success(),
        "an unreachable rule is a warning, not a load failure — the gateway \
         starts on this policy, so the check must accept it too"
    );
    let stderr = stderr(&output);
    assert!(
        stderr.contains("unreachable") && stderr.contains("sql-no-drop"),
        "the shadowed rule must be named; got: {stderr}"
    );
    assert!(
        stdout(&output).is_empty(),
        "the warning belongs on stderr, not in whatever a caller is piping"
    );
}

/// A file whose top level is a plain scalar, in the shape that makes the leak
/// worst: YAML folds the lines of a plain scalar into one, so serde's
/// `invalid type: string "<value>"` carries the *whole* file rather than one
/// line of it.
///
/// Not a real key. The body lines are base64 — they have to be, or the file
/// would not read as a PEM — but they decode to `not-a-key-just-a-fixture-…`
/// rather than to a DER key. The shape is what matters: no YAML structure,
/// several lines, and a first line that is itself a disclosure.
///
/// The test searches for *every* line, including the two `-----BEGIN/END-----`
/// markers. Those are boilerplate rather than distinctive, and they are asserted
/// anyway on purpose: the marker is the first thing a reader of a leaked log
/// sees, and it is what tells them a key was printed. Do not trim the fixture to
/// its "interesting" lines.
const NOT_A_POLICY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
bm90LWEta2V5LWp1c3QtYS1maXh0dXJlLWZpcnN0LWxpbmU
bm90LWEta2V5LWp1c3QtYS1maXh0dXJlLXNlY29uZC1saW5l
-----END PRIVATE KEY-----
";

/// The same file with a second YAML document after it — the shape that defeated
/// the first version of this fix, and the reason the guard reads one document
/// rather than the stream.
///
/// `serde_yaml::from_str::<Value>` refuses a multi-document stream instead of
/// returning its first document, so a guard that classified the stream deferred
/// every file carrying a `---` line to the loader. The loader deserializes the
/// first document *before* it notices the second, so the key came back out — on
/// all three commands, past a guard whose whole purpose was to stop exactly that.
/// A `.env`, a Kubernetes manifest and a `helm` values file all routinely carry a
/// `---` line, so this is not a contrived shape.
const NOT_A_POLICY_MULTIDOC: &str = "\
-----BEGIN PRIVATE KEY-----
bm90LWEta2V5LWp1c3QtYS1maXh0dXJlLWZpcnN0LWxpbmU
bm90LWEta2V5LWp1c3QtYS1maXh0dXJlLXNlY29uZC1saW5l
-----END PRIVATE KEY-----
---
also: not a policy
";

/// #202: the exposure is the *read*, not the command.
///
/// `policy validate` was fixed first (#201) because it is the documented CI
/// path, where the file a mistyped `policy.yaml` resolves to belongs to the
/// repository under test. It was the only one fixed, and the other two printed
/// the file whole: `honmoon run --policy` through `load_policy`, and
/// `honmoon gateway --config` through its own inlined read. Operator-interactive
/// is not the same as read by one person — a supervisor ships stderr to a
/// journal or a log aggregator, which is the exposure with a different audience,
/// and the same reasoning the management-token banner already follows when it
/// declines to print a credential to a pipe.
///
/// Asserted as an absence, because that is the security property: the content
/// must not be in the output. Naming the problem is asserted alongside it so the
/// absence cannot be satisfied by a command that says nothing useful.
#[test]
fn no_command_that_loads_a_policy_by_path_quotes_the_file() {
    for (fixture, name, contents) in [
        ("one document", "mistyped.pem", NOT_A_POLICY_PEM),
        (
            "two documents",
            "mistyped-multidoc.pem",
            NOT_A_POLICY_MULTIDOC,
        ),
    ] {
        no_command_quotes(fixture, name, contents);
    }
}

/// The body of the test above, run once per fixture.
///
/// A fresh `TempHome` per fixture, because `gateway` writes a management token
/// into it and the label is what keeps two of them apart.
fn no_command_quotes(fixture: &str, name: &str, contents: &str) {
    let home = TempHome::new(&format!("path-leak-{}", name));
    let mistyped = home.write_policy(name, contents);
    let path = mistyped.to_str().unwrap();

    let commands = vec![
        ("policy validate", vec!["policy", "validate", path]),
        // `run` loads the policy as its first step — before it binds a port or
        // spawns anything — so the command after `--` is never reached and needs
        // to be no more than a placeholder.
        ("run --policy", vec!["run", "--policy", path, "--", "true"]),
        // `gateway` resolves a management token before it reads the policy, and
        // minting one reads `/dev/urandom`; on a non-Unix host it refuses
        // outright, so the run never reaches the loader and there is nothing
        // here to observe. Gated for the reason the other gateway controls in
        // this file are.
        #[cfg(unix)]
        ("gateway --config", vec!["gateway", "--config", path]),
    ];

    for (label, args) in commands {
        let output = run(&home, &args);
        assert!(
            !output.status.success(),
            "`{label}` must refuse a file that is not a policy ({fixture})"
        );
        let printed = format!("{}{}", stdout(&output), stderr(&output));
        for line in contents.lines() {
            assert!(
                !printed.contains(line),
                "`{label}` put the file's contents in its error ({fixture}) — \
                 the line {line:?} is in: {printed}"
            );
        }
        assert!(
            printed.contains("not a policy document"),
            "`{label}` must say what is actually wrong ({fixture}); got: {printed}"
        );
    }
}

/// #220: a mapping is a policy's *shape*, which is not the same as being one.
///
/// Every `Policy` field carries `#[serde(default)]` and the struct has no
/// `deny_unknown_fields`, so any mapping deserialized into a policy with every
/// field at its default. These three files are the ones the issue measured, and
/// all three exited 0 with `policy is valid (0 rules, 0 endpoints)` — the
/// opposite failure to #202's, and the worse one: #202 said too much about a
/// file it refused, this said nothing at all about a file it took. Under
/// `gateway --config` the text then reached `AppState.policy_yaml` and was
/// served at `GET /api/policy`.
///
/// Run over all three commands for the reason `no_command_quotes` is: the file a
/// mistyped path resolves to is the same file whichever flag named it, and the
/// rule lives in the read they share.
///
/// The no-quoting claim rides along rather than being assumed. A refusal that
/// named the offending keys would be a new disclosure on the same files these
/// fixtures stand in for — the key names of a secrets file are not its values,
/// but `AWS_SECRET_ACCESS_KEY` in a CI log is still a fact about that host.
#[test]
fn no_command_accepts_a_mapping_that_declares_no_policy_field() {
    for (fixture, name, contents) in [
        (
            "a Kubernetes Secret",
            "secret.yaml",
            NOT_A_POLICY_K8S_SECRET,
        ),
        (
            "a colon-style secrets file",
            "creds.yaml",
            NOT_A_POLICY_DOTENV,
        ),
        (
            "a service-account JSON key",
            "sa-key.json",
            NOT_A_POLICY_SERVICE_ACCOUNT,
        ),
    ] {
        no_command_takes_it(fixture, name, contents);
    }
}

/// A Kubernetes `Secret`, which is what a `--config` pointed one directory over
/// in a deploy repository lands on.
///
/// Not a real credential: the `data` value is base64 for
/// `throwaway-not-a-real-value`. It has to be base64 for the file to read as a
/// `Secret` at all, and being decodable is the point — a leaked one is readable.
const NOT_A_POLICY_K8S_SECRET: &str = "\
apiVersion: v1
kind: Secret
metadata:
  name: honmoon-db-credentials
  namespace: production
type: Opaque
data:
  password: dGhyb3dhd2F5LW5vdC1hLXJlYWwtdmFsdWU=
";

/// The shape a `.env` takes when it is spelled with colons — and the one that
/// makes the old behaviour easiest to hit, because it is one mapping of two
/// keys and nothing about it is malformed.
const NOT_A_POLICY_DOTENV: &str = "\
DB_PASSWORD: throwaway-not-a-real-value
AWS_SECRET_ACCESS_KEY: throwaway-also-not-real
";

/// JSON is valid YAML, so a service-account key is a mapping like any other.
///
/// The `private_key` is a fixture, not a key: a PEM envelope around a line of
/// text. The envelope is kept because it is what a reader of a leaked log
/// recognises.
const NOT_A_POLICY_SERVICE_ACCOUNT: &str = r#"{
  "type": "service_account",
  "project_id": "throwaway-not-a-real-project",
  "private_key_id": "0000000000000000000000000000000000000000",
  "private_key": "-----BEGIN PRIVATE KEY-----\nnot-a-key-just-a-fixture\n-----END PRIVATE KEY-----\n",
  "client_email": "throwaway@not-a-real-project.iam.gserviceaccount.com"
}
"#;

/// The body of the test above, run once per fixture — the counterpart of
/// `no_command_quotes`, asserting the verdict it could not.
fn no_command_takes_it(fixture: &str, name: &str, contents: &str) {
    let home = TempHome::new(&format!("no-policy-field-{name}"));
    let mistyped = home.write_policy(name, contents);
    let path = mistyped.to_str().unwrap();

    let commands = vec![
        ("policy validate", vec!["policy", "validate", path]),
        ("run --policy", vec!["run", "--policy", path, "--", "true"]),
        // Gated for the reason every other gateway control in this file is:
        // `gateway` mints a management token before it reads the policy, and
        // cannot on a non-Unix host, so it never reaches the read there.
        #[cfg(unix)]
        ("gateway --config", vec!["gateway", "--config", path]),
    ];

    for (label, args) in commands {
        let output = run(&home, &args);
        assert!(
            !output.status.success(),
            "`{label}` must refuse {fixture}: it is a mapping, but it declares no \
             policy field, so accepting it reports a credential file as a valid \
             0-rule policy"
        );
        let printed = format!("{}{}", stdout(&output), stderr(&output));
        assert!(
            printed.contains("none of its keys is a policy field"),
            "`{label}` must say what is actually wrong with {fixture}; got: {printed}"
        );
        // Not a repeat of `no_command_quotes`: that test's fixtures are refused
        // by the *shape* guard, and these reach a different refusal, so the
        // absence has to be measured again on this path.
        for line in contents.lines() {
            assert!(
                !printed.contains(line.trim()),
                "`{label}` put the file's contents in its error ({fixture}) — \
                 the line {line:?} is in: {printed}"
            );
        }
    }
}

/// The property that made "require a recognised key" the chosen option rather
/// than `#[serde(deny_unknown_fields)]`, so it is the one most worth pinning.
///
/// A policy written for a newer honmoon carries fields this build has never
/// heard of. It loaded before and it has to go on loading: an operator rolling
/// a fleet back one version must not have the old binary refuse the file the new
/// one wrote. One recognised key is the whole admission test, and what sits
/// beside it is not this check's business.
///
/// Asserted through the gateway as well as `validate`, because accepting a
/// policy the gateway then refuses is the drift that matters most here — the
/// unbindable address turns "it got past the loader" into an immediate exit.
#[test]
fn a_policy_carrying_an_unknown_field_still_loads() {
    let home = TempHome::new("forward-compat");
    let policy = home.write_policy(
        "from-the-future.yaml",
        r#"
version: 2
egress:
  default: deny
telemetry:
  exporter: otlp
  endpoint: https://collector.internal:4317
"#,
    );

    let output = run(&home, &["policy", "validate", policy.to_str().unwrap()]);
    assert!(
        output.status.success(),
        "an unknown field beside a recognised one must still load — that is the \
         forward-compatibility `deny_unknown_fields` would have broken; got: {}",
        stderr(&output)
    );

    #[cfg(unix)]
    {
        let gateway_home = TempHome::new("forward-compat-gateway");
        let gateway_policy = gateway_home.write_policy(
            "from-the-future.yaml",
            "version: 2\negress:\n  default: deny\ntelemetry:\n  exporter: otlp\n",
        );
        let started = run(
            &gateway_home,
            &[
                "gateway",
                "--config",
                gateway_policy.to_str().unwrap(),
                "--addr",
                UNBINDABLE_ADDR,
            ],
        );
        let stderr = stderr(&started);
        assert!(
            stderr.contains("binding proxy"),
            "the gateway must have got past the loader and failed at the bind — \
             anything about a policy field here means the read refused a policy \
             `validate` had just accepted; got: {stderr}"
        );
    }
}
