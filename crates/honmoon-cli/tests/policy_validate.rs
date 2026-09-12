//! `honmoon policy validate` — the load-and-exit check (#198).
//!
//! Three claims are asserted against the *shipped binary* rather than the
//! loader, because all three are about what running the command does rather
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
    // The endpoint name and host are the part an operator may not want in a CI
    // log, so they are distinctive enough to search the output for.
    let policy = home.write_policy(
        "good.yaml",
        r#"
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
"#,
    );

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

    // Refusing it early changes no verdict — it is refused either way. Without
    // this, the guard could quietly start rejecting files the gateway accepts.
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
            "the gateway refuses this file too, so the guard only changes the wording"
        );
    }
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
