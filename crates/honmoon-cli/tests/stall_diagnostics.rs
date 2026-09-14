//! The startup line that says how to see the data plane's stall diagnostics
//! (#228), and the claim it makes.
//!
//! `init_tracing` leaves every command at `ERROR` when `RUST_LOG` is unset, so
//! a session that hangs prints nothing about why. The decision on #228 was to
//! keep that default and make it *discoverable*: one line in the `eprintln!`
//! banner `gateway` and `run` already print, naming the filter that turns the
//! diagnostics on.
//!
//! Two claims, and the second is the one worth a test. The line being printed
//! is checked against the shipped binary for `run` and `gateway` both, because
//! a banner that only one of them prints is the failure this is meant to
//! prevent. But a *pointer* is only as good as where it points, so the filter
//! string is run through the binary as well: with it, a warning the default
//! swallows comes back.
//!
//! That last case is why the filter reads `honmoon=warn` rather than the
//! `honmoon_proxy=warn` the issue first named. The warnings an operator wants
//! are split across two target roots — `honmoon_proxy::runtime::postgres` for
//! the relay giving up, the oversized-copy quiet line and the
//! refusal-suppressed/lost pair, and `honmoon::isolate::bridge` for a confined
//! child whose route to the proxy is gone, which is this binary's own module
//! path. `honmoon` reaches both only because `EnvFilter` matches a target by
//! string prefix, and that is a property of the dependency rather than of this
//! crate. The load-time warning used below lives in **`honmoon_core`**, so
//! seeing it come back through `honmoon=warn` exercises exactly the
//! crate-name-prefix step `honmoon_proxy` depends on.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn honmoon() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_honmoon"))
}

/// The line the banner prints. Spelled out here rather than imported: the test
/// is for what an operator reads, so a rename that changes the wording should
/// have to be made twice.
const BANNER_LINE: &str = "honmoon: stall diagnostics: RUST_LOG=honmoon=warn";

/// A scratch `HOME` a subprocess can write into, removed when the test ends.
///
/// Hand-rolled for the reason `tests/policy_validate.rs` gives: a new workspace
/// dependency is an "ask first" change in `crates/AGENTS.md`. Uniqueness is
/// derived the same way too — libtest runs the whole binary in one process, on
/// threads, so `process::id()` alone does not separate two tests and the thread
/// name (which libtest sets to the test function's own name) carries it.
struct TempHome(PathBuf);

impl TempHome {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "honmoon-stall-diagnostics-{}-{}-{label}",
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

/// A policy the gateway loads without a word.
const QUIET_POLICY: &str = r#"
version: 1
egress:
  default: deny
  allow:
    - github.com
"#;

/// A policy that loads *and* makes `honmoon-core` emit a `tracing::warn!`.
///
/// `Policy::from_yaml` warns about a rule naming an endpoint `endpoints` does
/// not declare, and it is a warning rather than an error precisely so the
/// policy still loads — which is what makes it usable here as a diagnostic that
/// the log filter alone decides the visibility of.
const POLICY_WITH_A_LOAD_WARNING: &str = r#"
version: 1
egress:
  default: deny
rules:
  - name: names-an-undeclared-endpoint
    endpoint: nowhere-in-endpoints
    condition: "true"
    verdict: deny
"#;

/// An address no interface owns, so a `gateway` that got past the policy load
/// stops at its first bind instead of serving until interrupted.
///
/// The same `192.0.2.1` (TEST-NET-1, RFC 5737) and the same reasoning as
/// `tests/policy_validate.rs`: an IP literal, so `bind` fails locally in
/// milliseconds without a resolver round trip, and no host carries the address
/// for a gateway to successfully bind and hang the suite on.
const UNBINDABLE_ADDR: &str = "192.0.2.1:8443";

/// Run the binary with a scratch `HOME` and an environment that cannot leak the
/// developer's own settings in.
///
/// `RUST_LOG` is removed rather than left alone because these tests assert what
/// an ordinary run prints; `rust_log` puts a value back for the one case that
/// is about a filter.
fn run(home: &TempHome, args: &[&str], rust_log: Option<&str>) -> Output {
    let mut command = Command::new(honmoon());
    command
        .args(args)
        .env("HOME", home.path())
        .env_remove("HONMOON_MGMT_TOKEN")
        .env_remove("HONMOON_HOOK_TOKEN")
        .env_remove("RUST_LOG");
    if let Some(filter) = rust_log {
        command.env("RUST_LOG", filter);
    }
    command.output().expect("run the honmoon binary")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// `honmoon run` names the filter before it hands control to the child.
///
/// The child is this same binary asking for its version: present wherever the
/// test binary is, exits immediately, and needs nothing from the host that a
/// confined child might not have. What matters is only that the line is out
/// before `run` reaches it — under enforced isolation `run_confined` never
/// returns, so a banner printed any later would be one a sandboxed run never
/// saw.
#[test]
fn run_names_the_filter_that_turns_stall_diagnostics_on() {
    let home = TempHome::new("run-banner");
    let policy = home.write_policy("quiet.yaml", QUIET_POLICY);
    let binary = honmoon();

    let output = run(
        &home,
        &[
            "run",
            "--policy",
            policy.to_str().unwrap(),
            "--",
            binary.to_str().unwrap(),
            "--version",
        ],
        None,
    );

    assert!(
        stderr(&output).contains(BANNER_LINE),
        "`honmoon run` must print the stall-diagnostics line at startup; stderr: {}",
        stderr(&output)
    );
}

/// And so does `honmoon gateway`, before it binds anything.
///
/// Pointed at an address no host owns so the process ends on its own: the
/// banner is printed between the policy load and the first bind, so the failure
/// that stops this run is also what proves the line does not depend on a
/// listener being up.
#[test]
fn the_gateway_names_it_too_even_when_it_cannot_bind() {
    let home = TempHome::new("gateway-banner");
    let policy = home.write_policy("quiet.yaml", QUIET_POLICY);

    let output = run(
        &home,
        &[
            "gateway",
            "--config",
            policy.to_str().unwrap(),
            "--addr",
            UNBINDABLE_ADDR,
        ],
        None,
    );

    assert!(
        !output.status.success(),
        "the control only works if the gateway stopped at the bind"
    );
    assert!(
        stderr(&output).contains(BANNER_LINE),
        "`honmoon gateway` must print the stall-diagnostics line at startup; stderr: {}",
        stderr(&output)
    );
}

/// The pointer points somewhere: the filter it names brings a warning back that
/// the default drops.
///
/// Both halves are asserted against the same policy and the same command, so
/// the only difference between them is `RUST_LOG`. The warning comes from
/// `honmoon_core::Policy::from_yaml`, a third crate — neither the one the
/// filter names nor the one the banner is printed from — which is what makes
/// this a check of `EnvFilter`'s prefix match rather than of a string this
/// repository controls. `honmoon_proxy::runtime::postgres`, where the stall
/// warnings themselves live, is reached by the identical step.
///
/// Warnings go to stdout here: `init_tracing` sends `policy validate` to stderr
/// and leaves every other command on `fmt`'s default, which is right for a
/// gateway whose log is its output.
#[test]
fn the_advertised_filter_is_what_the_default_is_hiding() {
    let home = TempHome::new("filter");
    let policy = home.write_policy("warns.yaml", POLICY_WITH_A_LOAD_WARNING);
    let binary = honmoon();
    let args = [
        "run",
        "--policy",
        policy.to_str().unwrap(),
        "--",
        binary.to_str().unwrap(),
        "--version",
    ];
    const WARNING: &str = "policy rule references an endpoint not declared in `endpoints`";

    let default_run = run(&home, &args, None);
    assert!(
        !stdout(&default_run).contains(WARNING) && !stderr(&default_run).contains(WARNING),
        "with `RUST_LOG` unset the warning must be filtered out — that is the \
         problem #228 is about. stdout: {} stderr: {}",
        stdout(&default_run),
        stderr(&default_run)
    );

    let filtered_run = run(&home, &args, Some("honmoon=warn"));
    assert!(
        stdout(&filtered_run).contains(WARNING),
        "the filter the banner advertises must bring it back, including for a \
         target under a different crate root (`honmoon_core`) than the \
         directive names. stdout: {} stderr: {}",
        stdout(&filtered_run),
        stderr(&filtered_run)
    );
}

/// `--help` carries the explanation the one-line pointer cannot.
#[test]
fn both_commands_explain_the_filter_in_help() {
    let home = TempHome::new("help");

    for command in ["run", "gateway"] {
        let output = run(&home, &[command, "--help"], None);
        let help = stdout(&output);
        assert!(
            help.contains("RUST_LOG=honmoon=warn"),
            "`honmoon {command} --help` must name the filter; got: {help}"
        );
    }
}
