//! Does `honmoon run` actually hold a child that refuses to cooperate?
//!
//! The claim under test is the one TD-003 is about and the one a user is most
//! likely to take on faith: a child that ignores `http_proxy` is still confined.
//! Every case here is paired with an **unsandboxed control** running the same
//! probe the same way, because "the connection failed" only means something once
//! you have shown it succeeds when honmoon is not in the picture.
//!
//! Linux only — it is the one platform where ADR-0005's enforcement is
//! implemented. On a host that cannot create unprivileged user namespaces the
//! tests skip loudly rather than passing quietly; CI additionally asserts that
//! the runner *can* enforce, so a skip cannot become permanent unnoticed.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;

/// Exit code the probe uses for "I could not get there".
const UNREACHABLE: i32 = 7;

fn honmoon() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_honmoon"))
}

/// The probe is an example, so it sits beside the binary rather than next to it.
///
/// Examples are built by `cargo test` and by CI's `--all-targets` run, but *not*
/// by `cargo test --test enforced_isolation`, which narrows the build to this
/// one target. Say that out loud instead of letting it surface as a bare
/// `No such file or directory` from deep inside the sandbox.
fn probe() -> PathBuf {
    let path = honmoon()
        .parent()
        .expect("the test binary lives in a target directory")
        .join("examples")
        .join("bypass_probe");
    assert!(
        path.exists(),
        "the probe fixture is missing at {path:?} — build it with \
         `cargo build -p honmoon-cli --example bypass_probe`, or run the whole \
         suite with `cargo test -p honmoon-cli`, which builds examples"
    );
    path
}

/// A scratch directory that removes itself, holding this test's policy file.
struct Scratch(PathBuf);

impl Scratch {
    fn with_policy(name: &str, policy: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("honmoon-it-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the scratch directory");
        std::fs::write(dir.join("policy.yaml"), policy).expect("write the policy");
        Self(dir)
    }

    fn policy(&self) -> PathBuf {
        self.0.join("policy.yaml")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// An origin server on host loopback, outside whatever namespace the child gets.
fn spawn_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the origin server");
    let address = listener.local_addr().expect("origin address");
    thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            thread::spawn(move || {
                // Read just enough to let the client finish its request; the
                // body is irrelevant, only reachability is being measured.
                let mut buffer = [0_u8; 1024];
                let _ = stream.read(&mut buffer);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
                );
            });
        }
    });
    address
}

fn run_sandboxed(policy: &Path, probe_args: &[&str]) -> Output {
    let mut command = Command::new(honmoon());
    command
        .arg("run")
        .arg("--policy")
        .arg(policy)
        .arg("--")
        .arg(probe())
        .args(probe_args);
    command.output().expect("run honmoon")
}

fn run_unsandboxed(probe_args: &[&str]) -> Output {
    Command::new(probe())
        .args(probe_args)
        .output()
        .expect("run the probe directly")
}

/// Ask the product itself whether this host can enforce, rather than guessing
/// from kernel settings: `run` prints the advisory warning exactly when it
/// could not confine the child.
fn enforcement_available(policy: &Path) -> bool {
    let output = Command::new(honmoon())
        .arg("run")
        .arg("--policy")
        .arg(policy)
        .arg("--")
        .arg("/bin/true")
        .output()
        .expect("run honmoon");
    !String::from_utf8_lossy(&output.stderr).contains("ADVISORY")
}

/// Returns `false` and says so when the host cannot enforce.
///
/// Set `HONMOON_REQUIRE_ENFORCEMENT` to turn the skip into a failure. CI does,
/// so a runner that quietly loses the ability to create user namespaces breaks
/// the build instead of reporting five green tests that never ran.
fn enforcing_or_skip(policy: &Path, test: &str) -> bool {
    if enforcement_available(policy) {
        return true;
    }
    let explanation = "this host cannot create unprivileged user namespaces, so `honmoon run` \
         is advisory here and there is no confinement to test. Under Docker this \
         usually means the default seccomp profile — retry with \
         `--security-opt seccomp=unconfined`. On Ubuntu 24.04 it usually means \
         `kernel.apparmor_restrict_unprivileged_userns`.";
    assert!(
        std::env::var_os("HONMOON_REQUIRE_ENFORCEMENT").is_none(),
        "{test}: HONMOON_REQUIRE_ENFORCEMENT is set, but {explanation}"
    );
    eprintln!("SKIPPED {test}: {explanation}");
    false
}

const ALLOW_LOOPBACK: &str = "version: 1\negress:\n  default: deny\n  allow:\n    - 127.0.0.1\n";

#[test]
fn a_child_that_ignores_the_proxy_environment_reaches_nothing() {
    let scratch = Scratch::with_policy("bypass", ALLOW_LOOPBACK);
    if !enforcing_or_skip(&scratch.policy(), "bypass") {
        return;
    }

    let origin = spawn_origin();
    let target = origin.to_string();
    let args = ["direct", target.as_str()];

    // The control comes first: if the probe cannot reach the origin even without
    // honmoon, the confined result below would prove nothing at all.
    let control = run_unsandboxed(&args);
    assert_eq!(
        control.status.code(),
        Some(0),
        "the probe must reach the origin when honmoon is not involved, or this \
         test cannot distinguish confinement from a broken fixture"
    );

    let confined = run_sandboxed(&scratch.policy(), &args);
    assert_eq!(
        confined.status.code(),
        Some(UNREACHABLE),
        "a child that dials the origin directly must fail inside the sandbox; \
         it reached it instead, so policy can be bypassed (TD-003).\nstderr: {}",
        String::from_utf8_lossy(&confined.stderr)
    );
}

#[test]
fn a_child_that_ignores_the_proxy_environment_cannot_leave_loopback_either() {
    let scratch = Scratch::with_policy("offbox", ALLOW_LOOPBACK);
    if !enforcing_or_skip(&scratch.policy(), "offbox") {
        return;
    }

    // A routable address that is not this machine. The sandbox has no interface
    // but loopback, so there is no route to it at all.
    let args = ["direct", "1.1.1.1:80"];
    let confined = run_sandboxed(&scratch.policy(), &args);
    assert_eq!(
        confined.status.code(),
        Some(UNREACHABLE),
        "an off-box address must be unreachable from inside the sandbox.\nstderr: {}",
        String::from_utf8_lossy(&confined.stderr)
    );
}

#[test]
fn a_cooperating_child_still_reaches_an_allowed_host() {
    let scratch = Scratch::with_policy("allowed", ALLOW_LOOPBACK);
    if !enforcing_or_skip(&scratch.policy(), "allowed") {
        return;
    }

    let origin = spawn_origin();
    let confined = run_sandboxed(&scratch.policy(), &["via-proxy", &origin.to_string()]);
    let status = String::from_utf8_lossy(&confined.stdout);
    assert_eq!(
        status.trim(),
        "200",
        "confinement must not break the cooperative path: the child reads \
         http_proxy, and that route has to carry an allowed host end to end.\nstderr: {}",
        String::from_utf8_lossy(&confined.stderr)
    );
}

#[test]
fn a_cooperating_child_is_refused_a_denied_host() {
    let scratch = Scratch::with_policy("denied", ALLOW_LOOPBACK);
    if !enforcing_or_skip(&scratch.policy(), "denied") {
        return;
    }

    // `.invalid` can never resolve, so a 403 also proves the proxy decided
    // before dialling rather than after failing to.
    let confined = run_sandboxed(&scratch.policy(), &["via-proxy", "blocked.invalid:80"]);
    let status = String::from_utf8_lossy(&confined.stdout);
    assert_eq!(
        status.trim(),
        "403",
        "a host outside the allow list must be refused by the proxy.\nstderr: {}",
        String::from_utf8_lossy(&confined.stderr)
    );
}

#[test]
fn the_sandboxed_command_keeps_its_own_exit_code() {
    let scratch = Scratch::with_policy("exitcode", ALLOW_LOOPBACK);
    if !enforcing_or_skip(&scratch.policy(), "exitcode") {
        return;
    }

    // Confinement adds two processes between the shell and the command; an exit
    // code that got swallowed on the way back would break every script wrapping
    // `honmoon run`.
    let status = Command::new(honmoon())
        .arg("run")
        .arg("--policy")
        .arg(scratch.policy())
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("exit 42")
        .status()
        .expect("run honmoon");
    assert_eq!(
        status.code(),
        Some(42),
        "the sandboxed command's exit code must reach the caller unchanged"
    );
}
