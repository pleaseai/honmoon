//! Does `honmoon run` actually hold a child that refuses to cooperate?
//!
//! The claim under test is the one TD-003 is about and the one a user is most
//! likely to take on faith: a child that ignores `http_proxy` is still confined.
//! Every case here is paired with an **unsandboxed control** running the same
//! probe the same way, because "the connection failed" only means something once
//! you have shown it succeeds when honmoon is not in the picture.
//!
//! Linux and macOS — the two platforms where ADR-0005's enforcement exists. The
//! mechanisms could hardly be less alike (an empty network namespace with a
//! bridged Unix socket; a Seatbelt profile with one open port), which is exactly
//! why the *claims* are asserted here rather than the mechanisms: both platforms
//! run the same cases and have to answer the same way. Anything platform-shaped
//! is gated and says why.
//!
//! On a host that cannot enforce the tests skip loudly rather than passing
//! quietly; CI additionally asserts that the runner *can* enforce, so a skip
//! cannot become permanent unnoticed.

#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

/// Exit code the probe uses for "I could not get there".
const UNREACHABLE: i32 = 7;

fn honmoon() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_honmoon"))
}

/// The probe is an example, so it sits beside the binary rather than next to it.
///
/// A plain `cargo test` builds it; two narrower invocations do not, and both
/// have already broken this suite once. `cargo test --test enforced_isolation`
/// narrows the build to this one target, and `--all-targets` compiles examples
/// as *test* targets rather than leaving a runnable binary here. Say so out
/// loud instead of letting it surface as a bare `No such file or directory`
/// from deep inside the sandbox.
fn probe() -> PathBuf {
    let path = honmoon()
        .parent()
        .expect("the test binary lives in a target directory")
        .join("examples")
        .join("bypass_probe");
    assert!(
        path.exists(),
        "the probe fixture is missing at {path:?} — build it with \
         `cargo build -p honmoon-cli --example bypass_probe`, or run the suite \
         as a plain `cargo test -p honmoon-cli`. Note that `--all-targets` does \
         *not* produce it: it compiles examples as test targets instead."
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

    /// A path inside the scratch directory, for a child to write its result to.
    fn scratch_file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// An origin server on host loopback, outside whatever namespace the child gets,
/// that stops accepting when this value is dropped.
///
/// Without the guard the acceptor loops on `accept` forever, so every test that
/// wanted an origin left a bound port and a permanently blocked thread behind for
/// the life of the test process.
struct Origin {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl Origin {
    fn address(&self) -> SocketAddr {
        self.address
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // The acceptor only looks at the flag between connections, so it has to
        // be woken from the `accept` it is sitting in. A throwaway connection is
        // the one portable way to do that; whether it succeeds is irrelevant.
        let _ = TcpStream::connect(self.address);
    }
}

fn spawn_origin() -> Origin {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the origin server");
    let address = listener.local_addr().expect("origin address");
    let stop = Arc::new(AtomicBool::new(false));
    let acceptor_stop = Arc::clone(&stop);
    thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            if acceptor_stop.load(Ordering::SeqCst) {
                break;
            }
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
    Origin { address, stop }
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
    let explanation = NO_ENFORCEMENT_HERE;
    assert!(
        std::env::var_os("HONMOON_REQUIRE_ENFORCEMENT").is_none(),
        "{test}: HONMOON_REQUIRE_ENFORCEMENT is set, but {explanation}"
    );
    // Written to the stderr handle rather than with `eprintln!`: libtest
    // captures the print macros and shows them only for a *failing* test, so
    // the macro form would make this skip invisible in exactly the run where it
    // matters — a plain `cargo test` reporting green tests that never executed.
    let _ = writeln!(std::io::stderr(), "SKIPPED {test}: {explanation}");
    false
}

/// Why this host cannot enforce, and what to do about it.
///
/// Split by platform because the two failures share nothing: one is a kernel
/// policy the operator can lift, the other is a profile that stopped compiling.
#[cfg(target_os = "linux")]
const NO_ENFORCEMENT_HERE: &str = "this host cannot create unprivileged user namespaces, so `honmoon run` is \
     advisory here and there is no confinement to test. Under Docker this \
     usually means the default seccomp profile — retry with \
     `--security-opt seccomp=unconfined`. On Ubuntu 24.04 it usually means \
     `kernel.apparmor_restrict_unprivileged_userns`.";

/// Every macOS host ships `/usr/bin/sandbox-exec`, so a skip here is not a host
/// that lacks the feature — it is honmoon's profile failing to compile, which is
/// the way the documented `sandbox-exec` deprecation would actually arrive.
#[cfg(target_os = "macos")]
const NO_ENFORCEMENT_HERE: &str = "`/usr/bin/sandbox-exec` could not apply honmoon's Seatbelt profile on this \
     host, so `honmoon run` is advisory here. Every macOS host ships it, so the \
     likely cause is a change in the SBPL dialect the profile is written in — \
     run it by hand against `isolate::macos::profile` to see the compiler error.";

const ALLOW_LOOPBACK: &str = "version: 1\negress:\n  default: deny\n  allow:\n    - 127.0.0.1\n";

/// Block until a detached child has written its report, or give up.
///
/// The child outlives every process the test can wait on, so there is nothing to
/// join — the file appearing is the only completion signal there is.
fn read_report(path: &Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        // Nested rather than a let-chain: those need Rust 1.88 and the
        // workspace declares `rust-version = "1.85"`.
        if let Ok(text) = std::fs::read_to_string(path) {
            if text.contains("exit=") {
                return text;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "the detached child never reported to {path:?}. It is supposed to write \
         its outcome whether it got through or not, so an empty report means it \
         died before dialling and this test proved nothing."
    );
}

#[test]
fn a_child_that_ignores_the_proxy_environment_reaches_nothing() {
    let scratch = Scratch::with_policy("bypass", ALLOW_LOOPBACK);
    if !enforcing_or_skip(&scratch.policy(), "bypass") {
        return;
    }

    let origin = spawn_origin();
    let target = origin.address().to_string();
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

/// Linux only: macOS builds its profile as a string argument and never touches
/// the filesystem, so there is no mode for a umask to strip.
#[cfg(target_os = "linux")]
#[test]
fn a_restrictive_umask_does_not_downgrade_enforcement() {
    let scratch = Scratch::with_policy("umask", ALLOW_LOOPBACK);
    if !enforcing_or_skip(&scratch.policy(), "umask") {
        return;
    }

    let origin = spawn_origin();
    let target = origin.address().to_string();

    // The control first, for the same reason the bypass test has one: a probe
    // that cannot reach the origin unsandboxed would make the assertion below
    // meaningless.
    let control = run_unsandboxed(&["direct", target.as_str()]);
    assert_eq!(
        control.status.code(),
        Some(0),
        "the probe must reach the origin when honmoon is not involved, or this \
         test cannot distinguish confinement from a broken fixture"
    );

    // The umask is set in a *spawned* shell rather than in this process, because
    // `umask` is process-wide and libtest runs every test in this binary on
    // threads of one process: setting it here would change the mode of files
    // other tests create at the same moment.
    //
    // What it exercises: `mkdir` intersects its mode argument with the umask, so
    // the bridge's scratch directory would arrive 0600 rather than 0700 without
    // the `set_permissions` restore in `private_scratch_dir`. A directory its own
    // owner cannot traverse takes the bridge socket with it — the bind fails,
    // `run` reports a setup error, and the run silently falls back to advisory,
    // which is the one state in which ignoring `http_proxy` works.
    let confined = Command::new("sh")
        .arg("-c")
        .arg(r#"umask 0177; exec "$0" run --policy "$1" -- "$2" direct "$3""#)
        .arg(honmoon())
        .arg(scratch.policy())
        .arg(probe())
        .arg(&target)
        .output()
        .expect("run honmoon under a restrictive umask");

    let stderr = String::from_utf8_lossy(&confined.stderr);
    assert!(
        !stderr.contains("ADVISORY"),
        "a restrictive umask must not knock the run down to advisory.\nstderr: {stderr}"
    );
    assert_eq!(
        confined.status.code(),
        Some(UNREACHABLE),
        "with a restrictive umask the run must still confine the child; it \
         reached the origin instead, so the umask bought a policy bypass \
         (TD-003).\nstderr: {stderr}"
    );
}

#[test]
fn a_child_that_ignores_the_proxy_environment_cannot_leave_loopback_either() {
    let scratch = Scratch::with_policy("offbox", ALLOW_LOOPBACK);
    if !enforcing_or_skip(&scratch.policy(), "offbox") {
        return;
    }

    // A routable address that is not this machine. On Linux the sandbox has no
    // interface but loopback, so there is no route to it at all; on macOS the
    // interfaces are still there and the profile refuses the connect. Different
    // mechanisms, one required answer.
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
    let confined = run_sandboxed(
        &scratch.policy(),
        &["via-proxy", &origin.address().to_string()],
    );
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
fn a_descendant_that_outlives_its_parent_is_confined_too() {
    let scratch = Scratch::with_policy("detached", ALLOW_LOOPBACK);
    if !enforcing_or_skip(&scratch.policy(), "detached") {
        return;
    }

    let origin = spawn_origin();
    let target = origin.address().to_string();

    // The control does double duty here. As everywhere else in this file it
    // shows the origin is reachable at all — but it also proves the fixture
    // really detaches, because `reparented=true` is measured rather than
    // assumed. Without that, a confined `exit=7` could just mean the grandchild
    // never got far enough to be interesting.
    let control_report = scratch.scratch_file("control.txt");
    run_unsandboxed(&[
        "detached",
        target.as_str(),
        &control_report.to_string_lossy(),
    ]);
    let control = read_report(&control_report);
    assert!(
        control.contains("reparented=true"),
        "the fixture must actually orphan its dialler, or this test is just \
         another child-process test wearing a different name. Got: {control}"
    );
    assert!(
        control.contains("exit=0"),
        "the detached dialler must reach the origin when honmoon is not \
         involved. Got: {control}"
    );

    // This is the case that defeated the PPID-matching design #69 originally
    // specified, and it is worth keeping now that the mechanism no longer works
    // that way: both a network namespace and a Seatbelt profile are kernel state
    // a process carries, not a lineage it can step out of. `honmoon run` returns
    // as soon as its own child exits, so the dialler is still running, already
    // re-parented, with nothing left of the tree it was started in.
    let confined_report = scratch.scratch_file("confined.txt");
    run_sandboxed(
        &scratch.policy(),
        &[
            "detached",
            target.as_str(),
            &confined_report.to_string_lossy(),
        ],
    );
    let confined = read_report(&confined_report);
    assert!(
        confined.contains("reparented=true"),
        "the confined dialler was never orphaned, so the interesting case did \
         not run. Got: {confined}"
    );
    assert!(
        confined.contains(&format!("exit={UNREACHABLE}")),
        "a descendant that outlived the process honmoon waited on reached the \
         origin. Confinement that ends with the process tree is not confinement \
         (TD-003). Got: {confined}"
    );
}

#[test]
fn the_sandboxed_command_keeps_its_own_exit_code() {
    let scratch = Scratch::with_policy("exitcode", ALLOW_LOOPBACK);
    if !enforcing_or_skip(&scratch.policy(), "exitcode") {
        return;
    }

    // Confinement puts processes between the caller and the command — two on
    // Linux, one on macOS — and an exit code swallowed on the way back would
    // break every script wrapping `honmoon run`.
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

/// Linux only, for the same reason: the macOS path has no scratch directory to
/// leak.
#[cfg(target_os = "linux")]
#[test]
fn the_sandbox_leaves_no_scratch_directory_behind() {
    let scratch = Scratch::with_policy("cleanup", ALLOW_LOOPBACK);
    if !enforcing_or_skip(&scratch.policy(), "cleanup") {
        return;
    }

    // Spawned rather than run to completion in one call so the honmoon pid is
    // known: the bridge directory is named after it, and checking that exact
    // path keeps this test immune to other tests running in parallel.
    let mut child = Command::new(honmoon())
        .arg("run")
        .arg("--policy")
        .arg(scratch.policy())
        .arg("--")
        .arg("/bin/true")
        .spawn()
        .expect("run honmoon");
    let pid = child.id();
    child.wait().expect("wait for honmoon");

    let bridge_dir = std::env::temp_dir().join(format!("honmoon-{pid}"));
    assert!(
        !bridge_dir.exists(),
        "the bridge's scratch directory {bridge_dir:?} outlived the run. \
         `run` ends in std::process::exit, which runs no destructors, so \
         anything relying on Drop across that call leaks one directory per \
         invocation."
    );
}
