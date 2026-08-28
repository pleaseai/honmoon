//! Test fixture: a child process that either honours or ignores the proxy
//! environment, so an integration test can tell the two apart by exit code.
//!
//! It is an example rather than a `[[bin]]` so it is built for tests but never
//! shipped in a release, and it speaks raw TCP rather than shelling out to
//! `curl` so the test has no dependency on what happens to be installed.
//!
//! Usage:
//!   `bypass_probe direct <host:port>`     — connect straight there, ignoring
//!                                           every proxy variable. Exits 0 when
//!                                           it got through, 7 when it did not.
//!   `bypass_probe via-proxy <host:port>`  — read `http_proxy` and fetch the
//!                                           address through it. Prints the HTTP
//!                                           status code.
//!   `bypass_probe detached <host:port> <report>`
//!                                         — hand the dial to a process that
//!                                           outlives this one, then exit 0
//!                                           immediately. The grandchild writes
//!                                           its own outcome to `<report>`.
//!   `bypass_probe orphan <host:port> <report> <parent-pid>`
//!                                         — the detached half. Not called
//!                                           directly by tests.

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(10);
const UNREACHABLE: i32 = 7;

/// How long `orphan` waits to be re-parented before giving up and dialling
/// anyway. Generous: a slow CI runner must not turn "not re-parented yet" into a
/// green test, and the report says which it was either way.
const REPARENT_TIMEOUT: Duration = Duration::from_secs(5);

fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_default();
    let target = args.next().unwrap_or_default();

    match mode.as_str() {
        "direct" => direct(&target),
        "via-proxy" => via_proxy(&target),
        "detached" => detached(&target, &args.next().unwrap_or_default()),
        "orphan" => orphan(
            &target,
            &args.next().unwrap_or_default(),
            args.next().unwrap_or_default().parse().unwrap_or(0),
        ),
        other => {
            eprintln!("bypass_probe: unknown mode {other:?}");
            std::process::exit(2);
        }
    }
}

/// The bypass attempt: dial the address itself and tell nobody.
fn direct(target: &str) {
    match dial(target) {
        Ok(_) => std::process::exit(0),
        Err(error) => {
            eprintln!("bypass_probe: {target} unreachable: {error}");
            std::process::exit(UNREACHABLE);
        }
    }
}

/// The escape attempt that a PPID-matching sandbox would miss.
///
/// Spawns a grandchild and exits **without waiting for it**, so the grandchild
/// is re-parented away and no longer belongs to any process tree the sandbox
/// could have been watching. A design that confines by process lineage lets it
/// through; one that confines by kernel state — a namespace, a Seatbelt profile
/// — does not, because that state is inherited and cannot be dropped.
///
/// The outcome goes to a file rather than to stdout: by the time the grandchild
/// has an answer, the pipe every process between it and the test has already
/// closed.
fn detached(target: &str, report: &str) {
    if report.is_empty() {
        eprintln!("bypass_probe: detached needs a report path");
        std::process::exit(2);
    }
    let executable = std::env::current_exe().expect("locate this probe");
    std::process::Command::new(executable)
        .arg("orphan")
        .arg(target)
        .arg(report)
        .arg(std::process::id().to_string())
        .spawn()
        .expect("spawn the detached dialler");
    // No `wait`: exiting here is what orphans the grandchild.
    std::process::exit(0);
}

/// The detached half: outlive the parent, then try the network.
fn orphan(target: &str, report: &str, parent: u32) {
    // Wait to actually be re-parented before dialling, so a pass cannot come
    // from having raced ahead while the original process tree was still intact.
    let deadline = Instant::now() + REPARENT_TIMEOUT;
    while std::os::unix::process::parent_id() == parent && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let reparented = std::os::unix::process::parent_id() != parent;

    let code = match dial(target) {
        Ok(_) => 0,
        Err(_) => UNREACHABLE,
    };
    std::fs::write(report, format!("reparented={reparented} exit={code}\n"))
        .expect("write the detached report");
}

/// The cooperative path: go through whatever `http_proxy` names.
fn via_proxy(target: &str) {
    let proxy = std::env::var("http_proxy").unwrap_or_else(|_| {
        eprintln!("bypass_probe: http_proxy is not set");
        std::process::exit(3);
    });
    let authority = proxy.trim_start_matches("http://").trim_end_matches('/');

    let mut stream = dial(authority).unwrap_or_else(|error| {
        eprintln!("bypass_probe: proxy {authority} unreachable: {error}");
        std::process::exit(UNREACHABLE);
    });

    // Absolute-form request line, which is how a client asks an HTTP proxy for
    // a plaintext origin (RFC 9112 §3.2.2).
    write!(
        stream,
        "GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
    )
    .expect("write the proxied request");
    stream.flush().expect("flush the proxied request");

    let mut status_line = String::new();
    BufReader::new(stream)
        .read_line(&mut status_line)
        .expect("read the status line");

    let code = status_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("000")
        .to_string();
    println!("{code}");
}

fn dial(authority: &str) -> std::io::Result<TcpStream> {
    let address: SocketAddr = authority
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no address"))?;
    let stream = TcpStream::connect_timeout(&address, TIMEOUT)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    Ok(stream)
}
