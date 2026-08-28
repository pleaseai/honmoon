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

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(10);
const UNREACHABLE: i32 = 7;

fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_default();
    let target = args.next().unwrap_or_default();

    match mode.as_str() {
        "direct" => direct(&target),
        "via-proxy" => via_proxy(&target),
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
