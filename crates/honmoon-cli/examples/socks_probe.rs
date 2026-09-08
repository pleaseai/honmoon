//! Test fixture: a child process that reaches a PostgreSQL endpoint the way a
//! confined command has to — over SOCKS5, through whatever `ALL_PROXY` names.
//!
//! A sibling of `bypass_probe`, and an example for the same reasons: it is
//! built for tests but never shipped in a release, and it speaks the protocols
//! itself rather than shelling out to `psql`, so the suite has no dependency on
//! what happens to be installed. `psql` could not stand in for it anyway — it
//! does not speak SOCKS5, which is the whole point of the README note this
//! fixture's test backs up.
//!
//! Usage:
//!   `socks_probe pg <host:port> <sql>` — read `ALL_PROXY`, open a SOCKS5
//!                                        tunnel to `<host:port>`, complete a
//!                                        PostgreSQL handshake, run `<sql>`,
//!                                        and print one word:
//!                                          `ok`               — the statement
//!                                                               was forwarded
//!                                                               and the server
//!                                                               answered.
//!                                          `refused`          — honmoon
//!                                                               answered with
//!                                                               an
//!                                                               ErrorResponse
//!                                                               carrying
//!                                                               SQLSTATE
//!                                                               42501.
//!                                          `socks-refused:<n>`— the SOCKS5
//!                                                               CONNECT itself
//!                                                               was refused
//!                                                               with reply `n`.
//!                                        Exits 7 when the proxy could not be
//!                                        reached at all.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(10);
const UNREACHABLE: i32 = 7;

/// PostgreSQL wire-protocol constants this fixture speaks.
const PROTOCOL_V3: u32 = 196_608;
const SSL_REQUEST: u32 = 80_877_103;

fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_default();
    let target = args.next().unwrap_or_default();

    match mode.as_str() {
        "pg" => pg(&target, &args.next().unwrap_or_default()),
        other => {
            eprintln!("socks_probe: unknown mode {other:?}");
            std::process::exit(2);
        }
    }
}

/// Run one statement against `target` through the SOCKS5 proxy.
fn pg(target: &str, sql: &str) {
    let (host, port) = split_authority(target);

    let mut stream = socks_connect(host, port);

    // Decline TLS: honmoon inspects the session inline, which needs plaintext,
    // so it answers `N` and the client falls back — exactly what a real driver
    // does when a server has no TLS.
    let mut request = Vec::new();
    request.extend_from_slice(&8u32.to_be_bytes());
    request.extend_from_slice(&SSL_REQUEST.to_be_bytes());
    write_all(&mut stream, &request);
    let mut answer = [0u8; 1];
    read_exact(&mut stream, &mut answer);
    if answer[0] != b'N' {
        eprintln!(
            "socks_probe: expected `N` to the SSLRequest, got {:?}",
            answer[0]
        );
        std::process::exit(4);
    }

    let body = b"user\0honmoon\0\0";
    let mut startup = Vec::new();
    startup.extend_from_slice(&((8 + body.len()) as u32).to_be_bytes());
    startup.extend_from_slice(&PROTOCOL_V3.to_be_bytes());
    startup.extend_from_slice(body);
    write_all(&mut stream, &startup);
    read_until_ready(&mut stream);

    let mut query = vec![b'Q'];
    query.extend_from_slice(&((5 + sql.len()) as u32).to_be_bytes());
    query.extend_from_slice(sql.as_bytes());
    query.push(0);
    write_all(&mut stream, &query);

    let frames = read_until_ready(&mut stream);
    match frames.first() {
        // CommandComplete: the statement reached the server and it answered.
        Some((b'C', _)) => println!("ok"),
        // honmoon's refusal, which it delivers as a PostgreSQL error so the
        // client sees a normal failure rather than a dropped connection.
        Some((b'E', payload)) => {
            let text = String::from_utf8_lossy(payload);
            if text.contains("C42501\0") {
                println!("refused");
            } else {
                println!("error:{text:?}");
            }
        }
        other => println!("unexpected:{:?}", other.map(|(tag, _)| *tag)),
    }
}

/// Open a SOCKS5 tunnel to `host:port` through `ALL_PROXY`.
///
/// The address type is DOMAIN even when the host is already an address, because
/// the hostname is the signal honmoon selects an endpoint with — which is why
/// `run` hands out a `socks5h://` URL rather than resolving here.
fn socks_connect(host: &str, port: u16) -> TcpStream {
    let proxy = std::env::var("ALL_PROXY").unwrap_or_else(|_| {
        eprintln!("socks_probe: ALL_PROXY is not set");
        std::process::exit(3);
    });
    let authority = proxy
        .trim_start_matches("socks5h://")
        .trim_start_matches("socks5://")
        .trim_end_matches('/');

    let mut stream = dial(authority).unwrap_or_else(|error| {
        eprintln!("socks_probe: proxy {authority} unreachable: {error}");
        std::process::exit(UNREACHABLE);
    });

    // Greeting: version 5, one method, "no authentication".
    write_all(&mut stream, &[0x05, 0x01, 0x00]);
    let mut greeting = [0u8; 2];
    read_exact(&mut stream, &mut greeting);
    if greeting != [0x05, 0x00] {
        eprintln!("socks_probe: proxy did not select no-auth: {greeting:?}");
        std::process::exit(5);
    }

    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    write_all(&mut stream, &request);

    let mut head = [0u8; 4];
    read_exact(&mut stream, &mut head);
    let address_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            read_exact(&mut stream, &mut len);
            usize::from(len[0])
        }
        other => {
            eprintln!("socks_probe: unexpected bound address type {other}");
            std::process::exit(5);
        }
    };
    let mut rest = vec![0u8; address_len + 2];
    read_exact(&mut stream, &mut rest);

    if head[1] != 0x00 {
        println!("socks-refused:{}", head[1]);
        std::process::exit(0);
    }
    stream
}

/// Read frames until `ReadyForQuery`, returning everything seen.
fn read_until_ready(stream: &mut TcpStream) -> Vec<(u8, Vec<u8>)> {
    let mut frames = Vec::new();
    loop {
        let mut tag = [0u8; 1];
        read_exact(stream, &mut tag);
        let mut length = [0u8; 4];
        read_exact(stream, &mut length);
        let declared = u32::from_be_bytes(length) as usize;
        if declared < 4 {
            eprintln!("socks_probe: frame shorter than its own length prefix");
            std::process::exit(6);
        }
        let mut payload = vec![0u8; declared - 4];
        read_exact(stream, &mut payload);
        let done = tag[0] == b'Z';
        frames.push((tag[0], payload));
        if done {
            return frames;
        }
    }
}

/// `host:port`, split without resolving: the host has to stay a name.
fn split_authority(target: &str) -> (&str, u16) {
    let (host, port) = target.rsplit_once(':').unwrap_or_else(|| {
        eprintln!("socks_probe: {target:?} is not host:port");
        std::process::exit(2);
    });
    let port = port.parse().unwrap_or_else(|_| {
        eprintln!("socks_probe: {port:?} is not a port");
        std::process::exit(2);
    });
    (host, port)
}

fn write_all(stream: &mut TcpStream, bytes: &[u8]) {
    stream.write_all(bytes).unwrap_or_else(|error| {
        eprintln!("socks_probe: write failed: {error}");
        std::process::exit(UNREACHABLE);
    });
}

fn read_exact(stream: &mut TcpStream, buffer: &mut [u8]) {
    stream.read_exact(buffer).unwrap_or_else(|error| {
        eprintln!("socks_probe: read failed: {error}");
        std::process::exit(UNREACHABLE);
    });
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
