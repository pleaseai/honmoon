//! Byte pumps that carry a connection across the namespace boundary.
//!
//! Enforced isolation leaves the child's network namespace empty, so the child
//! cannot reach the proxy's host loopback address. A Unix socket can cross that
//! boundary — it is addressed by filesystem path, not by network namespace — so
//! two pumps sit on either side of it:
//!
//! - on the host, [`serve`] accepts on the Unix socket and dials the proxy;
//! - inside the namespace, [`serve`] accepts on loopback TCP and dials the Unix
//!   socket.
//!
//! Both directions are the same operation with the endpoint types swapped, which
//! is why [`Endpoint`] exists rather than two near-identical modules.

//! Kept portable rather than gated to Linux so the pump's own tests — the
//! half-close case and the survives-a-dead-upstream case, where the bugs live —
//! run on every developer's machine and not only in CI.
#![cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "only the Linux isolation path bridges today")
)]

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;

/// A stream this module can copy bytes through in both directions.
///
/// `TcpStream` and `UnixStream` already share the shape; the trait only names
/// the two operations a pump needs beyond `Read`/`Write`: a second handle for
/// the opposite direction, and a half-close so the peer sees EOF rather than
/// waiting on a connection nobody will write to again.
pub trait Endpoint: Read + Write + Send + Sized + 'static {
    fn duplicate(&self) -> io::Result<Self>;
    fn shutdown_write(&self) -> io::Result<()>;
}

impl Endpoint for TcpStream {
    fn duplicate(&self) -> io::Result<Self> {
        self.try_clone()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown(std::net::Shutdown::Write)
    }
}

impl Endpoint for UnixStream {
    fn duplicate(&self) -> io::Result<Self> {
        self.try_clone()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown(std::net::Shutdown::Write)
    }
}

/// Something that hands out inbound connections.
pub trait Listener: Send + 'static {
    type Stream: Endpoint;
    fn accept_one(&self) -> io::Result<Self::Stream>;
}

impl Listener for UnixListener {
    type Stream = UnixStream;

    fn accept_one(&self) -> io::Result<Self::Stream> {
        self.accept().map(|(stream, _)| stream)
    }
}

impl Listener for TcpListener {
    type Stream = TcpStream;

    fn accept_one(&self) -> io::Result<Self::Stream> {
        self.accept().map(|(stream, _)| stream)
    }
}

/// Where a pump sends the traffic it accepted.
pub trait Upstream: Send + Clone + 'static {
    type Stream: Endpoint;
    fn connect(&self) -> io::Result<Self::Stream>;
}

/// How many `accept` failures in a row before the pump concludes the listener is
/// gone rather than merely having a bad moment.
///
/// A cap rather than an unconditional retry: a listener that is genuinely broken
/// — a closed descriptor, say — fails instantly and forever, and an uncapped
/// loop would spin on it.
const ACCEPT_FAILURE_LIMIT: u32 = 64;

/// How long to wait before retrying a failed `accept`.
///
/// Short enough to be invisible to a client that is merely unlucky, long enough
/// that the retry budget above spans seconds rather than microseconds.
const ACCEPT_RETRY_PAUSE: std::time::Duration = std::time::Duration::from_millis(20);

/// Accept forever, and splice each connection onto a fresh upstream one.
///
/// A connection that cannot reach its upstream is dropped: the client sees a
/// closed connection, which is the correct signal that policy did not carry it,
/// and one failed dial must not take the accept loop down with it.
///
/// Neither may one failed *accept*. `ECONNABORTED` (the peer went away mid
/// handshake) and `EMFILE` (the process is momentarily out of descriptors) are
/// each about a single client and each routine under load; ending the loop on one
/// would leave the sandbox with no route to the proxy for the rest of the run —
/// and, since nothing else watches the listener, would do it silently.
pub fn serve<L: Listener, U: Upstream>(listener: L, upstream: U) {
    let mut consecutive_failures: u32 = 0;
    loop {
        let inbound = match listener.accept_one() {
            Ok(inbound) => {
                consecutive_failures = 0;
                inbound
            }
            Err(error) => {
                consecutive_failures += 1;
                if consecutive_failures >= ACCEPT_FAILURE_LIMIT {
                    tracing::warn!(
                        %error,
                        "bridge stopped accepting; the sandbox has no route to the proxy"
                    );
                    return;
                }
                // A beat before retrying. The cited failures clear on their own
                // — a descriptor is returned, the next peer completes its
                // handshake — but only if some time passes; retrying 64 times
                // in one instant burst would exhaust the budget while the
                // condition is still there and end the pump anyway.
                tracing::debug!(%error, "bridge accept failed, still listening");
                thread::sleep(ACCEPT_RETRY_PAUSE);
                continue;
            }
        };

        let upstream = upstream.clone();
        thread::spawn(move || match upstream.connect() {
            Ok(outbound) => splice(inbound, outbound),
            Err(error) => {
                tracing::debug!(%error, "bridge could not reach its upstream");
            }
        });
    }
}

/// Copy bytes both ways until each side is done, then half-close that side.
///
/// Each direction gets its own thread because a single-threaded copy would
/// deadlock the moment a protocol has both peers waiting to read — which is
/// every protocol worth proxying.
fn splice<A: Endpoint, B: Endpoint>(a: A, b: B) {
    let (Ok(mut a_read), Ok(mut b_write)) = (a.duplicate(), b.duplicate()) else {
        return;
    };
    let mut a_write = a;
    let mut b_read = b;

    let forward = thread::spawn(move || {
        let _ = io::copy(&mut a_read, &mut b_write);
        let _ = b_write.shutdown_write();
    });

    let _ = io::copy(&mut b_read, &mut a_write);
    let _ = a_write.shutdown_write();
    let _ = forward.join();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[derive(Clone)]
    struct Tcp(SocketAddr);

    impl Upstream for Tcp {
        type Stream = TcpStream;

        fn connect(&self) -> io::Result<Self::Stream> {
            TcpStream::connect(self.0)
        }
    }

    /// Stand in for the proxy: echo every byte back, uppercased, so the test can
    /// tell a real round trip from a coincidence.
    fn spawn_shouting_echo() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo server");
        let addr = listener.local_addr().expect("echo server address");
        thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                thread::spawn(move || {
                    let mut buf = Vec::new();
                    if stream.read_to_end(&mut buf).is_ok() {
                        buf.make_ascii_uppercase();
                        let _ = stream.write_all(&buf);
                    }
                });
            }
        });
        addr
    }

    #[test]
    fn a_bridged_connection_carries_bytes_both_ways() {
        let echo = spawn_shouting_echo();
        let front = TcpListener::bind("127.0.0.1:0").expect("bind bridge front door");
        let front_addr = front.local_addr().expect("bridge address");
        thread::spawn(move || serve(front, Tcp(echo)));

        let mut client = TcpStream::connect(front_addr).expect("reach the bridge");
        client.write_all(b"honmoon").expect("write through bridge");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("half-close so the echo server sees EOF");

        let mut reply = String::new();
        client.read_to_string(&mut reply).expect("read the reply");
        assert_eq!(
            reply, "HONMOON",
            "the bridge must carry bytes to the upstream and the answer back"
        );
    }

    /// A listener that refuses a fixed number of times before behaving, standing
    /// in for `ECONNABORTED` / `EMFILE` — failures that are about one client, not
    /// about the listener.
    struct Flaky {
        inner: TcpListener,
        remaining_failures: std::sync::Mutex<u32>,
    }

    impl Listener for Flaky {
        type Stream = TcpStream;

        fn accept_one(&self) -> io::Result<Self::Stream> {
            {
                let mut remaining = self.remaining_failures.lock().expect("failure counter");
                if *remaining > 0 {
                    *remaining -= 1;
                    return Err(io::Error::from(io::ErrorKind::ConnectionAborted));
                }
            }
            self.inner.accept().map(|(stream, _)| stream)
        }
    }

    #[test]
    fn a_transient_accept_failure_does_not_stop_the_accept_loop() {
        let echo = spawn_shouting_echo();
        let front = TcpListener::bind("127.0.0.1:0").expect("bind bridge front door");
        let front_addr = front.local_addr().expect("bridge address");
        let flaky = Flaky {
            inner: front,
            remaining_failures: std::sync::Mutex::new(5),
        };
        thread::spawn(move || serve(flaky, Tcp(echo)));

        let mut client = TcpStream::connect(front_addr).expect("reach the bridge");
        client.write_all(b"honmoon").expect("write through bridge");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("half-close so the echo server sees EOF");

        let mut reply = String::new();
        client.read_to_string(&mut reply).expect("read the reply");
        assert_eq!(
            reply, "HONMOON",
            "an aborted handshake concerns one client; ending the accept loop on \
             it would leave the sandbox with no route to the proxy at all"
        );
    }

    #[test]
    fn one_unreachable_upstream_does_not_stop_the_accept_loop() {
        // A port nobody is listening on: reserve one, then drop the listener.
        let dead = {
            let probe = TcpListener::bind("127.0.0.1:0").expect("reserve a port");
            probe.local_addr().expect("reserved address")
        };
        let front = TcpListener::bind("127.0.0.1:0").expect("bind bridge front door");
        let front_addr = front.local_addr().expect("bridge address");
        thread::spawn(move || serve(front, Tcp(dead)));

        // First connection cannot be spliced anywhere and is dropped.
        let mut doomed = TcpStream::connect(front_addr).expect("reach the bridge");
        let _ = doomed.write_all(b"lost");
        let mut discarded = Vec::new();
        let _ = doomed.read_to_end(&mut discarded);

        // The loop has to still be there for the next one.
        let survivor = TcpStream::connect(front_addr);
        assert!(
            survivor.is_ok(),
            "a failed upstream dial must not take the accept loop down with it"
        );
    }
}
