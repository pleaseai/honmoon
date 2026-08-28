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

/// Accept forever, and splice each connection onto a fresh upstream one.
///
/// Runs until the listener fails, which for our listeners means the process is
/// going away. A connection that cannot reach its upstream is dropped: the
/// client sees a closed connection, which is the correct signal that policy did
/// not carry it, and one failed dial must not take the accept loop down with it.
pub fn serve<L: Listener, U: Upstream>(listener: L, upstream: U) {
    while let Ok(inbound) = listener.accept_one() {
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
