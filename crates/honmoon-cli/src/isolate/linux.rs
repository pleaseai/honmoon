//! Enforced `honmoon run` isolation on Linux: an empty network namespace with
//! the proxy bridged in over a Unix socket (ADR-0005).
//!
//! The shape, and why each piece is here:
//!
//! 1. The parent binds the proxy on host loopback and opens a Unix socket in a
//!    private directory. A pump behind that socket dials the proxy.
//! 2. The child is forked with a `pre_exec` hook that unshares a new user and
//!    network namespace, writes a 1:1 uid/gid map, and brings `lo` up. The new
//!    network namespace has no interface but loopback and no route anywhere, so
//!    nothing in it can reach the host's network.
//! 3. The child execs `honmoon` again, into [`supervise`], which listens on
//!    loopback inside the namespace and pumps to the Unix socket. Unix sockets
//!    are addressed by filesystem path rather than by network namespace, which
//!    is the one channel that still crosses the boundary.
//! 4. `supervise` runs the user's command with the proxy variables pointed at
//!    its own loopback port.
//!
//! A child that ignores those variables does not escape — it reaches nothing,
//! because there is nothing in its namespace to reach. That is the whole
//! difference between this and the advisory path.
//!
//! The honest boundary is unchanged from ADR-0004: this confines an
//! **unprivileged** child. A child that can become root on the host, already
//! holds `CAP_SYS_ADMIN`, or has passwordless `sudo` can leave the namespace.

use std::ffi::CStr;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::thread;

use super::bridge::{self, Upstream};

/// Hidden subcommand name for the in-namespace supervisor.
///
/// Not a public interface: it exists because the namespace has to be entered by
/// `pre_exec` — which can only be followed by an `exec` — so the code that runs
/// inside it must arrive as a fresh process image.
pub const SUPERVISE_SUBCOMMAND: &str = "__supervise-sandbox";

// Fixed by the Linux ioctl ABI. Spelled out here rather than taken from `libc`
// so the build does not depend on which of these the crate happens to re-export
// for a given target.
const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
const SIOCSIFFLAGS: libc::c_ulong = 0x8914;
const IFF_UP: libc::c_short = 0x1;
const IFF_RUNNING: libc::c_short = 0x40;

/// `struct ifreq`, narrowed to the one union member this module touches.
///
/// The real union is 24 bytes wide; the tail is padding here because only
/// `ifr_flags` is ever read or written, and a wrong total size would corrupt the
/// caller's stack on the `SIOCGIFFLAGS` copy-out.
#[repr(C)]
struct IfReq {
    name: [libc::c_char; 16],
    flags: libc::c_short,
    _rest_of_union: [u8; 22],
}

/// Can this host give a child an empty namespace at all?
///
/// Answered by trying it in a throwaway child rather than by reading kernel
/// settings, because the ways this is refused are plural — `user.max_user_namespaces`
/// at zero, a hardened distribution's AppArmor restriction, a container seccomp
/// profile that denies the syscall — and they do not share one readable flag.
///
/// The probe forks and touches nothing but `unshare` and `_exit`, both
/// async-signal-safe, which matters because this process is already running the
/// proxy on other threads.
pub fn namespaces_available() -> bool {
    // SAFETY: the child path calls only async-signal-safe functions before
    // `_exit`, which is the requirement for `fork` from a threaded process.
    unsafe {
        match libc::fork() {
            -1 => false,
            0 => {
                let unshared = libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET);
                libc::_exit(if unshared == 0 { 0 } else { 1 });
            }
            child => {
                let mut status: libc::c_int = 0;
                if libc::waitpid(child, &mut status, 0) < 0 {
                    return false;
                }
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
            }
        }
    }
}

/// The host end of the bridge: a private directory holding one Unix socket that
/// pumps to the proxy, removed when this value is dropped.
struct HostBridge {
    dir: PathBuf,
    socket: PathBuf,
}

#[derive(Clone)]
struct ProxyUpstream(SocketAddr);

impl Upstream for ProxyUpstream {
    type Stream = TcpStream;

    fn connect(&self) -> io::Result<Self::Stream> {
        TcpStream::connect(self.0)
    }
}

#[derive(Clone)]
struct SocketUpstream(PathBuf);

impl Upstream for SocketUpstream {
    type Stream = UnixStream;

    fn connect(&self) -> io::Result<Self::Stream> {
        UnixStream::connect(&self.0)
    }
}

impl HostBridge {
    /// Open the socket and start pumping to `proxy`.
    fn open(proxy: SocketAddr) -> io::Result<Self> {
        use std::os::unix::fs::PermissionsExt;

        // `0700` on the directory is what keeps the socket off-limits to other
        // users on the box: a Unix socket's own mode is not honoured everywhere,
        // but the containing directory's traverse bit always is. Anyone who
        // could connect here would be handed an unauthenticated path to the
        // proxy, and through it to whatever the policy allows.
        let dir = std::env::temp_dir().join(format!("honmoon-{}", std::process::id()));
        std::fs::create_dir(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;

        let socket = dir.join("proxy.sock");
        let listener = UnixListener::bind(&socket)?;
        thread::spawn(move || bridge::serve(listener, ProxyUpstream(proxy)));

        Ok(Self { dir, socket })
    }

    fn socket(&self) -> &Path {
        &self.socket
    }
}

impl Drop for HostBridge {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Run `program` with `args` confined to an empty network namespace.
///
/// An `Err` here always means the setup failed *before* the user's command could
/// run, so the caller may fall back to the advisory path without any risk of
/// running the command twice. Once the supervisor has been exec'd, everything
/// that follows is reported as its exit status.
pub fn run_confined(
    proxy: SocketAddr,
    program: &str,
    args: &[String],
) -> io::Result<(ExitStatus, HostBridgeGuard)> {
    let host_bridge = HostBridge::open(proxy)?;

    // Built before the fork: `pre_exec` runs between `fork` and `exec` in a
    // process that still has the proxy's threads in its memory image, where
    // allocating can deadlock on an allocator lock another thread held at the
    // moment of the fork. Everything the hook touches must already exist.
    // SAFETY: `getuid`/`getgid` cannot fail and have no side effects.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let uid_map = format!("{uid} {uid} 1\n").into_bytes();
    let gid_map = format!("{gid} {gid} 1\n").into_bytes();

    let executable = std::env::current_exe()?;
    let mut command = Command::new(executable);
    command
        .arg(SUPERVISE_SUBCOMMAND)
        .arg("--bridge-socket")
        .arg(host_bridge.socket())
        .arg("--")
        .arg(program)
        .args(args);

    // SAFETY: the hook calls only raw syscalls — `unshare`, `open`, `write`,
    // `close`, `socket`, `ioctl` — and allocates nothing.
    unsafe {
        command.pre_exec(move || enter_empty_namespace(&uid_map, &gid_map));
    }

    let status = command.status()?;
    Ok((status, HostBridgeGuard(host_bridge)))
}

/// Keeps the host bridge alive for as long as the caller holds it.
pub struct HostBridgeGuard(#[allow(dead_code)] HostBridge);

/// Unshare into a new user + network namespace and make loopback usable.
///
/// Runs after `fork` and before `exec`, so it is restricted to async-signal-safe
/// calls and must not allocate.
fn enter_empty_namespace(uid_map: &[u8], gid_map: &[u8]) -> io::Result<()> {
    // SAFETY: raw syscalls only, with every buffer supplied by the caller.
    unsafe {
        if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    // `setgroups` has to be denied before `gid_map` will accept a write from a
    // process without `CAP_SETGID` in the parent namespace. The kernel enforces
    // the order; getting it wrong surfaces as `EPERM` on the next line.
    write_once(c"/proc/self/setgroups", b"deny")?;
    write_once(c"/proc/self/gid_map", gid_map)?;
    write_once(c"/proc/self/uid_map", uid_map)?;

    bring_loopback_up()
}

/// Write `data` to `path` in exactly one `write`.
///
/// The uid/gid map files reject a second write and reject a partial one, so a
/// short write is a hard error rather than something to loop over.
fn write_once(path: &CStr, data: &[u8]) -> io::Result<()> {
    // SAFETY: `path` is NUL-terminated by construction and `data` is a valid
    // slice for the length passed.
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let written = libc::write(fd, data.as_ptr().cast(), data.len());
        let failed = written < 0 || written as usize != data.len();
        let error = io::Error::last_os_error();
        libc::close(fd);
        if failed {
            return Err(if written < 0 {
                error
            } else {
                io::Error::new(io::ErrorKind::WriteZero, "short write to a namespace map")
            });
        }
    }
    Ok(())
}

/// Bring `lo` up inside the new namespace.
///
/// A fresh network namespace has a loopback interface but leaves it `DOWN`, so
/// `127.0.0.1` is unreachable until this runs — which would make the supervisor's
/// own listener useless. The new user namespace grants `CAP_NET_ADMIN` over the
/// network namespace it owns, so no host privilege is involved.
fn bring_loopback_up() -> io::Result<()> {
    // SAFETY: `request` is a fixed ioctl number and `ifreq` matches the kernel's
    // 40-byte layout, so the copy-out cannot overrun.
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if sock < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut request = IfReq {
            name: [0; 16],
            flags: 0,
            _rest_of_union: [0; 22],
        };
        request.name[0] = b'l' as libc::c_char;
        request.name[1] = b'o' as libc::c_char;

        let mut result = libc::ioctl(sock, SIOCGIFFLAGS as _, &raw mut request);
        if result == 0 {
            request.flags |= IFF_UP | IFF_RUNNING;
            result = libc::ioctl(sock, SIOCSIFFLAGS as _, &raw const request);
        }
        let error = io::Error::last_os_error();
        libc::close(sock);
        if result != 0 {
            return Err(error);
        }
    }
    Ok(())
}

/// The in-namespace half: listen on loopback, pump to the host's Unix socket,
/// and run the user's command against that port.
///
/// Reached only through [`SUPERVISE_SUBCOMMAND`], as the exec target of
/// [`run_confined`].
pub fn supervise(bridge_socket: &Path, argv: &[String]) -> io::Result<ExitStatus> {
    let (program, args) = argv.split_first().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "no command to supervise inside the sandbox",
        )
    })?;

    // Port 0: the supervisor picks the child's proxy port itself and puts it in
    // the environment, so nothing has to agree on a fixed number, and two
    // sandboxes on one host cannot collide.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();

    let socket = bridge_socket.to_path_buf();
    thread::spawn(move || bridge::serve(listener, SocketUpstream(socket)));

    let proxy_url = format!("http://127.0.0.1:{port}");
    let mut command = Command::new(program);
    command.args(args);
    for (key, value) in super::proxy_env(&proxy_url) {
        command.env(key, value);
    }
    command.status()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifreq_matches_the_kernel_layout() {
        // A wrong size means `SIOCGIFFLAGS` writes past our struct. The kernel's
        // `struct ifreq` is a 16-byte name plus a 24-byte union.
        assert_eq!(
            std::mem::size_of::<IfReq>(),
            40,
            "ifreq must be 40 bytes or the ioctl copy-out corrupts the stack"
        );
    }

    #[test]
    fn a_short_write_is_reported_rather_than_retried() {
        // /proc/self/setgroups is the one map-like file safe to open read-only
        // here; opening a directory for writing fails, which is the error path
        // this asserts is surfaced rather than swallowed.
        let error = write_once(c"/proc", b"deny").expect_err("writing a directory must fail");
        assert!(
            error.raw_os_error().is_some(),
            "the OS error has to reach the caller, got: {error}"
        );
    }

    #[test]
    fn supervise_rejects_an_empty_command() {
        let error = supervise(Path::new("/nonexistent.sock"), &[])
            .expect_err("an empty argv has nothing to supervise");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
