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
//!
//! One more limit is worth naming, because "no network" reads stronger than it
//! is: only the *network* namespace is unshared, not the mount namespace. IP is
//! gone and so are abstract Unix sockets (they are per-netns), but Unix sockets
//! that live in the filesystem are not — a child that can open
//! `/var/run/docker.sock`, or any other local daemon's socket, still reaches
//! whatever that daemon will do for it. Keep such sockets away from the uid you
//! run under, or use `honmoon join` where that matters.
//!
//! Stdio is the same shape of exception. Descriptor cleanup starts above the
//! first three, because the child needs a stdin, stdout and stderr to be a
//! usable command at all — so a *connected network socket* handed to `honmoon`
//! as one of those three is inherited by the child and stays a live channel to
//! that one peer, empty namespace or not. A socket keeps its binding across
//! `unshare`. This is a property of how honmoon was launched rather than
//! anything the child can arrange for itself: it needs an operator to have
//! already wired honmoon's stdio to a network peer.

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
/// `align(8)` because the kernel's `struct ifreq` carries a union of pointers
/// and sockaddrs and is 8-byte aligned; the narrowed form here would otherwise
/// inherit `c_short`'s 2-byte alignment and model the C type more weakly than
/// the ioctl it is handed to expects.
#[repr(C, align(8))]
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
                // `waitpid` returning `EINTR` says a signal arrived, not that
                // the probe failed. Treating it as failure would downgrade the
                // whole run to advisory because something unrelated — a
                // `SIGWINCH`, a profiler's timer — happened to land here.
                let mut status: libc::c_int = 0;
                loop {
                    if libc::waitpid(child, &mut status, 0) >= 0 {
                        break;
                    }
                    if io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                        return false;
                    }
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
        let dir = private_scratch_dir()?;
        let socket = dir.join(SOCKET_FILE);

        // Own the directory before anything else can fail, so an error below
        // takes the scratch directory with it rather than leaving one behind
        // that the *next* run would then trip over.
        let opened = Self { dir, socket };
        let listener = UnixListener::bind(&opened.socket)?;
        thread::spawn(move || bridge::serve(listener, ProxyUpstream(proxy)));

        Ok(opened)
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

/// How many random bytes name a scratch directory.
///
/// 96 bits. The name only has to be unguessable *before* the directory exists —
/// the attack it defeats is squatting the path this run is about to ask for —
/// and 2^96 is far past reach for that. The reason not to spend more is
/// [`SUN_PATH_LIMIT`]: every hex character here costs a byte of the socket path
/// budget, and running out of that budget is itself a fail-open.
const SCRATCH_NAME_BYTES: usize = 12;

/// How many bytes fit in `sockaddr_un::sun_path`, NUL included.
///
/// Fixed by the AF_UNIX ABI. A `bind` past it fails, and a failed bind means
/// [`HostBridge::open`] errors and the run drops to advisory — so the path is
/// kept inside the limit by construction rather than discovered to be too long
/// at bind time.
const SUN_PATH_LIMIT: usize = 108;

/// The socket file created inside the scratch directory.
const SOCKET_FILE: &str = "proxy.sock";

/// Fill `buffer` from the kernel's random pool.
///
/// `getrandom` first because it needs no descriptor, and the fallback does: a
/// process that has run out of descriptors is precisely one that cannot open
/// `/dev/urandom` either. Both can return short or be interrupted, so both are
/// looped rather than called once.
///
/// There is deliberately no time- or pid-derived last resort. A guessable name
/// is the failure this exists to prevent, so no randomness means no run: the
/// caller reports a setup error, which happens before the child exists and which
/// [`run_confined`]'s contract already handles.
fn fill_random(buffer: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < buffer.len() {
        // SAFETY: the pointer and length describe the unfilled tail of a slice
        // this call borrows exclusively.
        let read = unsafe {
            libc::getrandom(
                buffer[filled..].as_mut_ptr().cast(),
                buffer.len() - filled,
                0,
            )
        };
        if read > 0 {
            filled += read as usize;
            continue;
        }
        if read < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        // `ENOSYS` on a kernel older than 3.17, `EPERM` under a seccomp filter
        // that denies the syscall: the device node answers both.
        use std::io::Read as _;
        return std::fs::File::open("/dev/urandom")?.read_exact(&mut buffer[filled..]);
    }
    Ok(())
}

/// Create a directory only this user can enter, under a name nobody else holds.
///
/// `0700` is what keeps the socket off-limits to other users on the box: a Unix
/// socket's own mode is not honoured everywhere, but the containing directory's
/// traverse bit always is. Anyone who could connect there would be handed an
/// unauthenticated path to the proxy, and through it to whatever policy allows.
/// The mode is set *at creation* rather than by a following `chmod`, because
/// `create_dir` honours the umask and the gap between the two calls is a window
/// in which a world-writable directory exists under a predictable name.
///
/// The name is random for a reason worth spelling out. It used to be derived
/// from the pid, which meant another local user with write access to the temp
/// directory could pre-create every candidate — `honmoon-<pid>` and each of its
/// numbered retries, or the whole plausible pid range on a shared runner — and
/// every attempt would come back `AlreadyExists`. That is a fail-open an
/// unprivileged outsider can trigger at will: the bridge never opens,
/// [`run_confined`] returns an error, and the run silently drops to advisory,
/// which is the one state where ignoring `http_proxy` works.
///
/// A taken name is still stepped over rather than treated as fatal — a random
/// collision is not a reason to stop enforcing either.
///
/// The directory goes under `TMPDIR` only when the resulting socket path fits in
/// [`SUN_PATH_LIMIT`], and under `/tmp` otherwise. A long `TMPDIR` would
/// otherwise push the socket past the AF_UNIX limit and fail the bind — the same
/// silent downgrade to advisory this function's random name exists to prevent,
/// arriving by a different route.
fn private_scratch_dir() -> io::Result<PathBuf> {
    use std::fmt::Write as _;
    use std::fs::DirBuilder;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    // "/honmoon-" + the hex name + "/" + the socket file + the trailing NUL.
    let suffix = 1 + "honmoon-".len() + SCRATCH_NAME_BYTES * 2 + 1 + SOCKET_FILE.len() + 1;
    let preferred = std::env::temp_dir();
    let temp = if preferred.as_os_str().len() + suffix <= SUN_PATH_LIMIT {
        preferred
    } else {
        PathBuf::from("/tmp")
    };
    for _ in 0..16 {
        let mut random = [0_u8; SCRATCH_NAME_BYTES];
        fill_random(&mut random)?;
        let mut name = String::from("honmoon-");
        for byte in random {
            let _ = write!(name, "{byte:02x}");
        }

        let dir = temp.join(&name);
        match DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => {
                // `mkdir` intersects the requested mode with the umask, so the
                // 0700 above is a ceiling rather than a guarantee: under
                // `umask 0100` the directory arrives 0600, and under
                // `umask 0777` it arrives 000. Either way nobody can traverse
                // it, the socket below cannot be bound, and the run drops to
                // advisory — the same fail-open this function's random name
                // exists to prevent, arriving through the caller's umask.
                //
                // Restoring the mode afterwards is not the window a
                // create-then-chmod would open. That pattern is unsafe because
                // it starts *wider* than intended; this one only ever moves
                // from more restrictive to 0700, and the group and world bits
                // were never requested, so there is no instant at which anyone
                // else could enter.
                if let Err(error) =
                    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                {
                    // Best-effort cleanup, and it has to happen here: the path
                    // has not been handed to `HostBridge` yet, so its `Drop`
                    // cannot remove it, and returning without this would strand
                    // a directory nothing owns on every such failure.
                    let _ = std::fs::remove_dir_all(&dir);
                    return Err(error);
                }
                return Ok(dir);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "no free scratch directory for the bridge socket",
    ))
}

/// Run `program` with `args` confined to an empty network namespace.
///
/// An `Err` here always means the setup failed *before* the user's command could
/// run, so the caller may fall back to the advisory path without any risk of
/// running the command twice. That invariant is why the spawn and the wait are
/// separate calls rather than one `status()`: everything `spawn` can report
/// happens before the `exec`, while a failed `wait` would be a *post*-exec error
/// that a caller reading it as "setup failed" would answer by starting the
/// command a second time — unconfined, alongside the first.
pub fn run_confined(proxy: SocketAddr, program: &str, args: &[String]) -> io::Result<ExitStatus> {
    use std::os::unix::process::ExitStatusExt;

    // Held as a local, never handed to the caller: the wait below already blocks
    // until the child is gone, so the bridge has no reason to outlive this
    // frame — and a guard returned into a caller that ends in
    // `std::process::exit` would never be dropped at all, leaking the scratch
    // directory on every run.
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

    let mut child = command.spawn()?;

    // Past this line the user's command is running. Losing the child — a
    // reaped-elsewhere `ECHILD`, say — is reported as a failing exit status
    // rather than an `Err`, because an `Err` here would be read as "isolation
    // never started" and answered by running the command again.
    let status = child.wait().unwrap_or_else(|error| {
        tracing::error!(%error, "lost track of the sandboxed command");
        ExitStatus::from_raw(1 << 8)
    });
    drop(host_bridge);
    Ok(status)
}

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
            // Both branches build an `io::Error` without allocating: an errno
            // error is stored inline, and `From<ErrorKind>` is a bare tag. The
            // `io::Error::new(_, "message")` spelling would box the message,
            // which is a heap allocation — forbidden here, because this runs
            // between `fork` and `exec` where another thread may have held the
            // allocator lock at the moment of the fork.
            return Err(if written < 0 {
                error
            } else {
                io::Error::from(io::ErrorKind::WriteZero)
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

/// Close every descriptor above stdio before the sandboxed command can inherit
/// one.
///
/// Rust opens its own sockets and files `O_CLOEXEC`, so nothing this process
/// created reaches here. What can is a descriptor that leaked into `honmoon`
/// from *its* parent without that flag — a shell's stray redirect, a C
/// library's socket — which survives both execs. An already-connected socket
/// keeps the peer it had when it was opened, so it still carries traffic inside
/// the empty namespace: exactly the route this module exists to remove.
///
/// An individual `close` that fails is ignored — a descriptor that will not
/// close is not a reason to refuse the run, and the ones that matter are gone by
/// then. What is *not* ignored is being unable to enumerate the descriptors at
/// all: an `Err` here means no tier could establish what to close, and the
/// caller refuses to launch rather than running the command with the escape
/// route possibly still open.
fn close_inherited_descriptors() -> io::Result<()> {
    // `close_range` is one syscall for the whole span, so nothing can be opened
    // between two closes. Invoked through `syscall` rather than a wrapper so the
    // build does not depend on which targets the `libc` crate re-exports it for.
    //
    // The bounds are `c_long` because Rust, unlike C, passes a variadic argument
    // as exactly the type it was given — there is no promotion to `long` here.
    // Handing a 32-bit value to a variadic that reads register-sized arguments
    // leaves the top half of the register to chance, and a garbage `flags` is
    // `EINVAL`: the sweep would report failure and fall through to the slower
    // tiers on every run.
    let first: libc::c_long = 3;
    let last: libc::c_long = libc::c_uint::MAX as libc::c_long;
    let flags: libc::c_long = 0;
    // SAFETY: a syscall with three integer arguments and no pointers.
    let closed_everything =
        unsafe { libc::syscall(libc::SYS_close_range, first, last, flags) == 0 };
    if closed_everything {
        return Ok(());
    }

    // Older kernels (pre-5.9) and seccomp profiles that do not know the syscall
    // land here. `/proc/self/fd` is collected in full *before* anything is
    // closed, because the directory handle is itself one of the entries and
    // closing it mid-iteration would end the walk early, leaving the rest open.
    let Ok(entries) = std::fs::read_dir("/proc/self/fd") else {
        return close_up_to_the_descriptor_limit();
    };
    let open: Vec<i32> = entries
        .filter_map(|entry| {
            let name = entry.ok()?.file_name();
            name.to_str()?.parse().ok()
        })
        .collect();
    for fd in open {
        if fd > 2 {
            // SAFETY: `close` on a descriptor that is already gone returns
            // `EBADF`, which is exactly the outcome being ignored here.
            unsafe {
                libc::close(fd);
            }
        }
    }
    Ok(())
}

/// The last resort: close every descriptor from 3 up to the process limit.
///
/// A `close` on a number that was never open returns `EBADF`, which is exactly
/// the outcome being ignored, so sweeping the whole range is correct however
/// many descriptors are actually there. It is last because it is the expensive
/// one — up to the soft limit in syscalls, where the other two tiers cost one
/// apiece — and it is reached only when both cheap mechanisms are gone at once:
/// a kernel without `close_range` on a host with no `/proc` mounted.
///
/// The **entire** soft limit is swept, not a convenient prefix of it. A sweep
/// that stopped early would leave descriptors open above the cut while still
/// reporting success, which is worse than an honest failure: the caller would
/// run the command believing the escape route was closed.
///
/// So when the limit is `RLIM_INFINITY` — nothing to enumerate, and no way to
/// know where to stop — this fails rather than guessing a bound. That combination
/// (no `close_range`, no `/proc`, no finite limit) should not occur in practice,
/// and refusing to launch is the right direction for a function whose job is
/// removing a way out of the sandbox.
fn close_up_to_the_descriptor_limit() -> io::Result<()> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `getrlimit` writes into an `rlimit` this frame owns.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if limit.rlim_cur == libc::RLIM_INFINITY {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cannot enumerate the descriptors to close: no close_range, no \
             /proc, and no finite descriptor limit",
        ));
    }

    // A descriptor number is a `c_int`, so a soft limit above `c_int::MAX`
    // describes numbers that cannot exist; stopping there still sweeps every
    // descriptor the process could actually hold.
    let bound = limit.rlim_cur.min(libc::c_int::MAX as libc::rlim_t) as libc::c_int;
    for fd in 3..bound {
        // SAFETY: `close` on a descriptor that is not open returns `EBADF`.
        unsafe {
            libc::close(fd);
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

    // Here rather than in `run_confined`'s `pre_exec` hook, and deliberately so:
    // between `fork` and `exec` Rust's `Command` still holds a `CLOEXEC` pipe it
    // uses to report a failed `exec` to the parent, and closing that pipe would
    // make a failed spawn look like a successful one. This process is past both
    // execs, so the only descriptors left are stdio and whatever leaked in. It
    // sits after the argv check so the "nothing to supervise" path — which the
    // unit tests take in-process — does not shut the caller's descriptors. A
    // failure to enumerate is propagated rather than swallowed: running the
    // command anyway would be claiming a confinement that was never applied.
    close_inherited_descriptors()?;

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
    // An inherited `no_proxy` is meaningless in here and actively harmful: the
    // hosts it exempts have no route out of this namespace, so a client that
    // honours it stops using the one channel that works and fails on a name the
    // operator listed precisely because they wanted it reachable. It is replaced
    // rather than removed, because loopback has to stay direct: the child's own
    // `127.0.0.1` lives inside this namespace, and sending a request for it
    // through the proxy would bridge it out and resolve it against the *host's*
    // loopback — a different machine's worth of services than the child meant.
    let loopback_direct = "localhost,127.0.0.1,::1";
    command
        .env("no_proxy", loopback_direct)
        .env("NO_PROXY", loopback_direct);
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
    fn a_scratch_directory_is_private_from_the_moment_it_exists() {
        use std::os::unix::fs::PermissionsExt;

        let dir = private_scratch_dir().expect("create a scratch directory");
        let mode = std::fs::metadata(&dir)
            .expect("stat the scratch directory")
            .permissions()
            .mode()
            & 0o777;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            mode, 0o700,
            "another local user who can enter this directory gets an \
             unauthenticated path to the proxy"
        );
    }

    #[test]
    fn successive_scratch_directories_are_distinct_and_private() {
        // This used to squat the pid-derived name to exercise the
        // `AlreadyExists` retry. The name is random now — precisely so that a
        // local user *cannot* squat it and force the run down to advisory —
        // which leaves no name a test could pre-create either. What is left to
        // assert is the property that makes the retry near-unreachable in the
        // first place: two calls are handed two different directories, and each
        // is private from the moment it exists rather than after a later
        // `chmod`.
        use std::os::unix::fs::PermissionsExt;

        let first = private_scratch_dir().expect("create a scratch directory");
        let second = private_scratch_dir().expect("create a second scratch directory");
        let modes = [&first, &second].map(|dir| {
            std::fs::metadata(dir)
                .expect("stat the scratch directory")
                .permissions()
                .mode()
                & 0o777
        });
        let distinct = first != second;
        let _ = std::fs::remove_dir_all(&first);
        let _ = std::fs::remove_dir_all(&second);
        assert!(
            distinct,
            "the second directory has to be a different one, not the same path \
             handed out twice"
        );
        assert_eq!(
            modes,
            [0o700, 0o700],
            "another local user who can enter one of these gets an \
             unauthenticated path to the proxy"
        );
    }

    #[test]
    fn supervise_rejects_an_empty_command() {
        let error = supervise(Path::new("/nonexistent.sock"), &[])
            .expect_err("an empty argv has nothing to supervise");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
