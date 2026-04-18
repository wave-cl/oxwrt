//! Per-service supervisor: namespaces + cgroups v2 + pivot_root, driven
//! directly by rustix. No OCI, no LXC.
//!
//! Two spawn paths:
//! - **Default (`user_namespace = false`):** `tokio::process::Command` with a
//!   `pre_exec` that calls `unshare(NEWNS|NEWUTS|...)` + rootfs setup + harden.
//!   Simple, well-tested, covers caps + no_new_privs + seccomp + landlock.
//! - **User namespace (`user_namespace = true`):** raw `clone3(2)` with
//!   `CLONE_NEWUSER | CLONE_NEWPID | NEWNS | NEWUTS | NEWIPC | NEWCGROUP`
//!   (+ NEWNET for isolated services). The child is born *inside* all
//!   namespaces. Parent writes uid_map/gid_map, signals child via pipe,
//!   child does rootfs setup + harden + execve. This avoids the three
//!   kernel barriers that block the `unshare(NEWUSER)` path: pivot_root
//!   EPERM, mount("proc") EPERM, mount("tmpfs") EOVERFLOW.

use std::collections::{BTreeMap, HashSet};
use std::ffi::{CString, OsStr};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

use caps::{CapSet, Capability};
use landlock::{
    ABI, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreated, RulesetCreatedAttr,
};
use rustix::ffi::CStr;
use rustix::fd::AsFd;
use rustix::mount::{
    MountFlags, MountPropagationFlags, UnmountFlags, mount, mount_bind, mount_change,
    mount_remount, unmount,
};
use rustix::process::{chdir, pivot_root};
use rustix::system::sethostname;
use rustix::thread::{UnshareFlags, unshare_unsafe};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

use crate::config::{NetMode, SecurityProfile, Service};
use crate::logd::Logd;
use crate::rpc::ServiceState;

const CGROUP_ROOT: &str = "/sys/fs/cgroup/svc";
const CGROUP_UNIFIED: &str = "/sys/fs/cgroup";
const BACKOFF_INITIAL: Duration = Duration::from_millis(100);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
const PUT_OLD_REL: &str = ".old_root";

/// The host uid/gid that container uid 0 maps to when `user_namespace`
/// is enabled. 65534 = `nobody` on most Linux distros. Chosen because
/// it has no login shell, no home directory, and (critically) no file
/// ownership on the host filesystem — so a container escape can't
/// read, write, or chown anything root-owned.
const USERNS_HOST_UID: u32 = 65534;
const USERNS_HOST_GID: u32 = 65534;

// ── clone3 infrastructure ───────────────────────────────────────────

/// Kernel `struct clone_args` for the `clone3(2)` syscall. We only use
/// a subset of the fields; the rest are zeroed. Must be `repr(C)` and
/// match the kernel layout exactly. Linux ≥ 5.3.
#[repr(C)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

/// Raw `clone3(2)` wrapper. Returns the child PID to the parent, or 0
/// in the child. Panics on architectures without `SYS_clone3` (should
/// never happen — we target Linux ≥ 7.0).
///
/// # Safety
/// Caller is responsible for the usual fork-safety contract: no locks,
/// no allocations, no stdio in the child before exec.
unsafe fn raw_clone3(flags: u64) -> io::Result<libc::pid_t> {
    let mut args = CloneArgs {
        flags,
        pidfd: 0,
        child_tid: 0,
        parent_tid: 0,
        exit_signal: libc::SIGCHLD as u64,
        stack: 0,
        stack_size: 0,
        tls: 0,
        set_tid: 0,
        set_tid_size: 0,
        cgroup: 0,
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &mut args as *mut CloneArgs,
            std::mem::size_of::<CloneArgs>(),
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as libc::pid_t)
    }
}

/// Write uid_map + gid_map for a child in a new user namespace.
/// Called on the parent side after clone3 returns the child PID.
fn write_uid_gid_map(child_pid: i32) -> io::Result<()> {
    let proc = format!("/proc/{child_pid}");
    tracing::debug!(child_pid, "writing uid_map/gid_map");

    // setgroups must be "deny" before gid_map when the parent is
    // writing from outside the child's userns.
    std::fs::write(format!("{proc}/setgroups"), "deny")?;
    std::fs::write(
        format!("{proc}/uid_map"),
        format!("0 {USERNS_HOST_UID} 1\n"),
    )?;
    std::fs::write(
        format!("{proc}/gid_map"),
        format!("0 {USERNS_HOST_GID} 1\n"),
    )?;

    tracing::debug!(child_pid, "uid_map/gid_map written");
    Ok(())
}

/// A child process created via raw `clone3(2)`. Provides the subset
/// of the `tokio::process::Child` interface that the supervisor and
/// `diag_exec` paths need.
pub struct RawChild {
    pid: i32,
    reaped: bool,
}

impl RawChild {
    fn id(&self) -> Option<u32> {
        if self.reaped { None } else { Some(self.pid as u32) }
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if self.reaped {
            return Ok(None);
        }
        let mut status: libc::c_int = 0;
        let ret = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
        if ret == 0 {
            Ok(None)
        } else if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            self.reaped = true;
            Ok(Some(ExitStatus::from_raw(status)))
        }
    }
}

/// Unified child handle for both the `tokio::process::Command` path
/// (default) and the raw `clone3` path (`user_namespace = true`).
pub enum AnyChild {
    Tokio(Child),
    Raw(RawChild),
}

impl AnyChild {
    pub fn id(&self) -> Option<u32> {
        match self {
            Self::Tokio(c) => c.id(),
            Self::Raw(c) => c.id(),
        }
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        match self {
            Self::Tokio(c) => c.try_wait(),
            Self::Raw(c) => c.try_wait(),
        }
    }
}

/// Minimum uptime a dependency must accumulate before its dependents
/// are allowed to start. Approximates "dep has finished initializing"
/// without any cooperation from the dep itself — if a dep crashes on
/// startup, it never reaches this threshold and dependents stay
/// blocked. Empirically chosen: hickory-dns, ntpd-rs, and coredhcp all
/// bind their listeners within ~200-400 ms on the target hardware, so
/// 1 second is comfortably past the typical "initial bind" moment.
const DEP_STARTUP_GRACE: Duration = Duration::from_secs(1);

#[cfg(target_arch = "x86_64")]
const SECCOMP_TARGET_ARCH: TargetArch = TargetArch::x86_64;
#[cfg(target_arch = "aarch64")]
const SECCOMP_TARGET_ARCH: TargetArch = TargetArch::aarch64;

/// Syscalls denied for any service whose `SecurityProfile.seccomp == true`.
/// These are the ones that either grant new privileges, escape namespaces,
/// load kernel code, manipulate the kernel keyring, or otherwise have no
/// place in an appliance service. The list is intentionally small — it's a
/// deny list, not an allow list, so we only block what is definitely wrong.
/// Anything not on this list passes through to the kernel unchanged. A
/// matched syscall returns EPERM (not SIGKILL) so a service author can debug
/// without the kernel rugpulling them.
///
/// `(name, nr)` pairs so that `SecurityProfile.seccomp_allow` can punch
/// per-service holes by name. The name is the bare syscall name without the
/// `SYS_` prefix.
const SECCOMP_DENY_LIST: &[(&str, i64)] = &[
    ("ptrace", libc::SYS_ptrace),
    ("mount", libc::SYS_mount),
    ("umount2", libc::SYS_umount2),
    ("pivot_root", libc::SYS_pivot_root),
    ("setns", libc::SYS_setns),
    ("unshare", libc::SYS_unshare),
    ("init_module", libc::SYS_init_module),
    ("finit_module", libc::SYS_finit_module),
    ("delete_module", libc::SYS_delete_module),
    ("bpf", libc::SYS_bpf),
    ("keyctl", libc::SYS_keyctl),
    ("add_key", libc::SYS_add_key),
    ("request_key", libc::SYS_request_key),
    ("kexec_load", libc::SYS_kexec_load),
    ("reboot", libc::SYS_reboot),
    ("swapon", libc::SYS_swapon),
    ("swapoff", libc::SYS_swapoff),
    ("userfaultfd", libc::SYS_userfaultfd),
    ("perf_event_open", libc::SYS_perf_event_open),
    ("syslog", libc::SYS_syslog),
    ("acct", libc::SYS_acct),
    ("quotactl", libc::SYS_quotactl),
];

/// Enable the memory / cpu / pids controllers in the unified-hierarchy
/// root and in our `/svc` subtree so services under `svc/<name>/` can
/// actually receive `memory.max`/`cpu.max`/`pids.max` writes. Reads
/// `cgroup.controllers` first to only enable the ones the kernel exposes
/// (e.g. cgroup-nested environments may be missing some). Idempotent.
/// Called once from `init::async_main` at boot.
pub fn enable_cgroup_controllers() -> io::Result<()> {
    let root_controllers =
        std::fs::read_to_string(format!("{CGROUP_UNIFIED}/cgroup.controllers"))
            .unwrap_or_default();
    let available: Vec<&str> = root_controllers.split_whitespace().collect();
    let wanted = ["memory", "cpu", "pids"];
    let to_enable: Vec<String> = wanted
        .iter()
        .filter(|c| available.contains(c))
        .map(|c| format!("+{c}"))
        .collect();
    if to_enable.is_empty() {
        tracing::warn!(
            "no memory/cpu/pids controllers available in cgroup root; resource limits disabled"
        );
        return Ok(());
    }
    let line = to_enable.join(" ");

    // Enable on the unified root. EBUSY here means the root already has
    // direct processes (no-internal-processes rule) — rare in our init
    // context but possible under nested containers. Log and continue.
    if let Err(e) = std::fs::write(format!("{CGROUP_UNIFIED}/cgroup.subtree_control"), &line) {
        tracing::warn!(error = %e, controllers = %line, "enable root subtree_control failed");
    }

    std::fs::create_dir_all(CGROUP_ROOT)?;

    // Enable the same controllers on the `/svc` subtree so its children
    // (per-service leaves) can set the limit files.
    if let Err(e) = std::fs::write(format!("{CGROUP_ROOT}/cgroup.subtree_control"), &line) {
        tracing::warn!(error = %e, controllers = %line, "enable svc subtree_control failed");
    } else {
        tracing::info!(controllers = %line, "cgroup v2 controllers enabled for svc subtree");
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("errno: {0}")]
    Errno(#[from] rustix::io::Errno),
    #[error("service {name}: {message}")]
    Service { name: String, message: String },
}

pub struct Supervised {
    pub spec: Service,
    pub child: Option<AnyChild>,
    pub state: ServiceState,
    pub started_at: Instant,
    pub restarts: u32,
    pub backoff: Duration,
    pub next_restart: Option<Instant>,
    pub last_exit: Option<ExitStatus>,
}

impl Supervised {
    pub fn new(spec: Service) -> Self {
        Self {
            spec,
            child: None,
            state: ServiceState::Stopped,
            started_at: Instant::now(),
            restarts: 0,
            backoff: BACKOFF_INITIAL,
            next_restart: None,
            last_exit: None,
        }
    }

    pub fn pid(&self) -> Option<i32> {
        self.child.as_ref().and_then(|c| c.id()).map(|p| p as i32 )
    }

    pub fn uptime(&self) -> Duration {
        if matches!(self.state, ServiceState::Running) {
            self.started_at.elapsed()
        } else {
            Duration::ZERO
        }
    }
}

/// Fork-exec the service into its own set of namespaces with a pivoted rootfs.
///
/// Must be called from a tokio runtime context — stdout/stderr draining
/// happens in tokio tasks spawned into the ambient runtime. Returns once the
/// parent has the `Child` handle; the child has not necessarily reached
/// `execve` yet (cgroup placement happens between fork and exec).
///
/// Dispatches to the `tokio::process::Command` path (default) or the raw
/// `clone3(2)` path when `user_namespace = true`.
pub fn spawn(sup: &mut Supervised, logd: &Logd) -> Result<(), Error> {
    setup_cgroup(&sup.spec)?;
    let prepared = PreparedContainer::prepare(&sup.spec).map_err(|e| Error::Service {
        name: sup.spec.name.clone(),
        message: format!("prepare: {e}"),
    })?;

    if sup.spec.entrypoint.is_empty() {
        return Err(Error::Service {
            name: sup.spec.name.clone(),
            message: "empty entrypoint".to_string(),
        });
    }

    sup.state = ServiceState::Starting;
    sup.started_at = Instant::now();

    let (child, stdout_for_drain, stderr_for_drain) =
        if sup.spec.security.user_namespace {
            spawn_clone3(prepared, &sup.spec)?
        } else {
            spawn_command(prepared, &sup.spec)?
        };

    // Place the child in its cgroup.
    if let Some(pid) = child.id() {
        if let Err(e) = move_to_cgroup(&sup.spec, pid) {
            tracing::warn!(service = %sup.spec.name, error = %e, "cgroup placement failed");
        }
    }

    // For isolated-netns services with a veth config, re-exec ourselves as
    // the `--attach-netns` helper to move the peer into the child netns and
    // configure it.
    if sup.spec.net_mode == crate::config::NetMode::Isolated {
        if let (Some(pid), Some(veth)) = (child.id(), sup.spec.veth.as_ref()) {
            attach_netns(&sup.spec.name, pid, veth);
        }
    }

    // Drain stdout/stderr into logd.
    if let Some(stdout) = stdout_for_drain {
        let logd = logd.clone();
        let name = sup.spec.name.clone();
        tokio::spawn(drain_lines(stdout, logd, name, "stdout"));
    }
    if let Some(stderr) = stderr_for_drain {
        let logd = logd.clone();
        let name = sup.spec.name.clone();
        tokio::spawn(drain_lines(stderr, logd, name, "stderr"));
    }

    sup.child = Some(child);
    sup.state = ServiceState::Running;
    sup.next_restart = None;
    Ok(())
}

/// Boxed async reader type for spawn return values.
type BoxReader = Box<dyn tokio::io::AsyncRead + Unpin + Send>;

/// tokio::process::Command spawn path (default, no user namespace).
fn spawn_command(
    prepared: PreparedContainer,
    spec: &Service,
) -> Result<(AnyChild, Option<BoxReader>, Option<BoxReader>), Error> {
    let mut cmd = Command::new(&spec.entrypoint[0]);
    if spec.entrypoint.len() > 1 {
        cmd.args(&spec.entrypoint[1..]);
    }
    cmd.env_clear();
    cmd.env("HOME", "/");
    cmd.env("PATH", "/usr/bin:/bin");
    cmd.env("HOSTNAME", &spec.name);
    for (k, v) in &spec.env {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.kill_on_drop(false);

    // SAFETY: `pre_exec` runs after fork(2) in the child, before execve(2).
    // The closure must be async-signal-safe: no heap allocation, no locks,
    // no stdio. Every CStr it uses has been pre-built in `PreparedContainer`.
    unsafe {
        let mut prepared: PreparedContainer = prepared;
        cmd.pre_exec(move || {
            prepared.enter().map_err(errno_to_io)?;
            prepared.harden()?;
            Ok(())
        });
    }

    let mut child = cmd.spawn().map_err(|e| Error::Service {
        name: spec.name.clone(),
        message: format!("spawn: {e}"),
    })?;

    let stdout: Option<BoxReader> = child.stdout.take().map(|r| Box::new(r) as _);
    let stderr: Option<BoxReader> = child.stderr.take().map(|r| Box::new(r) as _);
    Ok((AnyChild::Tokio(child), stdout, stderr))
}

/// `clone3(CLONE_NEWUSER | CLONE_NEWPID | ...)` spawn path. The child is
/// born inside all namespaces from birth, so `pivot_root`, `mount("proc")`,
/// and `mount("tmpfs")` all succeed — avoiding the three kernel barriers
/// that block the `unshare(NEWUSER)` approach.
fn spawn_clone3(
    mut prepared: PreparedContainer,
    spec: &Service,
) -> Result<(AnyChild, Option<BoxReader>, Option<BoxReader>), Error> {
    use rustix::pipe::PipeFlags;

    // Build clone3 flags: NEWUSER + NEWPID + all the namespace flags.
    let clone_flags: u64 =
        libc::CLONE_NEWUSER as u64
        | libc::CLONE_NEWPID as u64
        | prepared.unshare_flags.bits() as u64;

    // Create stdio pipes (CLOEXEC so they don't leak past execve).
    let (stdout_r, stdout_w) =
        rustix::pipe::pipe_with(PipeFlags::CLOEXEC).map_err(errno_to_io)?;
    let (stderr_r, stderr_w) =
        rustix::pipe::pipe_with(PipeFlags::CLOEXEC).map_err(errno_to_io)?;
    // Sync pipe: parent writes 1 byte after uid_map is set to unblock child.
    let (sync_r, sync_w) =
        rustix::pipe::pipe_with(PipeFlags::CLOEXEC).map_err(errno_to_io)?;
    // Open /dev/null for stdin before clone3 (path resolves in parent ns).
    let devnull = std::fs::File::open("/dev/null").map_err(Error::Io)?;

    // --- clone3 ---
    let child_pid = unsafe { raw_clone3(clone_flags) }.map_err(|e| Error::Service {
        name: spec.name.clone(),
        message: format!("clone3: {e}"),
    })?;

    if child_pid == 0 {
        // ── CHILD ──────────────────────────────────────────────
        // We are PID 1 inside the new PID namespace, inside the new
        // user namespace (no uid_map yet — parent will write it).
        // async-signal-safe only from here until execve.

        use std::os::unix::io::IntoRawFd;
        unsafe {
            // Set up stdio: dup2 clears CLOEXEC on the target fd.
            libc::dup2(devnull.into_raw_fd(), 0);
            libc::dup2(stdout_w.into_raw_fd(), 1);
            libc::dup2(stderr_w.into_raw_fd(), 2);
            // Close parent-side pipe ends (we have copies due to fork).
            drop(stdout_r);
            drop(stderr_r);
            drop(sync_w);

            // Block until parent writes uid_map and signals us.
            let sync_fd = sync_r.into_raw_fd();
            let mut ack = [0u8; 1];
            libc::read(sync_fd, ack.as_mut_ptr() as *mut libc::c_void, 1);
            libc::close(sync_fd);

            // Set up rootfs (hostname, pivot_root, mount /proc etc.)
            if let Err(e) = prepared.setup_rootfs() {
                // Write errno detail to stderr (fd 2 is our pipe).
                // This allocation is technically not async-signal-safe,
                // but works in practice on Linux after fork.
                let msg = format!("clone3 child: setup_rootfs: {e}\n");
                libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
                libc::_exit(127);
            }

            // Apply hardening (caps, no_new_privs, seccomp, landlock).
            if let Err(e) = prepared.harden() {
                let msg = format!("clone3 child: harden: {e}\n");
                libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
                libc::_exit(128);
            }

            // Close all fds >= 3 before exec (clean fd table).
            // close_range(2) is Linux 5.9+. On older kernels (QSDK 5.4),
            // fall back to closing fds individually.
            if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) < 0 {
                for fd in 3..1024 {
                    libc::close(fd);
                }
            }

            // execve with pre-built argv and envp.
            let argv_ptrs: Vec<*const libc::c_char> = prepared
                .argv_c
                .iter()
                .map(|s| s.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect();
            let envp_ptrs: Vec<*const libc::c_char> = prepared
                .envp_c
                .iter()
                .map(|s| s.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect();
            libc::execve(
                prepared.argv_c[0].as_ptr(),
                argv_ptrs.as_ptr(),
                envp_ptrs.as_ptr(),
            );
            // If execve returns, it failed.
            libc::_exit(126);
        }
    }

    // ── PARENT ─────────────────────────────────────────────────
    // Close child-side pipe ends.
    drop(stdout_w);
    drop(stderr_w);
    drop(sync_r);
    drop(devnull);

    // Write uid_map + gid_map for the child. The child is blocked on
    // the sync pipe until we signal it.
    if let Err(e) = write_uid_gid_map(child_pid) {
        // Child is stuck; kill it.
        unsafe { libc::kill(child_pid, libc::SIGKILL); }
        return Err(Error::Service {
            name: spec.name.clone(),
            message: format!("write_uid_gid_map: {e}"),
        });
    }

    // Signal the child to proceed with rootfs setup.
    rustix::io::write(sync_w.as_fd(), &[1]).map_err(|e| Error::Service {
        name: spec.name.clone(),
        message: format!("sync signal: {e}"),
    })?;
    drop(sync_w);

    // Wrap stdout/stderr as tokio pipe Receivers for async drain.
    let stdout_reader: BoxReader = Box::new(
        tokio::net::unix::pipe::Receiver::from_owned_fd(stdout_r)
            .map_err(|e| Error::Service {
                name: spec.name.clone(),
                message: format!("tokio pipe stdout: {e}"),
            })?
    );
    let stderr_reader: BoxReader = Box::new(
        tokio::net::unix::pipe::Receiver::from_owned_fd(stderr_r)
            .map_err(|e| Error::Service {
                name: spec.name.clone(),
                message: format!("tokio pipe stderr: {e}"),
            })?
    );

    Ok((
        AnyChild::Raw(RawChild { pid: child_pid, reaped: false }),
        Some(stdout_reader),
        Some(stderr_reader),
    ))
}

/// Run the `--attach-netns` helper to move veth peer into child netns.
fn attach_netns(svc_name: &str, pid: u32, veth: &crate::config::VethConfig) {
    let peer_name = format!("veth-{svc_name}-p");
    match std::env::current_exe() {
        Ok(exe) => {
            let status = std::process::Command::new(&exe)
                .arg("--attach-netns")
                .arg(pid.to_string())
                .arg(&peer_name)
                .arg(veth.peer_ip.to_string())
                .arg(veth.prefix.to_string())
                .arg(veth.host_ip.to_string())
                .status();
            match status {
                Ok(s) if s.success() => {
                    tracing::info!(service = %svc_name, pid, "netns attached");
                }
                Ok(s) => {
                    tracing::error!(service = %svc_name, status = ?s, "attach-netns helper failed");
                }
                Err(e) => {
                    tracing::error!(service = %svc_name, error = %e, "attach-netns helper spawn error");
                }
            }
        }
        Err(e) => {
            tracing::error!(service = %svc_name, error = %e, "current_exe failed");
        }
    }
}

/// Spawn a one-shot hardened exec — no `Supervised` state, no `Logd`
/// wiring, no cgroup leaf. Used by `control/server.rs::diag_exec` to
/// run whitelisted diagnostic binaries (iputils-ping, traceroute, dig,
/// ...) inside the same namespace+hardening pipeline.
///
/// Returns the child's `Output` (status + stdout + stderr) directly.
/// The caller wraps this in `tokio::time::timeout` for the deadline.
/// Dispatches to the Command path (default) or clone3 path when
/// `user_namespace = true`.
pub async fn oneshot_exec(spec: &Service) -> Result<std::process::Output, Error> {
    if spec.entrypoint.is_empty() {
        return Err(Error::Service {
            name: spec.name.clone(),
            message: "empty entrypoint".to_string(),
        });
    }

    let prepared = PreparedContainer::prepare(spec).map_err(|e| Error::Service {
        name: spec.name.clone(),
        message: format!("prepare: {e}"),
    })?;

    if spec.security.user_namespace {
        oneshot_exec_clone3(prepared, spec).await
    } else {
        oneshot_exec_command(prepared, spec).await
    }
}

async fn oneshot_exec_command(
    prepared: PreparedContainer,
    spec: &Service,
) -> Result<std::process::Output, Error> {
    let mut cmd = Command::new(&spec.entrypoint[0]);
    if spec.entrypoint.len() > 1 {
        cmd.args(&spec.entrypoint[1..]);
    }
    cmd.env_clear();
    cmd.env("HOME", "/");
    cmd.env("PATH", "/usr/bin:/bin");
    cmd.env("HOSTNAME", &spec.name);
    for (k, v) in &spec.env {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.kill_on_drop(true);

    unsafe {
        let mut prepared: PreparedContainer = prepared;
        cmd.pre_exec(move || {
            prepared.enter().map_err(errno_to_io)?;
            prepared.harden()?;
            Ok(())
        });
    }

    let child = cmd.spawn().map_err(|e| Error::Service {
        name: spec.name.clone(),
        message: format!("spawn: {e}"),
    })?;
    child.wait_with_output().await.map_err(Error::Io)
}

/// clone3 one-shot: the child is born inside NEWUSER + NEWPID + ...
/// namespaces, parent writes uid_map, signals, then waits for the child
/// to exit and captures stdout/stderr. The entire sequence runs in
/// `spawn_blocking` since it's all synchronous syscalls.
async fn oneshot_exec_clone3(
    mut prepared: PreparedContainer,
    spec: &Service,
) -> Result<std::process::Output, Error> {
    use rustix::pipe::PipeFlags;

    let clone_flags: u64 =
        libc::CLONE_NEWUSER as u64
        | libc::CLONE_NEWPID as u64
        | prepared.unshare_flags.bits() as u64;

    let (stdout_r, stdout_w) =
        rustix::pipe::pipe_with(PipeFlags::CLOEXEC).map_err(errno_to_io)?;
    let (stderr_r, stderr_w) =
        rustix::pipe::pipe_with(PipeFlags::CLOEXEC).map_err(errno_to_io)?;
    let (sync_r, sync_w) =
        rustix::pipe::pipe_with(PipeFlags::CLOEXEC).map_err(errno_to_io)?;
    let devnull = std::fs::File::open("/dev/null").map_err(Error::Io)?;

    let child_pid = unsafe { raw_clone3(clone_flags) }.map_err(|e| Error::Service {
        name: spec.name.clone(),
        message: format!("clone3: {e}"),
    })?;

    if child_pid == 0 {
        use std::os::unix::io::IntoRawFd;
        unsafe {
            libc::dup2(devnull.into_raw_fd(), 0);
            libc::dup2(stdout_w.into_raw_fd(), 1);
            libc::dup2(stderr_w.into_raw_fd(), 2);
            drop(stdout_r);
            drop(stderr_r);
            drop(sync_w);

            let sync_fd = sync_r.into_raw_fd();
            let mut ack = [0u8; 1];
            libc::read(sync_fd, ack.as_mut_ptr() as *mut libc::c_void, 1);
            libc::close(sync_fd);

            if let Err(e) = prepared.setup_rootfs() {
                let msg = format!("clone3 child: setup_rootfs: {e}\n");
                libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
                libc::_exit(127);
            }
            if let Err(e) = prepared.harden() {
                let msg = format!("clone3 child: harden: {e}\n");
                libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
                libc::_exit(128);
            }

            libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32);

            let argv_ptrs: Vec<*const libc::c_char> = prepared
                .argv_c
                .iter()
                .map(|s| s.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect();
            let envp_ptrs: Vec<*const libc::c_char> = prepared
                .envp_c
                .iter()
                .map(|s| s.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect();
            libc::execve(
                prepared.argv_c[0].as_ptr(),
                argv_ptrs.as_ptr(),
                envp_ptrs.as_ptr(),
            );
            libc::_exit(126);
        }
    }

    // Parent: close child-side pipe ends.
    drop(stdout_w);
    drop(stderr_w);
    drop(sync_r);
    drop(devnull);

    // Write uid_map, signal child.
    if let Err(e) = write_uid_gid_map(child_pid) {
        unsafe { libc::kill(child_pid, libc::SIGKILL); }
        return Err(Error::Service {
            name: spec.name.clone(),
            message: format!("write_uid_gid_map: {e}"),
        });
    }
    rustix::io::write(sync_w.as_fd(), &[1]).map_err(|e| Error::Service {
        name: spec.name.clone(),
        message: format!("sync signal: {e}"),
    })?;
    drop(sync_w);

    // Read stdout/stderr and waitpid in spawn_blocking (all blocking I/O).
    let svc_name = spec.name.clone();
    tokio::task::spawn_blocking(move || {
        use std::os::unix::io::IntoRawFd;

        let stdout_fd = stdout_r.into_raw_fd();
        let stderr_fd = stderr_r.into_raw_fd();

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        // Read pipes until EOF (child closes write ends on exit).
        let mut buf = [0u8; 4096];
        loop {
            let n = unsafe { libc::read(stdout_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n <= 0 { break; }
            stdout.extend_from_slice(&buf[..n as usize]);
        }
        unsafe { libc::close(stdout_fd); }

        loop {
            let n = unsafe { libc::read(stderr_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n <= 0 { break; }
            stderr.extend_from_slice(&buf[..n as usize]);
        }
        unsafe { libc::close(stderr_fd); }

        // Reap the child.
        let mut status: libc::c_int = 0;
        unsafe { libc::waitpid(child_pid, &mut status, 0); }

        Ok(std::process::Output {
            status: ExitStatus::from_raw(status),
            stdout,
            stderr,
        })
    })
    .await
    .map_err(|e| Error::Service {
        name: svc_name,
        message: format!("spawn_blocking join: {e}"),
    })?
}

/// Max bytes we keep for any single log line. A service that emits a
/// massive no-newline burst gets its line truncated here so `logd`'s
/// ring buffer can't grow without bound. `read_line` itself still reads
/// the whole line from the pipe — the hard cap is on what we store.
const MAX_LOG_LINE: usize = 4096;

async fn drain_lines<R>(reader: R, logd: Logd, service: String, stream: &'static str)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut reader = BufReader::with_capacity(MAX_LOG_LINE, reader);
    let mut buf = String::with_capacity(MAX_LOG_LINE);
    loop {
        buf.clear();
        match reader.read_line(&mut buf).await {
            Ok(0) => break,
            Ok(_) => {
                if buf.ends_with('\n') {
                    buf.pop();
                    if buf.ends_with('\r') {
                        buf.pop();
                    }
                }
                let line = if buf.len() > MAX_LOG_LINE {
                    let mut truncated = buf[..MAX_LOG_LINE].to_string();
                    truncated.push_str(" [TRUNCATED]");
                    truncated
                } else {
                    std::mem::take(&mut buf)
                };
                logd.push(&service, line);
            }
            Err(e) => {
                tracing::debug!(service = %service, stream, error = %e, "log drain error");
                break;
            }
        }
    }
}

/// Non-blocking reap. Returns `Some(status)` if the child exited, otherwise
/// `None`. Updates the supervisor state and schedules the next restart.
pub fn reap(sup: &mut Supervised) -> Result<Option<ExitStatus>, Error> {
    let Some(ref mut child) = sup.child else {
        return Ok(None);
    };
    match child.try_wait() {
        Ok(Some(status)) => {
            sup.last_exit = Some(status);
            sup.child = None;
            sup.state = if status.success() {
                ServiceState::Stopped
            } else {
                ServiceState::Crashed
            };
            sup.restarts = sup.restarts.saturating_add(1);
            sup.next_restart = Some(Instant::now() + sup.backoff);
            sup.backoff = (sup.backoff * 2).min(BACKOFF_MAX);
            Ok(Some(status))
        }
        Ok(None) => Ok(None),
        Err(e) => Err(Error::Io(e)),
    }
}

/// Whether the supervisor should (re)spawn `sup` right now. Callers invoke
/// `spawn` when this returns true.
pub fn should_start(sup: &Supervised, now: Instant) -> bool {
    match sup.state {
        ServiceState::Running | ServiceState::Starting => false,
        ServiceState::Stopped | ServiceState::Crashed => sup
            .next_restart
            .map(|t| now >= t)
            .unwrap_or(true),
    }
}

pub struct Supervisor {
    pub services: Vec<Supervised>,
}

impl Supervisor {
    pub fn from_config(services: &[Service]) -> Self {
        // Topologically order on depends_on. Services without dependencies
        // come first; the rest follow in insertion order once their deps are
        // satisfied. A cycle short-circuits to insertion order with a warn.
        let mut ordered: Vec<Service> = Vec::with_capacity(services.len());
        let mut remaining: Vec<&Service> = services.iter().collect();
        let mut progressed = true;
        while progressed && !remaining.is_empty() {
            progressed = false;
            let mut next = Vec::with_capacity(remaining.len());
            for svc in remaining.drain(..) {
                let deps_ready = svc
                    .depends_on
                    .iter()
                    .all(|dep| ordered.iter().any(|o| &o.name == dep));
                if deps_ready {
                    ordered.push(svc.clone());
                    progressed = true;
                } else {
                    next.push(svc);
                }
            }
            remaining = next;
        }
        if !remaining.is_empty() {
            tracing::warn!(
                unresolved = ?remaining.iter().map(|s| &s.name).collect::<Vec<_>>(),
                "service dependency cycle; appending in insertion order"
            );
            ordered.extend(remaining.into_iter().cloned());
        }

        Self {
            services: ordered.into_iter().map(Supervised::new).collect(),
        }
    }

    /// One non-blocking pass: reap exited children, start anything due
    /// whose dependencies are themselves ready. Must be called from a
    /// tokio runtime context — `spawn` spawns drain tasks into the
    /// ambient runtime.
    ///
    /// **Dependency-aware spawning.** A service with `depends_on = [x]`
    /// is only spawned once `x` has been in `Running` state for at
    /// least `DEP_STARTUP_GRACE`. Before that, the service stays in
    /// `Stopped` and `tick` re-checks on the next 100 ms iteration.
    /// This prevents the "ntp spawns before dns is listening, first
    /// resolution fails, ntp crashes, supervisor backs off" startup
    /// race. The tick loop's short period makes the extra latency
    /// imperceptible (~1 s past dns ready vs. the race case, where
    /// the crash-restart churn could take 10+ seconds to stabilize).
    pub fn tick(&mut self, logd: &Logd) {
        let now = Instant::now();

        // Phase 1: reap exited children. This is pure mutation per
        // service, no cross-service state, so we can do it in a single
        // iter_mut pass.
        for sup in self.services.iter_mut() {
            match reap(sup) {
                Ok(Some(status)) => {
                    // Same tracing + logd dual-write as spawn failure
                    // (see the `spawn failed` arm below) — surface the
                    // exit code so the Status RPC's `last_log` shows
                    // something useful for a service that exited
                    // cleanly but with a non-zero status (bad config,
                    // missing runtime dep, etc.).
                    tracing::warn!(
                        service = %sup.spec.name,
                        code = status.code().unwrap_or(-1),
                        signal = ?status.signal(),
                        restarts = sup.restarts,
                        "service exited"
                    );
                    logd.push(
                        &sup.spec.name,
                        format!(
                            "service exited: code={} signal={:?} restarts={}",
                            status.code().unwrap_or(-1),
                            status.signal(),
                            sup.restarts
                        ),
                    );
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::error!(service = %sup.spec.name, error = %e, "reap failed");
                    logd.push(&sup.spec.name, format!("reap failed: {e}"));
                }
            }
        }

        // Phase 2: snapshot which services are currently "dep-ready".
        // A service is ready to satisfy another service's dependency
        // when it's Running AND has been up for at least
        // DEP_STARTUP_GRACE. Built as a name-indexed BTreeMap so the
        // subsequent spawn pass can look up each dep without borrowing
        // `self.services` a second time.
        let ready: std::collections::BTreeMap<String, bool> = self
            .services
            .iter()
            .map(|s| {
                let is_ready = matches!(s.state, ServiceState::Running)
                    && s.uptime() >= DEP_STARTUP_GRACE;
                (s.spec.name.clone(), is_ready)
            })
            .collect();

        // Phase 3: spawn anything due whose deps are satisfied. A
        // service with deps that aren't ready is silently skipped —
        // no log spam, the tick loop will try again in 100 ms.
        for sup in self.services.iter_mut() {
            if !should_start(sup, now) {
                continue;
            }
            let deps_ready = sup
                .spec
                .depends_on
                .iter()
                .all(|dep| *ready.get(dep).unwrap_or(&false));
            if !deps_ready {
                continue;
            }
            if let Err(e) = spawn(sup, logd) {
                // Log to tracing for syslog/journalctl AND push to the
                // per-service ring so the Status RPC surfaces the
                // reason in `last_log`. Without the logd.push, a
                // crash-looping service shows "Crashed restarts=N"
                // with no hint as to why, forcing operators to ssh
                // in and read syslog.
                tracing::error!(service = %sup.spec.name, error = %e, "spawn failed");
                logd.push(&sup.spec.name, format!("spawn failed: {e}"));
                sup.state = ServiceState::Crashed;
                sup.next_restart = Some(now + sup.backoff);
                sup.backoff = (sup.backoff * 2).min(BACKOFF_MAX);
            }
        }
    }

    pub fn shutdown(&mut self) {
        for sup in self.services.iter_mut().rev() {
            if sup.child.is_some() {
                let _ = stop(sup);
            }
        }
        // Wait briefly for children to exit, reap each, then rmdir its
        // cgroup leaf. A cgroup can only be removed when empty, so the
        // reap must come first. Bounded: ~1 s max per service.
        for sup in self.services.iter_mut().rev() {
            let deadline = Instant::now() + Duration::from_secs(1);
            while sup.child.is_some() && Instant::now() < deadline {
                if let Ok(Some(_)) = reap(sup) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            remove_cgroup(&sup.spec);
        }
    }
}

/// Kill the running child (SIGTERM) and mark the state as `Stopped`. The
/// actual reap happens via `reap()` on the next tick.
pub fn stop(sup: &mut Supervised) -> Result<(), Error> {
    if let Some(pid) = sup.child.as_ref().and_then(|c| c.id()) {
        if let Some(pid) = rustix::process::Pid::from_raw(pid as i32) {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
        }
    }
    sup.state = ServiceState::Stopped;
    sup.next_restart = None;
    sup.backoff = BACKOFF_INITIAL;
    Ok(())
}

fn setup_cgroup(spec: &Service) -> Result<(), Error> {
    let dir: PathBuf = [CGROUP_ROOT, spec.name.as_str()].iter().collect();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        if e.kind() != io::ErrorKind::AlreadyExists {
            return Err(Error::Io(e));
        }
    }
    // Resource-limit writes are best-effort. In nested-cgroup environments
    // (e.g. running under Docker with --cgroupns=private), the parent may
    // not have the relevant controller enabled in its subtree_control, so
    // the memory.max / cpu.max / pids.max control files don't exist. Don't
    // let that kill the spawn — the container still boots, just without
    // the limit in place.
    if let Some(mem) = spec.memory_max {
        if let Err(e) = std::fs::write(dir.join("memory.max"), mem.to_string()) {
            tracing::warn!(service = %spec.name, error = %e, "memory.max write failed");
        }
    }
    if let Some(cpu) = &spec.cpu_max {
        if let Err(e) = std::fs::write(dir.join("cpu.max"), cpu) {
            tracing::warn!(service = %spec.name, error = %e, "cpu.max write failed");
        }
    }
    if let Some(pids) = spec.pids_max {
        if let Err(e) = std::fs::write(dir.join("pids.max"), pids.to_string()) {
            tracing::warn!(service = %spec.name, error = %e, "pids.max write failed");
        }
    }
    Ok(())
}

fn remove_cgroup(spec: &Service) {
    let dir: PathBuf = [CGROUP_ROOT, spec.name.as_str()].iter().collect();
    match std::fs::remove_dir(&dir) {
        Ok(()) => tracing::debug!(service = %spec.name, path = %dir.display(), "cgroup removed"),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(service = %spec.name, error = %e, "cgroup rmdir failed"),
    }
}

fn move_to_cgroup(spec: &Service, pid: u32) -> Result<(), Error> {
    let path: PathBuf = [CGROUP_ROOT, spec.name.as_str(), "cgroup.procs"]
        .iter()
        .collect();
    std::fs::write(path, pid.to_string())?;
    Ok(())
}

/// Pre-built CStrings + flags for the child's post-fork syscall sequence.
/// Constructed on the parent side so no allocation happens in pre_exec.
///
/// `Debug` is only for test assertions (`unwrap_err()` requires it); the
/// real-world path only ever reads individual fields during pre_exec.
#[derive(Debug)]
struct PreparedContainer {
    rootfs: CString,
    put_old_in_new_root: CString,  // <rootfs>/.old_root — argument to pivot_root
    put_old_after_pivot: CString,  // /.old_root         — path after pivot_root
    proc_target: CString,
    sys_target: CString,
    dev_target: CString,
    devpts_target: CString,
    hostname: Vec<u8>,
    binds: Vec<BindEntry>,
    unshare_flags: UnshareFlags,
    /// Whether the service wants user_namespace isolation.
    user_namespace: bool,
    /// Capabilities to drop from the bounding set, EXCLUDING SETPCAP. Built
    /// in `prepare()` from `SecurityProfile.caps`. Dropped first in `harden()`.
    drops_non_setpcap: Vec<Capability>,
    /// Whether SETPCAP itself should be dropped from the bounding set after
    /// the others. Equivalent to "SETPCAP is not in the retain list."
    drop_setpcap: bool,
    /// `prctl(PR_SET_NO_NEW_PRIVS, 1)` if true. Required precondition for
    /// `seccomp_program` to apply without `CAP_SYS_ADMIN`.
    no_new_privs: bool,
    /// Pre-compiled BPF program. `None` means seccomp is disabled for this
    /// service (`SecurityProfile.seccomp == false`).
    seccomp_program: Option<BpfProgram>,
    /// Pre-built Landlock ruleset, `None` means landlock is disabled for
    /// this service. The parent side opens `PathFd`s for the rootfs +
    /// each writable bind mount source, constructs a ruleset that only
    /// handles write-type accesses, and stores the `RulesetCreated` here.
    /// The child's `harden()` consumes it via `restrict_self()`. Since
    /// we restrict only writes, reads (including `/proc/self/*` etc.)
    /// are unrestricted — see `SecurityProfile::landlock` docs for the
    /// full rationale.
    landlock_ruleset: Option<RulesetCreated>,
    /// Pre-built CString entrypoint argv for the clone3 path's direct
    /// `execve(2)`. Empty on the Command path (Command handles exec).
    argv_c: Vec<CString>,
    /// Pre-built "KEY=VALUE" environment CStrings for clone3's execve.
    envp_c: Vec<CString>,
}

#[derive(Debug)]
struct BindEntry {
    source: CString,
    target_in_rootfs: CString,
    readonly: bool,
}

impl PreparedContainer {
    fn prepare(spec: &Service) -> io::Result<Self> {
        if !spec.rootfs.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("rootfs {:?} must be absolute", spec.rootfs),
            ));
        }
        // Ensure the mount target directories exist in the rootfs before
        // the child tries to mount them. /dev/pts is not created here —
        // it's created by the child after /dev is mounted as tmpfs.
        for dir in [PUT_OLD_REL, "proc", "sys", "dev"] {
            std::fs::create_dir_all(spec.rootfs.join(dir))?;
        }
        let put_old_host = spec.rootfs.join(PUT_OLD_REL);

        let rootfs = os_cstring(spec.rootfs.as_os_str())?;
        let put_old_in_new_root = os_cstring(put_old_host.as_os_str())?;
        let put_old_after_pivot = CString::new(format!("/{PUT_OLD_REL}")).unwrap();
        let proc_target = CString::new("/proc").unwrap();
        let sys_target = CString::new("/sys").unwrap();
        let dev_target = CString::new("/dev").unwrap();
        let devpts_target = CString::new("/dev/pts").unwrap();

        let mut binds = Vec::with_capacity(spec.binds.len());
        for b in &spec.binds {
            if !b.target.is_absolute() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("bind target {:?} must be absolute", b.target),
                ));
            }
            let mut target_abs = spec.rootfs.clone();
            for component in b.target.components().skip(1) {
                target_abs.push(component);
            }
            // Ensure target exists in the rootfs so bind mount has something
            // to attach to. We don't know if it's a file or dir without a
            // stat on source; treat directories as the common case.
            if let Ok(meta) = std::fs::metadata(&b.source) {
                if meta.is_dir() {
                    std::fs::create_dir_all(&target_abs)?;
                } else if let Some(parent) = target_abs.parent() {
                    std::fs::create_dir_all(parent)?;
                    let _ = std::fs::File::create(&target_abs);
                }
            }
            binds.push(BindEntry {
                source: os_cstring(b.source.as_os_str())?,
                target_in_rootfs: os_cstring(target_abs.as_os_str())?,
                readonly: b.readonly,
            });
        }

        let mut unshare_flags = UnshareFlags::NEWNS
            | UnshareFlags::NEWUTS
            | UnshareFlags::NEWIPC
            | UnshareFlags::NEWCGROUP;
        if spec.net_mode == NetMode::Isolated {
            unshare_flags |= UnshareFlags::NEWNET;
        }
        // Note: NEWPID is NOT added to unshare_flags — unshare(NEWPID)
        // only affects future children, not the caller. For services with
        // `user_namespace = true`, NEWPID is passed to clone3 instead,
        // which creates the child INSIDE the new PID namespace from birth.

        let (drops_non_setpcap, drop_setpcap) = build_cap_drops(&spec.security)?;
        let seccomp_program = if spec.security.seccomp {
            build_seccomp_program(&spec.security.seccomp_allow)?
        } else {
            None
        };
        let landlock_ruleset = if spec.security.landlock {
            match build_landlock_ruleset(spec) {
                Ok(r) => r,
                Err(e) => {
                    // Landlock was added in kernel 5.13. On older kernels
                    // (e.g., QSDK's 5.4), the syscall returns ENOSYS.
                    // Degrade gracefully: log and skip. The remaining
                    // hardening layers (caps + seccomp + mount namespace
                    // isolation) are still in effect.
                    tracing::warn!(
                        service = %spec.name,
                        error = %e,
                        "landlock unavailable (kernel too old?); skipping"
                    );
                    None
                }
            }
        } else {
            None
        };

        // Pre-build entrypoint argv and env for the clone3 path's
        // direct execve(2). The Command path ignores these.
        let argv_c: Vec<CString> = spec
            .entrypoint
            .iter()
            .map(|s| CString::new(s.as_bytes()).unwrap_or_default())
            .collect();

        let mut env_pairs: Vec<CString> = vec![
            CString::new(format!("HOME=/")).unwrap(),
            CString::new(format!("PATH=/usr/bin:/bin")).unwrap(),
            CString::new(format!("HOSTNAME={}", spec.name)).unwrap(),
        ];
        for (k, v) in &spec.env {
            if let Ok(cs) = CString::new(format!("{k}={v}")) {
                env_pairs.push(cs);
            }
        }

        Ok(Self {
            rootfs,
            put_old_in_new_root,
            put_old_after_pivot,
            proc_target,
            sys_target,
            dev_target,
            devpts_target,
            hostname: spec.name.as_bytes().to_vec(),
            binds,
            unshare_flags,
            user_namespace: spec.security.user_namespace,
            drops_non_setpcap,
            drop_setpcap,
            no_new_privs: spec.security.no_new_privs,
            seccomp_program,
            landlock_ruleset,
            argv_c,
            envp_c: env_pairs,
        })
    }

    /// Runs in the forked child (Command path), before execve. Calls
    /// `unshare(2)` then `setup_rootfs()`. Must be async-signal-safe.
    fn enter(&self) -> rustix::io::Result<()> {
        unsafe {
            unshare_unsafe(self.unshare_flags)?;
        }
        self.setup_rootfs()
    }

    /// Set up the container rootfs: hostname, pivot_root, mount /proc
    /// /sys /dev /dev/pts, apply user bind mounts. Called from both
    /// `enter()` (Command path, after unshare) and the clone3 child
    /// (after the parent has written uid_map and signaled).
    ///
    /// When the child was created via clone3(CLONE_NEWPID), it IS PID 1
    /// in its own PID namespace, so `mount -t proc` succeeds (the kernel
    /// sees the process is inside a PID namespace owned by its userns).
    /// pivot_root also succeeds because the child has CAP_SYS_ADMIN
    /// inside the userns.
    fn setup_rootfs(&self) -> rustix::io::Result<()> {
        // Each step is annotated with a label so that the clone3 child's
        // error path can report exactly which syscall failed.
        sethostname(&self.hostname)
            .map_err(|e| rustix::io::Errno::from_raw_os_error(map_step_err("sethostname", e)))?;

        mount_change(
            c"/",
            MountPropagationFlags::DOWNSTREAM | MountPropagationFlags::REC,
        ).map_err(|e| rustix::io::Errno::from_raw_os_error(map_step_err("mount_change /", e)))?;

        mount_bind(self.rootfs.as_c_str(), self.rootfs.as_c_str())
            .map_err(|e| rustix::io::Errno::from_raw_os_error(map_step_err("bind rootfs", e)))?;

        for bind in &self.binds {
            mount_bind(bind.source.as_c_str(), bind.target_in_rootfs.as_c_str())?;
            if bind.readonly {
                mount_remount(
                    bind.target_in_rootfs.as_c_str(),
                    MountFlags::BIND | MountFlags::RDONLY,
                    c"",
                )?;
            }
        }

        pivot_root(
            self.rootfs.as_c_str(),
            self.put_old_in_new_root.as_c_str(),
        ).map_err(|e| rustix::io::Errno::from_raw_os_error(map_step_err("pivot_root", e)))?;
        chdir(c"/")?;

        let none: Option<&CStr> = None;
        let nsnd = MountFlags::NOSUID | MountFlags::NOEXEC | MountFlags::NODEV;

        mount(c"proc", self.proc_target.as_c_str(), c"proc", nsnd, none)
            .map_err(|e| rustix::io::Errno::from_raw_os_error(map_step_err("mount proc", e)))?;

        // In a user namespace, mounting sysfs is denied unless the child
        // is also in a non-init network namespace. Host-netns services
        // (net_mode = Host, diag tools) hit this. Make sysfs best-effort
        // when `user_namespace` is true — most services don't need /sys.
        // Similarly, devpts mounting may fail in some userns configurations.
        if self.user_namespace {
            let _ = mount(
                c"sysfs",
                self.sys_target.as_c_str(),
                c"sysfs",
                nsnd | MountFlags::RDONLY,
                none,
            );
        } else {
            mount(
                c"sysfs",
                self.sys_target.as_c_str(),
                c"sysfs",
                nsnd | MountFlags::RDONLY,
                none,
            ).map_err(|e| rustix::io::Errno::from_raw_os_error(map_step_err("mount sysfs", e)))?;
        }

        // In a user namespace, tmpfs mount may return EOVERFLOW unless
        // the mount options explicitly set uid= and gid= to values
        // that exist in the container's uid/gid mapping. Pass "uid=0,gid=0"
        // which maps to the container's root user (mapped to host 65534).
        if self.user_namespace {
            mount(
                c"tmpfs",
                self.dev_target.as_c_str(),
                c"tmpfs",
                MountFlags::NOSUID,
                Some(c"uid=0,gid=0,mode=0755"),
            ).map_err(|e| rustix::io::Errno::from_raw_os_error(map_step_err("mount tmpfs /dev (userns)", e)))?;
        } else {
            mount(
                c"tmpfs",
                self.dev_target.as_c_str(),
                c"tmpfs",
                MountFlags::NOSUID,
                none,
            ).map_err(|e| rustix::io::Errno::from_raw_os_error(map_step_err("mount tmpfs /dev", e)))?;
        }
        // In a userns, mkdir on the freshly-mounted tmpfs may fail with
        // EOVERFLOW (uid overflow check) and devpts mount is also
        // restricted. Skip the whole devpts subtree — services that need
        // a PTY must declare a bind mount for /dev/pts instead.
        if !self.user_namespace {
            rustix::fs::mkdir(self.devpts_target.as_c_str(), rustix::fs::Mode::from(0o755))
                .map_err(|e| rustix::io::Errno::from_raw_os_error(map_step_err("mkdir /dev/pts", e)))?;
            // ptmxmode=666,gid=5 makes /dev/pts/ptmx openable by non-root
            // users (dropbear drops to the logged-in user before calling
            // openpty). Without this the kernel defaults ptmxmode to 0000
            // and PTY allocation fails with EACCES — seen in debug-ssh as
            // "PTY allocation request failed on channel 0".
            mount(
                c"devpts",
                self.devpts_target.as_c_str(),
                c"devpts",
                MountFlags::NOSUID | MountFlags::NOEXEC,
                Some(c"ptmxmode=666,gid=5"),
            ).map_err(|e| rustix::io::Errno::from_raw_os_error(map_step_err("mount devpts", e)))?;
            // /dev is a fresh tmpfs — whatever the rootfs image staged at
            // /dev/ptmx is hidden. openpty(3) / dropbear open /dev/ptmx
            // (not /dev/pts/ptmx), so materialize the conventional symlink
            // inside the container's tmpfs /dev.
            let _ = rustix::fs::symlink(c"pts/ptmx", c"/dev/ptmx");
            // Standard character-device nodes. Without these, any service
            // that opens /dev/null, /dev/zero, /dev/urandom, /dev/random,
            // /dev/tty fails with ENOENT — seen with hostapd ("Could not
            // open /dev/urandom"), and dropbear would also hit it if it
            // ever needed the RNG (dropbear reads /dev/urandom on some
            // crypto paths). Major/minor numbers per Linux mem-major (1).
            use rustix::fs::{FileType, Mode, mknodat, CWD};
            let chr = FileType::CharacterDevice;
            let _ = mknodat(CWD, c"/dev/null",    chr, Mode::from(0o666), rustix::fs::makedev(1, 3));
            let _ = mknodat(CWD, c"/dev/zero",    chr, Mode::from(0o666), rustix::fs::makedev(1, 5));
            let _ = mknodat(CWD, c"/dev/full",    chr, Mode::from(0o666), rustix::fs::makedev(1, 7));
            let _ = mknodat(CWD, c"/dev/random",  chr, Mode::from(0o666), rustix::fs::makedev(1, 8));
            let _ = mknodat(CWD, c"/dev/urandom", chr, Mode::from(0o666), rustix::fs::makedev(1, 9));
            let _ = mknodat(CWD, c"/dev/tty",     chr, Mode::from(0o666), rustix::fs::makedev(5, 0));
        }

        unmount(self.put_old_after_pivot.as_c_str(), UnmountFlags::DETACH)
            .map_err(|e| rustix::io::Errno::from_raw_os_error(map_step_err("unmount .old_root", e)))?;
        Ok(())
    }

    /// Apply the per-service hardening layer: capability drop → no_new_privs
    /// → seccomp filter → landlock. Runs in the forked child between
    /// `enter()` and `execve(2)`, so the rules are inherited by the service
    /// binary. Order matters:
    ///
    /// 1. `SETPCAP` is dropped LAST because the kernel requires it in the
    ///    effective set to drop other capabilities.
    /// 2. Seccomp must come AFTER `no_new_privs` so the kernel doesn't
    ///    reject the filter for lack of `CAP_SYS_ADMIN`.
    /// 3. Landlock comes last so any syscalls seccomp would have blocked
    ///    don't also need to be filtered by landlock's path rules.
    ///
    /// `&mut self` because `landlock::RulesetCreated::restrict_self()`
    /// consumes the ruleset — we `.take()` the `Option` to move it out.
    fn harden(&mut self) -> io::Result<()> {
        for cap in &self.drops_non_setpcap {
            caps::drop(None, CapSet::Bounding, *cap).map_err(|e| {
                io::Error::other(format!("drop bounding {cap:?}: {e}"))
            })?;
        }
        if self.drop_setpcap {
            caps::drop(None, CapSet::Bounding, Capability::CAP_SETPCAP).map_err(|e| {
                io::Error::other(format!("drop bounding SETPCAP: {e}"))
            })?;
        }

        if self.no_new_privs {
            // SAFETY: prctl is async-signal-safe.
            let r = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
            if r != 0 {
                return Err(io::Error::last_os_error());
            }
        }

        if let Some(program) = &self.seccomp_program {
            seccompiler::apply_filter(program)
                .map_err(|e| io::Error::other(format!("seccomp apply: {e}")))?;
        }

        // Landlock last — `restrict_self` consumes the ruleset, so we
        // `.take()` it out of the `Option` to avoid a borrow problem.
        // On success, returns a `RestrictionStatus` we ignore; on
        // failure (e.g. kernel too old, ruleset syscall refused) we
        // bubble up — a "safer" failure mode than silently running
        // without the sandbox.
        if let Some(ruleset) = self.landlock_ruleset.take() {
            ruleset
                .restrict_self()
                .map_err(|e| io::Error::other(format!("landlock apply: {e}")))?;
        }

        Ok(())
    }
}

/// Build a Landlock ruleset that **only restricts writes**. Reads are
/// unrestricted — a deliberate choice so the mounted `/proc`/`/sys`/`/dev`
/// inside the container (fresh inodes post-pivot_root) don't silently break
/// Rust stdlib and typical service needs.
///
/// Rules:
/// - Read+exec access is NOT handled (so it's unrestricted everywhere).
/// - Write access is handled on the rootfs inode + every writable bind
///   mount source. Rules are added as `PathBeneath` so descendants are
///   included. The child, after pivot_root, sees the same inodes at
///   new paths, and landlock checks by inode, so the allow list transfers.
///
/// Returns `None` if no rules would be added AND the ruleset is empty —
/// which happens when a service has no writable bind mounts. The empty
/// write-ruleset is still applied (denies ALL writes to new paths).
fn build_landlock_ruleset(spec: &Service) -> io::Result<Option<RulesetCreated>> {
    let abi = ABI::V1;
    let write_access = AccessFs::from_write(abi);

    let mut ruleset = Ruleset::default()
        .handle_access(write_access)
        .map_err(|e| io::Error::other(format!("landlock handle_access: {e}")))?
        .create()
        .map_err(|e| io::Error::other(format!("landlock create: {e}")))?;

    // NOTE: rootfs is NOT added to the write allow list. In production the
    // rootfs is squashfs and the mount layer rejects writes regardless of
    // landlock. In smoke/dev setups the rootfs is a regular directory, and
    // adding it would silently allow writes to anywhere under the rootfs —
    // which is exactly the hole landlock is supposed to close. Services
    // that need scratch space must declare a writable bind mount (or a
    // future tmpfs mount at /tmp).

    // Grant writes on every writable bind mount source. The rule applies
    // to the underlying inode, which the child sees at the bind target
    // path after pivot_root.
    for bind in &spec.binds {
        if bind.readonly {
            continue;
        }
        let fd = PathFd::new(&bind.source).map_err(|e| {
            io::Error::other(format!(
                "landlock PathFd({:?}): {e}",
                bind.source
            ))
        })?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, write_access))
            .map_err(|e| {
                io::Error::other(format!(
                    "landlock add writable bind {:?}: {e}",
                    bind.source
                ))
            })?;
    }

    Ok(Some(ruleset))
}

/// Parse the retain list from `SecurityProfile.caps` and split the universe
/// of capabilities into "drop, but not SETPCAP yet" and "drop SETPCAP last".
/// Returns an error if a name in the retain list isn't a known capability.
fn build_cap_drops(profile: &SecurityProfile) -> io::Result<(Vec<Capability>, bool)> {
    let mut retained: HashSet<Capability> = HashSet::new();
    for name in &profile.caps {
        let full = if name.starts_with("CAP_") {
            name.clone()
        } else {
            format!("CAP_{name}")
        };
        let cap = Capability::from_str(&full).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown capability: {name}"),
            )
        })?;
        retained.insert(cap);
    }
    let mut drops_non_setpcap: Vec<Capability> = caps::all()
        .into_iter()
        .filter(|c| !retained.contains(c) && *c != Capability::CAP_SETPCAP)
        .collect();
    // Stable order so behavior is deterministic across runs and arches.
    drops_non_setpcap.sort_by_key(|c| format!("{c:?}"));
    let drop_setpcap = !retained.contains(&Capability::CAP_SETPCAP);
    Ok((drops_non_setpcap, drop_setpcap))
}

/// Build the deny-list seccomp BPF program. Compiled in the parent so the
/// child only does the `seccomp(2)` syscall in pre_exec. An empty rule list
/// for each syscall means "match unconditionally on this nr"; non-matched
/// syscalls fall through to `Allow`.
///
/// `allow` is the per-service `seccomp_allow` list — names removed from the
/// default deny list. Unknown names error out so a typo can't silently
/// neuter the filter. If every entry on the deny list ends up allowed, the
/// resulting filter has no rules — `SeccompFilter::new` rejects that, so we
/// return `None` instead and the harden step skips the seccomp call.
fn build_seccomp_program(allow: &[String]) -> io::Result<Option<BpfProgram>> {
    // Validate every name first so a typo halts spawn before anything else.
    for name in allow {
        if !SECCOMP_DENY_LIST.iter().any(|(n, _)| *n == name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "seccomp_allow: {name:?} is not in the default deny list (allowed names: {})",
                    SECCOMP_DENY_LIST
                        .iter()
                        .map(|(n, _)| *n)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }
    }

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for (name, nr) in SECCOMP_DENY_LIST {
        if allow.iter().any(|a| a == *name) {
            continue;
        }
        rules.insert(*nr, Vec::new());
    }
    if rules.is_empty() {
        return Ok(None);
    }
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        SECCOMP_TARGET_ARCH,
    )
    .map_err(|e| io::Error::other(format!("build seccomp filter: {e}")))?;
    filter
        .try_into()
        .map(Some)
        .map_err(|e: seccompiler::BackendError| {
            io::Error::other(format!("compile seccomp filter: {e}"))
        })
}

fn os_cstring(s: &OsStr) -> io::Result<CString> {
    CString::new(s.as_bytes()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

fn errno_to_io(e: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(e.raw_os_error())
}

/// Log a step name + errno to stderr (for the clone3 child's error path),
/// then pass the raw errno through so the caller can re-wrap it.
fn map_step_err(step: &str, e: rustix::io::Errno) -> i32 {
    // This is only called in the clone3 child path where stderr (fd 2) is
    // a pipe. The format! allocates, which is technically not async-signal-
    // safe but works in practice after fork on Linux.
    let msg = format!("  → {step}: {e}\n");
    unsafe { libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len()); }
    e.raw_os_error()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BindMount, Service};
    use std::path::PathBuf;

    fn tmp_service(rootfs: PathBuf) -> Service {
        Service {
            name: "t".to_string(),
            rootfs,
            entrypoint: vec!["/bin/true".to_string()],
            env: Default::default(),
            net_mode: NetMode::Isolated,
            veth: None,
            memory_max: Some(32 * 1024 * 1024),
            cpu_max: None,
            pids_max: Some(16),
            binds: vec![],
            depends_on: vec![],
            security: Default::default(),
        }
    }

    #[test]
    fn backoff_grows_then_caps() {
        let spec = tmp_service(PathBuf::from("/tmp/rootfs"));
        let mut sup = Supervised::new(spec);
        let mut seen = Vec::new();
        for _ in 0..12 {
            seen.push(sup.backoff);
            sup.backoff = (sup.backoff * 2).min(BACKOFF_MAX);
        }
        assert!(seen[0] < seen[1]);
        assert!(seen.last().copied().unwrap() <= BACKOFF_MAX);
    }

    #[test]
    fn should_start_after_next_restart() {
        let spec = tmp_service(PathBuf::from("/tmp/rootfs"));
        let mut sup = Supervised::new(spec);
        assert!(should_start(&sup, Instant::now()));
        sup.state = ServiceState::Crashed;
        sup.next_restart = Some(Instant::now() + Duration::from_secs(10));
        assert!(!should_start(&sup, Instant::now()));
        sup.next_restart = Some(Instant::now() - Duration::from_secs(1));
        assert!(should_start(&sup, Instant::now()));
    }

    #[test]
    fn non_absolute_rootfs_rejected() {
        let spec = tmp_service(PathBuf::from("relative/path"));
        let err = PreparedContainer::prepare(&spec).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn non_absolute_bind_target_rejected() {
        let mut spec = tmp_service(PathBuf::from("/tmp/oxwrt-test-rootfs"));
        std::fs::create_dir_all(&spec.rootfs).unwrap();
        spec.binds.push(BindMount {
            source: PathBuf::from("/etc/hostname"),
            target: PathBuf::from("etc/relative"),
            readonly: false,
        });
        let err = PreparedContainer::prepare(&spec).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
