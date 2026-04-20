//! PID-1 entrypoint. Mounts early filesystems, reaps children,
//! supervises containers, hosts the sQUIC control plane.
//!
//! File refactor note: this module used to be a single 2144-line
//! file. The code is now split into topic-grouped submodules. All
//! submodules are `pub(super)` to preserve the existing call sites
//! (they used to be `fn` in the same module); the only `pub` item
//! this module exports is the three run entry points + the `Error`
//! type.
//!
//! - [`run`] — entry points + async orchestration (`async_main`,
//!   `services_only_main`, `control_only_main`, signal handling,
//!   parse_listen_addrs).
//! - [`preinit`] — early_mounts, /dev population, mount_root hot path,
//!   overlay probing, loop-device creation, config-backup restore,
//!   truncate_stale_dhcp_leases, run_uci_defaults.
//! - [`modules`] — kernel-module loader (finit_module + dep resolution
//!   via modules.dep OR byte-scanned .modinfo depends).
//! - [`netdev`] — RTM_SETLINK netdev rename from DTS label, and wifi AP
//!   iface creation via `iw`.
//! - [`clock`] — SNTP bootstrap (hardcoded anycast server) and
//!   BUILD_EPOCH_SECS clock floor.
//! - [`watchdog`] — inherited-fd or /dev/watchdog open + pet loop.
//! - [`console`] — /dev/console dup + Rust panic hook to /dev/kmsg.

// Shared imports re-exported as `pub(super)` so every submodule in
// this tree can `use super::*;` and pick them up without restating.
pub(super) use std::net::SocketAddr;
pub(super) use std::path::{Path, PathBuf};
pub(super) use std::sync::Arc;
pub(super) use std::time::Duration;

pub(super) use crate::config::{self, Config, NetMode, Network, WanConfig};
pub(super) use crate::container::Supervisor;
pub(super) use crate::control::{self, ControlState, server::Server};
pub(super) use crate::logd::Logd;
pub(super) use crate::net::{self, Net};
pub(super) use crate::wan_dhcp;
pub(super) use crate::wan_dhcp6;

pub(super) const SIGNING_KEY_PATH: &str = "/etc/oxwrt/key.ed25519";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("config: {0}")]
    Config(#[from] config::Error),
    #[error("mount {target}: {source}")]
    Mount {
        target: String,
        #[source]
        source: rustix::io::Errno,
    },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("net: {0}")]
    Net(#[from] net::Error),
    #[error("control: {0}")]
    Control(#[from] crate::control::server::Error),
    #[error("runtime: {0}")]
    Runtime(String),
}

mod clock;
pub mod console;
mod main_loop;
mod modules;
mod netdev;
mod preinit;
mod run;
mod watchdog;

pub use run::{run, run_control_only, run_services_only};
