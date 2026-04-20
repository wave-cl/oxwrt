//! oxwrt-api — shared data types for the oxwrt control plane.
//!
//! Two modules:
//! - [`config`] — TOML schema + [`config::Config`] loader.
//! - [`rpc`] — Request/Response enums exchanged over the sQUIC frame
//!   protocol.
//!
//! Everything here is pure-data: no system calls, no tokio, no
//! netlink. The crate builds on every target the workspace builds on
//! (including macOS, which matters for the CLI client). Daemon-side
//! concerns (ControlState, supervisor handles, wan-lease cache) live
//! in the daemon crate and borrow these types by reference.

pub mod config;
pub mod firewall_schedule;
pub mod rpc;
pub mod secrets;
