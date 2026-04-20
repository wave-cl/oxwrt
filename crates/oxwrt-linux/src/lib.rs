#![cfg(target_os = "linux")]
//! oxwrt-linux — Linux-only system integrations for the oxwrt
//! daemon.
//!
//! Everything in this crate either executes Linux-specific syscalls
//! (clone3, seccomp, landlock, mount, pivot_root), talks to
//! Linux-specific kernel interfaces (rtnetlink, nftables, AF_PACKET),
//! or reads Linux-specific /sys + /proc paths. A `cfg_attr` at the
//! crate root would be redundant — the deps themselves only build on
//! Linux. We let Cargo's dep resolver fail loudly if someone tries to
//! build the daemon on a non-Linux target instead of silently
//! producing a half-functional binary.
//!
//! ## Module map
//!
//! - [`container`] — clone3-based container spawn + pivot_root +
//!   tmpfs /dev + caps drop + seccomp + landlock. Reaper. Log pipe
//!   draining into [`logd`].
//! - [`net`] — rtnetlink interface bring-up (address, bridge ports,
//!   veth pairs) + nftables install (inet filter + IPv4 NAT
//!   masquerade + DNAT).
//! - [`wan_dhcp`] — DHCPv4 client. DISCOVER/REQUEST via AF_PACKET
//!   raw socket, OFFER/ACK via UDP. Carrier-watch + renewal loop.
//! - [`wifi`] — hostapd.conf generator from the `[[radios]]` +
//!   `[[wifi]]` TOML schema. Multi-BSS aware.
//! - [`sysupgrade`] — native OTA: fwtool trailer parse, preflight
//!   tar, config backup, pivot_to_ramfs, flash kernel+root, reboot.
//! - [`logd`] — per-service ring buffer. Used by the control plane's
//!   `logs` RPC.

pub mod blocklists;
pub mod container;
pub mod coredhcp;
pub mod corerad;
pub mod hickory;
pub mod logd;
pub mod metrics_state;
pub mod miniupnpd;
pub mod net;
pub mod ntpd;
pub mod sqm;
pub mod static_routes;
pub mod svc_resolv;

pub mod sysupgrade;
pub mod urandom_seed;
pub mod vpn_client;
pub mod vpn_failover;
pub mod vpn_routing;
pub mod wan_dhcp;
pub mod wan_dhcp6;
pub mod wan_failover;
pub mod wan_routing;
pub mod wifi;
pub mod wireguard;
