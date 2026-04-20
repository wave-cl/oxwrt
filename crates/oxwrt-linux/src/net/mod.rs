//! rtnetlink-driven link/addr programming + rustables-driven nftables.
//! No shelling out to `ip(8)` or `nft(8)` — everything is direct netlink.
//!
//! v0.1 scope (this landing):
//! - `Net` struct owns the rtnetlink handle and worker task.
//! - `bring_up(&Config)`: loopback up, `br-lan` bridge create/up, LAN address
//!   assigned, LAN members enslaved, WAN link up.
//! - `create_veth_pair(svc)`: host-side veth pair ready for container attach.
//! - `install_firewall(&Config)`: minimal inet nftables ruleset — INPUT drops
//!   by default, accepts established / lo / sQUIC control on LAN, FORWARD
//!   accepts, OUTPUT accepts.
//!
//! Deferred to a follow-up landing:
//! - NAT masquerade on WAN
//! - Per-service forward rules (LAN ↔ container netns)
//! - WAN DHCP client, route programming, PPPoE
//! - IPv6 (ICMPv6 RA, ND)

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;

use futures_util::stream::TryStreamExt;
use rtnetlink::{Handle, LinkBridge, LinkUnspec, LinkVeth, LinkVlan, new_connection};

use oxwrt_api::config::{Config, Network, WanConfig};

// The firewall/install/dump stack lives in its own module. External
// callers continue to reach it via `crate::net::X` through the
// re-export block below — the split is source-compatible.
mod firewall;
pub use firewall::{format_firewall_dump, install_firewall, zone_ifaces};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("rtnetlink: {0}")]
    Rtnetlink(#[from] rtnetlink::Error),
    #[error("netlink socket: {0}")]
    Socket(#[from] std::io::Error),
    #[error("link {0} not found")]
    LinkNotFound(String),
    #[error("firewall: {0}")]
    Firewall(String),
}

/// Owns the rtnetlink handle and the background worker task that services it.
/// Dropping `Net` aborts the worker.
pub struct Net {
    handle: Handle,
    worker: tokio::task::JoinHandle<()>,
}

/// VLAN sub-ifaces we've created (by name). Written on successful
/// create in `setup_simple`, read + diffed in `bring_up`'s cleanup
/// pass so ifaces whose backing Simple network disappeared from
/// config get `ip link delete`'d on the next reload.
///
/// Static because `Net` is reconstructed on every reload, but the
/// kernel state persists across reload invocations — a per-instance
/// field would forget what we created last boot. The tradeoff is
/// test isolation (shared state across tests), accepted because
/// the only direct callers are in the linux-gated test suite and
/// they don't exercise the cleanup path.
static CREATED_VLAN_IFACES: Mutex<Vec<String>> = Mutex::new(Vec::new());

impl Net {
    pub fn new() -> Result<Self, Error> {
        let (connection, handle, _messages) = new_connection()?;
        let worker = tokio::spawn(async move {
            connection.await;
        });
        Ok(Self { handle, worker })
    }

    pub fn handle(&self) -> &Handle {
        &self.handle
    }

    pub async fn bring_up(&self, cfg: &Config) -> Result<(), Error> {
        self.up_link("lo").await?;
        for net in &cfg.networks {
            match net {
                Network::Lan { .. } => self.setup_lan(net).await?,
                Network::Wan { .. } => self.setup_wan(net).await?,
                Network::Simple {
                    iface,
                    address,
                    prefix,
                    vlan,
                    vlan_parent,
                    ..
                } => {
                    // VLAN sub-iface: create `<iface>` on top of
                    // `vlan_parent` with tag `vlan` before addressing.
                    // Both fields required together — validate.rs
                    // enforces that. Idempotent: if the iface already
                    // exists we assume a previous boot created it
                    // with the same parent+tag and move on.
                    if let (Some(vlan_id), Some(parent)) = (vlan, vlan_parent) {
                        if matches!(self.link_index(iface).await, Err(Error::LinkNotFound(_))) {
                            let parent_idx = self.link_index(parent).await?;
                            self.handle
                                .link()
                                .add(LinkVlan::new(iface, parent_idx, *vlan_id).build())
                                .execute()
                                .await?;
                            tracing::info!(
                                %iface, parent = %parent, vlan = vlan_id,
                                "simple: created VLAN sub-iface"
                            );
                        }
                        // Track this iface by name so the cleanup
                        // pass at the end of bring_up can delete it
                        // if a future reload drops the config entry.
                        {
                            let mut tracked = CREATED_VLAN_IFACES.lock().unwrap();
                            if !tracked.iter().any(|n| n == iface) {
                                tracked.push(iface.clone());
                            }
                        }
                        let idx = self.link_index(iface).await?;
                        self.handle
                            .link()
                            .set(LinkUnspec::new_with_index(idx).up().build())
                            .execute()
                            .await?;
                        // Assign the IPv4 address on the VLAN iface.
                        // For non-VLAN Simple networks this is
                        // expected to happen out-of-band (bridge
                        // declared by LAN membership or platform
                        // hot-plug), but for a VLAN sub-iface we're
                        // the only thing that knows it exists.
                        match self
                            .handle
                            .address()
                            .add(idx, IpAddr::V4(*address), *prefix)
                            .execute()
                            .await
                        {
                            Ok(()) => {}
                            Err(e) if is_exists(&e) => {
                                tracing::debug!(%iface, %address, "vlan v4 already present");
                            }
                            Err(e) => return Err(e.into()),
                        }
                    }
                    // Simple network bridges are created out-of-band
                    // (typically via platform hot-plug or a LAN
                    // [[networks]] declaration referencing the same
                    // iface). No iface + address setup here.
                    //
                    // But if the operator declared a v6 address on a
                    // Simple network, assign it — operators often
                    // use Simple for guest/iot VLANs that do want v6.
                    if let Some((v6, prefix)) = net.ipv6() {
                        if let Ok(idx) = self.link_index(iface).await {
                            let res = self
                                .handle
                                .address()
                                .add(idx, IpAddr::V6(v6), prefix)
                                .execute()
                                .await;
                            if let Err(e) = res {
                                if !is_exists(&e) {
                                    return Err(e.into());
                                }
                                tracing::debug!(%iface, %v6, "simple v6 already present");
                            }
                        }
                    }
                }
            }
        }

        // Cleanup pass: delete any VLAN sub-iface we previously
        // created whose backing Simple network has disappeared
        // from the new config. Iterates the in-memory tracker,
        // not the kernel, to avoid deleting VLAN ifaces the
        // operator created manually via debug-ssh.
        let expected: HashSet<String> = cfg
            .networks
            .iter()
            .filter_map(|n| match n {
                Network::Simple {
                    iface,
                    vlan: Some(_),
                    vlan_parent: Some(_),
                    ..
                } => Some(iface.clone()),
                _ => None,
            })
            .collect();
        let stale: Vec<String> = {
            let tracked = CREATED_VLAN_IFACES.lock().unwrap();
            tracked
                .iter()
                .filter(|name| !expected.contains(*name))
                .cloned()
                .collect()
        };
        for name in &stale {
            match self.link_index(name).await {
                Ok(idx) => {
                    if let Err(e) = self.handle.link().del(idx).execute().await {
                        tracing::warn!(iface = %name, error = %e, "vlan: cleanup delete failed");
                    } else {
                        tracing::info!(iface = %name, "vlan: deleted stale sub-iface");
                    }
                }
                Err(Error::LinkNotFound(_)) => {
                    // Already gone — operator deleted it out of band;
                    // our tracker just hadn't caught up. Fine.
                }
                Err(e) => {
                    tracing::warn!(iface = %name, error = %e, "vlan: cleanup lookup failed");
                }
            }
        }
        // Drop stale entries from the tracker regardless of the
        // kernel-side result — the next reload shouldn't keep
        // retrying a delete that already happened (or that the
        // kernel refuses permanently).
        CREATED_VLAN_IFACES
            .lock()
            .unwrap()
            .retain(|name| !stale.iter().any(|s| s == name));

        Ok(())
    }

    async fn up_link(&self, name: &str) -> Result<(), Error> {
        let idx = self.link_index(name).await?;
        self.handle
            .link()
            .set(LinkUnspec::new_with_index(idx).up().build())
            .execute()
            .await?;
        Ok(())
    }

    async fn link_index(&self, name: &str) -> Result<u32, Error> {
        let mut stream = self
            .handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute();
        match stream.try_next().await {
            Ok(Some(msg)) => Ok(msg.header.index),
            Ok(None) => Err(Error::LinkNotFound(name.to_string())),
            // RTM_GETLINK for a nonexistent name returns -ENODEV (19) rather
            // than an empty response. Map that to our LinkNotFound so callers
            // can use the match!() pattern.
            Err(e) if is_nodev(&e) => Err(Error::LinkNotFound(name.to_string())),
            Err(e) => Err(Error::Rtnetlink(e)),
        }
    }

    async fn setup_lan(&self, net: &Network) -> Result<(), Error> {
        let Network::Lan {
            bridge,
            members,
            address,
            prefix,
            vlan_filtering,
            vlan_ports,
            ..
        } = net
        else {
            return Ok(());
        };
        if matches!(self.link_index(bridge).await, Err(Error::LinkNotFound(_))) {
            self.handle
                .link()
                .add(LinkBridge::new(bridge).build())
                .execute()
                .await?;
        }
        let bridge_idx = self.link_index(bridge).await?;

        self.handle
            .link()
            .set(LinkUnspec::new_with_index(bridge_idx).up().build())
            .execute()
            .await?;

        let addr_res = self
            .handle
            .address()
            .add(bridge_idx, IpAddr::V4(*address), *prefix)
            .execute()
            .await;
        if let Err(e) = addr_res {
            if !is_exists(&e) {
                return Err(e.into());
            }
            tracing::debug!(%bridge, "lan address already present");
        }

        // Optional IPv6 on the same bridge. The rtnetlink .address()
        // builder takes IpAddr directly so we reuse the same call path
        // — no v6-specific plumbing. Typically the first host of a
        // /64 (ULA today; delegated prefix when DHCPv6-PD lands).
        if let Some((v6, v6_prefix)) = net.ipv6() {
            let res = self
                .handle
                .address()
                .add(bridge_idx, IpAddr::V6(v6), v6_prefix)
                .execute()
                .await;
            if let Err(e) = res {
                if !is_exists(&e) {
                    return Err(e.into());
                }
                tracing::debug!(%bridge, %v6, "lan ipv6 address already present");
            }
        }

        // Enslave LAN members to the bridge. Missing members are warned and
        // skipped — hardware may lack a given port, or the config may refer
        // to an interface that's renamed by the board-files.
        for member in members {
            let member_idx = match self.link_index(member).await {
                Ok(idx) => idx,
                Err(Error::LinkNotFound(_)) => {
                    tracing::warn!(iface = %member, "lan member not present — skipping");
                    continue;
                }
                Err(e) => return Err(e),
            };
            self.handle
                .link()
                .set(
                    LinkUnspec::new_with_index(member_idx)
                        .controller(bridge_idx)
                        .up()
                        .build(),
                )
                .execute()
                .await?;
        }

        // VLAN-aware bridging. Shell out to `ip` + `bridge` — the
        // rtnetlink crate's link-kind handling doesn't cover bridge
        // vlan_filtering or per-port VLAN attributes as of 0.20, and
        // wrapping libnetlink's AF_BRIDGE raw messages would add
        // significant complexity for what's effectively a
        // static-at-boot config. `bridge` ships with iproute2 in
        // every OpenWrt image; it's on PATH.
        if *vlan_filtering {
            apply_bridge_vlan_filtering(bridge, vlan_ports)?;
        }
        Ok(())
    }

    async fn setup_wan(&self, net: &Network) -> Result<(), Error> {
        let Network::Wan {
            iface,
            wan,
            mac_address,
            ..
        } = net
        else {
            return Ok(());
        };
        // MAC spoofing first, before any up-link. Some kernel link
        // drivers refuse address changes while admin-up, so we
        // bounce the link: down → set-address → up. No-op if
        // mac_address is None — the iface keeps its factory MAC
        // and we don't touch link state here.
        if let Some(mac_str) = mac_address.as_deref() {
            let mac = parse_mac(mac_str)?;
            let idx = self.link_index(iface).await?;
            // Ignore errors on down — the iface may already be down,
            // or the driver may tolerate address changes while up.
            // We only care that the subsequent address-set succeeds.
            let _ = self
                .handle
                .link()
                .set(LinkUnspec::new_with_index(idx).down().build())
                .execute()
                .await;
            self.handle
                .link()
                .set(
                    LinkUnspec::new_with_index(idx)
                        .address(mac.to_vec())
                        .build(),
                )
                .execute()
                .await?;
            tracing::info!(
                iface = %iface,
                mac = %mac_str,
                "wan: MAC overridden from config"
            );
        }
        self.up_link(iface).await?;

        // DHCP: wan_dhcp::acquire handles addressing.
        // Pppoe: not yet implemented, link-only.
        // Static: apply the configured address + default route here so a
        // static-WAN router actually comes up with the operator's
        // configured IP without needing a reload. EEXIST on address / route
        // is tolerated so re-running this is idempotent.
        if let WanConfig::Static {
            address,
            prefix,
            gateway,
            ..
        } = wan
        {
            let idx = self.link_index(iface).await?;
            let add_res = self
                .handle
                .address()
                .add(idx, IpAddr::V4(*address), *prefix)
                .execute()
                .await;
            if let Err(e) = add_res {
                if !is_exists(&e) {
                    return Err(e.into());
                }
                tracing::debug!(%iface, %address, "static wan address already present");
            }
            // NOTE: default-route install is owned by the failover
            // coordinator (wan_failover::spawn), not here. Static
            // WANs are published into WanLeases by init::run so the
            // coordinator sees them alongside DHCP WANs and picks
            // exactly one default. Same reasoning as the DHCP path
            // (wan_dhcp::apply_lease) — avoids the EEXIST race.
            let _ = gateway; // suppress unused-binding lint
            tracing::info!(%iface, %address, prefix = %prefix, "static wan: address applied");
        }
        Ok(())
    }

    /// Create a host-side veth pair for a service container. The peer end
    /// will later be moved into the container's network namespace by the
    /// supervisor (not yet wired). Returns `(host_end, peer_end)` names.
    pub async fn create_veth_pair(&self, svc_name: &str) -> Result<(String, String), Error> {
        let host_name = format!("veth-{svc_name}");
        let peer_name = format!("veth-{svc_name}-p");
        self.handle
            .link()
            .add(LinkVeth::new(&host_name, &peer_name).build())
            .execute()
            .await?;
        Ok((host_name, peer_name))
    }

    /// Full host-side veth setup: create the pair, assign `host_ip/prefix`
    /// to the host end, bring the host end up. Returns `(host_name, peer_name)`.
    /// Idempotent on repeat runs (`EEXIST` on address is swallowed).
    pub async fn setup_host_veth(
        &self,
        svc_name: &str,
        host_ip: Ipv4Addr,
        prefix: u8,
    ) -> Result<(String, String), Error> {
        let (host_name, peer_name) = self.create_veth_pair(svc_name).await?;

        let host_idx = self.link_index(&host_name).await?;

        match self
            .handle
            .address()
            .add(host_idx, IpAddr::V4(host_ip), prefix)
            .execute()
            .await
        {
            Ok(()) => {}
            Err(e) if is_exists(&e) => {
                tracing::debug!(iface = %host_name, "veth host ip already present");
            }
            Err(e) => return Err(e.into()),
        }

        self.handle
            .link()
            .set(LinkUnspec::new_with_index(host_idx).up().build())
            .execute()
            .await?;

        Ok((host_name, peer_name))
    }
}

impl Drop for Net {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

fn is_exists(err: &rtnetlink::Error) -> bool {
    // rtnetlink 0.20 wraps the kernel's -errno in NetlinkError. EEXIST = 17
    // on Linux (all arches), and the kernel negates it before sending.
    netlink_errno(err) == Some(-17)
}

/// Parse an operator-supplied MAC string into six bytes. Accepts
/// colon- or hyphen-separated hex octets (`"aa:bb:cc:dd:ee:ff"` or
/// `"aa-bb-cc-dd-ee-ff"`, case-insensitive). Rejects multicast
/// addresses (low bit of first octet set) — DHCP servers ignore
/// DISCOVERs with a multicast source, so that shape can't work on
/// a WAN link and is almost certainly a typo.
pub fn parse_mac(s: &str) -> Result<[u8; 6], Error> {
    let normalized = s.replace('-', ":");
    let parts: Vec<&str> = normalized.split(':').collect();
    if parts.len() != 6 {
        return Err(Error::Firewall(format!(
            "mac_address {s:?}: expected six hex octets (got {})",
            parts.len()
        )));
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        if p.len() != 2 {
            return Err(Error::Firewall(format!(
                "mac_address {s:?}: octet {p:?} must be two hex chars"
            )));
        }
        out[i] = u8::from_str_radix(p, 16)
            .map_err(|_| Error::Firewall(format!("mac_address {s:?}: octet {p:?} not hex")))?;
    }
    if out[0] & 0x01 != 0 {
        return Err(Error::Firewall(format!(
            "mac_address {s:?}: multicast address rejected (low bit of first octet set)"
        )));
    }
    Ok(out)
}

fn is_nodev(err: &rtnetlink::Error) -> bool {
    // ENODEV = 19. RTM_GETLINK with a name that doesn't exist returns this.
    netlink_errno(err) == Some(-19)
}

fn netlink_errno(err: &rtnetlink::Error) -> Option<i32> {
    if let rtnetlink::Error::NetlinkError(msg) = err {
        msg.code.map(|c| c.get())
    } else {
        None
    }
}

/// Enable IPv4 forwarding in the current netns. Idempotent — safe to call
/// more than once. Required for packets from service netns containers to
/// egress through the outer netns's upstream interface.
/// Enable 802.1Q VLAN filtering on `bridge` and apply per-port
/// VLAN assignments via the `bridge` iproute2 helper.
///
/// Idempotent: duplicate `bridge vlan add` calls return
/// "already exists" which we log + ignore. On a fresh boot the
/// bridge starts with `vlan_filtering=0` and an implicit "VID 1
/// PVID untagged" on every port; enabling filtering makes that
/// default EXPLICIT but doesn't change observable behavior for
/// ports we don't touch.
///
/// Per port:
///   - `bridge vlan add vid X dev <iface> pvid untagged` →
///     access port for VID X (default + egress-untag).
///   - `bridge vlan add vid Y dev <iface>` → trunk-tagged VID Y.
///   - Both combine on hybrid ports; call the first for the
///     pvid/untagged VID and the second for each tagged VID.
///
/// Note: doesn't DIFF against current kernel state — on reload,
/// an operator removing a VLAN from config leaves its kernel
/// entry in place until reboot. Accept as v1 limitation; clean
/// state on every change requires bridge-vlan enumerate-and-
/// diff which the iproute2 helper doesn't expose cleanly.
pub(crate) fn apply_bridge_vlan_filtering(
    bridge: &str,
    vlan_ports: &[oxwrt_api::config::VlanPort],
) -> Result<(), Error> {
    use std::process::Command;

    // Flip the bridge into vlan-aware mode first. The sysfs knob
    // is `/sys/class/net/<br>/bridge/vlan_filtering`; writing "1"
    // is the canonical way (iproute2 does the same under the
    // hood).
    let path = format!("/sys/class/net/{bridge}/bridge/vlan_filtering");
    if let Err(e) = std::fs::write(&path, "1\n") {
        return Err(Error::Firewall(format!(
            "bridge vlan_filtering enable ({path}): {e}"
        )));
    }
    tracing::info!(bridge, "bridge vlan_filtering enabled");

    for p in vlan_ports {
        // PVID (access / hybrid untagged default).
        if let Some(vid) = p.pvid {
            let vid_s = vid.to_string();
            let out = Command::new("bridge")
                .args([
                    "vlan", "add", "vid", &vid_s, "dev", &p.iface, "pvid", "untagged",
                ])
                .output()
                .map_err(|e| Error::Firewall(format!("bridge vlan add pvid: {e}")))?;
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr);
                // "already configured" is fine — idempotent re-run
                // after reload. Any other error logs + continues.
                if !stderr.contains("exists") && !stderr.contains("already") {
                    tracing::warn!(
                        iface = %p.iface, vid, stderr = %stderr.trim(),
                        "bridge vlan add pvid failed"
                    );
                } else {
                    tracing::debug!(iface = %p.iface, vid, "bridge vlan pvid already present");
                }
            } else {
                tracing::info!(iface = %p.iface, vid, "bridge vlan pvid set");
            }
        }
        // Tagged VIDs (trunk).
        for vid in &p.tagged {
            let vid_s = vid.to_string();
            let out = Command::new("bridge")
                .args(["vlan", "add", "vid", &vid_s, "dev", &p.iface])
                .output()
                .map_err(|e| Error::Firewall(format!("bridge vlan add tagged: {e}")))?;
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr);
                if !stderr.contains("exists") && !stderr.contains("already") {
                    tracing::warn!(
                        iface = %p.iface, vid, stderr = %stderr.trim(),
                        "bridge vlan add tagged failed"
                    );
                }
            } else {
                tracing::info!(iface = %p.iface, vid, "bridge vlan tagged added");
            }
        }
    }
    // Bridge itself usually needs vid 1 self-port so it can
    // originate + receive untagged management frames — left to
    // operator discretion in v1 (declare via vlan_ports with
    // iface = bridge name if needed). Most VLAN-aware setups
    // assign mgmt IP directly on a sub-iface rather than the
    // bridge itself anyway.
    Ok(())
}

pub fn enable_ipv4_forwarding() -> Result<(), Error> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1\n")?;
    Ok(())
}

/// Enable IPv6 forwarding. Required for corerad's RA emission to make
/// sense — the kernel will emit the "no global IPv6" warning and drop
/// packets that would need to route otherwise. Also flips
/// `accept_ra=2` on `all` so forwarding hosts keep learning from
/// upstream RAs (the default is 1 on non-forwarding, 0 on forwarding).
/// Idempotent.
pub fn enable_ipv6_forwarding() -> Result<(), Error> {
    std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1\n")?;
    // Best-effort; on a freshly booted box these may not exist for every
    // interface yet. Ignore errors (the write above is the essential one).
    let _ = std::fs::write("/proc/sys/net/ipv6/conf/all/accept_ra", "2\n");
    Ok(())
}

// (install_firewall and friends moved out to firewall.rs; the doc
// comment that used to live here got orphaned on the `mod tests`
// below, which clippy flags as inner+outer-attrs-on-same-item.)
#[cfg(test)]
mod tests {
    //! Pure-function unit tests for the helpers at the bottom of this
    //! file. Compiles and runs only on Linux targets (the whole module
    //! is `#[cfg(target_os = "linux")]`), so `cargo test` on a macOS
    //! dev box skips them — re-run via `cargo test --target
    //! aarch64-unknown-linux-musl` when iterating, or rely on CI that
    //! builds for Linux.
    //!
    //! The four helpers tested here are the glue between the declarative
    //! `Config` (from config.rs) and the rustables / nftables wire types
    //! used by `install_firewall`. They're pure functions of their
    //! inputs, so the tests don't need any mock netlink / cgroup /
    //! seccomp infrastructure.
    use super::*;

    #[test]
    fn parse_mac_colon_lowercase() {
        assert_eq!(
            parse_mac("aa:bb:cc:dd:ee:ff").unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
    }

    #[test]
    fn parse_mac_hyphen_uppercase() {
        assert_eq!(
            parse_mac("AA-BB-CC-DD-EE-FF").unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
    }

    #[test]
    fn parse_mac_rejects_multicast() {
        // First octet 0x01 has the low bit set → multicast.
        let err = parse_mac("01:02:03:04:05:06").unwrap_err();
        assert!(format!("{err:?}").contains("multicast"));
    }

    #[test]
    fn parse_mac_rejects_wrong_length() {
        assert!(parse_mac("aa:bb:cc").is_err());
        assert!(parse_mac("aa:bb:cc:dd:ee:ff:00").is_err());
        assert!(parse_mac("").is_err());
    }

    #[test]
    fn parse_mac_rejects_non_hex() {
        assert!(parse_mac("aa:bb:cc:dd:ee:gg").is_err());
        assert!(parse_mac("aa:bb:cc:dd:ee:f").is_err()); // single-char octet
    }
}
