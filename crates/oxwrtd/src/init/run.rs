//! Daemon entry points + async orchestration.
//!
//! Split out of init.rs in step 6 of the workspace refactor.

#![allow(clippy::too_many_lines)]

use super::modules::load_modules;
use super::netdev::{create_wifi_ap_interfaces, rename_netdevs_from_dts};
use super::preinit::*;
use super::*;

pub fn run() -> Result<(), Error> {
    early_mounts()?;

    // Temporary diagnostic: log /dev contents and /proc/mounts after
    // early_mounts. Helps pinpoint why /dev/mmcblk0pN isn't available
    // when mount_root tries to open it on the standalone pid1 path.
    {
        let mut dev_entries: Vec<String> = std::fs::read_dir("/dev")
            .ok()
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        dev_entries.sort();
        tracing::info!(count = dev_entries.len(), sample = ?dev_entries.iter().take(20).collect::<Vec<_>>(), "diag: /dev entries after early_mounts");
        if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
            for line in mounts.lines().take(15) {
                tracing::info!(line, "diag: /proc/mounts");
            }
        }
    }

    // Stage 1 of the procd-init takeover: kernel module loading.
    // Walk /etc/modules-boot.d/ then /etc/modules.d/ and finit_module
    // each entry. In coexist mode (procd-init still runs preinit
    // upstream), every call returns EEXIST and this is a no-op —
    // that's intentional, the migration path is "land the code, verify
    // it's benign in coexist, then remove procd-init ahead of it."
    load_modules();

    // Stage 2 of the takeover: mount_root. Gate on "is the overlay
    // already mounted?" — in coexist with procd-init the answer is
    // always yes (procd ran /lib/preinit/80_mount_root upstream) and
    // we skip. When Stage 4 removes procd-init, this becomes the hot
    // path.
    // Stage 3 of the takeover: netdev renaming from DTS labels.
    // On OpenWrt the target-specific /lib/preinit/04_set_netdev_label
    // hook walks /sys/class/net/*/of_node/label and renames the
    // interface to match. On the GL-MT6000 this is what makes the
    // kernel's default ethX naming line up with the "lan1..lan5"
    // labels we reference in oxwrt.toml. In coexist this has already
    // happened upstream and our walk is all no-ops.
    rename_netdevs_from_dts();

    // Wifi AP interfaces. Once the mt76 driver has registered phy0/phy1,
    // we need AP-mode netdevs on them before hostapd can start (hostapd
    // with driver=nl80211 does not auto-create from the `phyN-` prefix
    // convention — OpenWrt's netifd did that on top). Idempotent: `iw
    // interface add` returns EEXIST if the iface is already there, which
    // we log and ignore. Skipped silently when iw isn't shipped (image
    // without wifi) or when the phys aren't registered (driver not
    // loaded / no hardware).
    create_wifi_ap_interfaces();

    if let Err(e) = mount_root_if_needed() {
        // Non-fatal: if we fail to set up the overlay here AND
        // procd-init didn't set it up either, /etc is read-only
        // squashfs and config-reload will fail. But oxwrtd can
        // still start the control plane on the in-memory config,
        // so operators have a recovery path.
        tracing::error!(error = %e, "mount_root_if_needed failed");
    }

    // Mark the overlay as READY so libfstools's next-boot mount_overlay()
    // doesn't fall through to overlay_delete() and wipe everything.
    //
    // OpenWrt's fstools treats /overlay/.fs_state as a three-state marker
    // (symlink target "0"=UNKNOWN, "1"=PENDING, "2"=READY). On boot, if
    // it reads PENDING (or UNKNOWN, which it auto-upgrades to PENDING),
    // mount_overlay() calls overlay_delete(overlay_mp, true) BEFORE the
    // pivot. That deletes every file on the overlay (libfstools/overlay.c
    // line 452-453: "overlay filesystem has not been fully initialized
    // yet" \u2192 overlay_delete).
    //
    // The READY transition is normally done by `mount_root done`,
    // invoked by procd at end-of-init (mount_root.c:132). Since oxwrtd
    // replaced procd as PID 1 and never calls `mount_root done`, the
    // overlay stays at PENDING forever \u2014 which means every boot wipes
    // the overlay, which is why pushed configs + urandom seed kept
    // reverting.
    mark_overlay_ready();

    let config_path = std::env::var("OXWRT_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(config::DEFAULT_PATH));

    // Forensics: log the on-disk config size + the WAN count so
    // we can correlate "pushed config lost on reboot" with what
    // oxwrtd actually read from disk at pid-1 time. Written to
    // /dev/kmsg directly (bypassing the tracing layer) so an
    // early-boot tracing-writer hiccup can't hide it.
    {
        use std::io::Write;
        let live_size = std::fs::metadata(&config_path)
            .map(|m| m.len())
            .unwrap_or(0);
        let rom_path = std::path::PathBuf::from(format!("/rom{}", config_path.display()));
        let rom_size = std::fs::metadata(&rom_path).map(|m| m.len()).unwrap_or(0);
        let live_body = std::fs::read_to_string(&config_path).unwrap_or_default();
        let wan_count = live_body.matches("type = \"wan\"").count();
        let probes = live_body.matches("probe_target").count();
        let backups = live_body.matches("wan-backup").count();
        let upper_new = std::fs::metadata("/overlay/upper/etc/oxwrt/oxwrt.toml")
            .map(|m| m.len())
            .ok();
        let upper_legacy = std::fs::metadata("/overlay/upper/etc/oxwrt.toml")
            .map(|m| m.len())
            .ok();
        let sysupgrade_tgz = std::fs::metadata("/sysupgrade.tgz").is_ok()
            || std::fs::metadata("/overlay/upper/sysupgrade.tgz").is_ok();
        let msg = format!(
            "<4>forensic: path={} live={} rom={} upper_new={:?} upper_legacy={:?} wan_count={} probe_target={} wan_backup={} sysupgrade_tgz={}\n",
            config_path.display(), live_size, rom_size, upper_new, upper_legacy, wan_count, probes, backups, sysupgrade_tgz
        );
        if let Ok(mut kmsg) = std::fs::OpenOptions::new().write(true).open("/dev/kmsg") {
            let _ = kmsg.write_all(msg.as_bytes());
        }
    }

    run_secrets_migration(&config_path);
    tighten_secrets_file_mode(&config_path);
    let cfg = Config::load(&config_path)?;

    // Sanity-truncate coredhcp's persisted lease file if any lease falls
    // outside the configured LAN subnet. This protects against the LAN
    // being renumbered (e.g. 192.168.1.0/24 → 192.168.50.0/24 to fix a
    // double-NAT collision): the range plugin fails fatally with
    // "allocator did not re-allocate requested leased ip X" when it
    // reads a pre-existing lease outside its pool. Losing DHCP lease
    // persistence on a subnet change is an acceptable trade — clients
    // re-DISCOVER within seconds.
    truncate_stale_dhcp_leases(&cfg);

    // Generate per-phy hostapd.conf files at /etc/oxwrt/hostapd/ from
    // the [[radios]] + [[wifi]] config. Bind-mount sources for the
    // hostapd-5g / hostapd-2g services point here (writable overlay
    // path), so changes via CRUD → reload → hostapd restart pick up the
    // new SSID / passphrase without a reflash. Non-fatal: if the write
    // fails, hostapd may start with stale or absent config, but the
    // rest of the router still comes up.
    if let Err(e) = crate::wifi::write_all(&cfg) {
        tracing::error!(error = %e, "wifi: write_all failed at boot");
    }

    // Point the router's own resolver at the LAN IP. Outbound
    // libc-resolving code (ddns reqwest, sysupgrade fetch, etc.)
    // falls through without this — there's no /etc/resolv.conf on
    // a fresh OpenWrt rootfs and nothing else populates it after
    // we ditched dnsmasq + resolvfs. Queries to <lan>:53 hit the
    // firewall's DNAT rule and land on the hickory container,
    // which forwards via DoH — so the router inherits the same
    // encrypted-upstream property as LAN clients.
    write_self_resolv_conf(&cfg);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .worker_threads(2)
        .build()
        .map_err(|e| Error::Runtime(e.to_string()))?;

    rt.block_on(main_loop::async_main(cfg))
}

/// Control-plane-only mode: starts the sQUIC listener + supervisor tick
/// loop, but skips early mounts, network bring-up, service spawning, and
/// firewall install. Safe to run as a normal process (procd managed or
/// from SSH) on a live OpenWrt device — won't touch the network config.
///
/// Use this for development: test CRUD / config-dump / diag / status
/// against real hardware before committing to a PID 1 replacement.
pub fn run_control_only() -> Result<(), Error> {
    let config_path = std::env::var("OXWRT_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(config::DEFAULT_PATH));
    run_secrets_migration(&config_path);
    tighten_secrets_file_mode(&config_path);
    let cfg = Config::load(&config_path)?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .worker_threads(2)
        .build()
        .map_err(|e| Error::Runtime(e.to_string()))?;

    rt.block_on(main_loop::control_only_main(cfg))
}

/// Services-only mode: control plane + supervisor (running the real
/// services declared in config), but no early mounts, no netlink
/// network bring-up, no WAN DHCP, no firewall install. Intermediate
/// between `--control-only` (supervisor empty) and full `--init`
/// (supervisor + netlink + firewall + PID 1 duties). Used during
/// bring-up to exercise the supervisor on a stock OpenWrt device:
/// procd/netifd/fw4 stay in charge of the network, oxwrtd only
/// runs the declared services.
///
/// Prerequisite on the host: `/dev/pts` already mounted (procd does
/// this in its initramfs), cgroup v2 controllers usable (likewise).
/// When we later promote this binary to PID 1, early_mounts() sets
/// those up — but as a side binary we rely on the host's.
pub fn run_services_only() -> Result<(), Error> {
    let config_path = std::env::var("OXWRT_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(config::DEFAULT_PATH));
    run_secrets_migration(&config_path);
    tighten_secrets_file_mode(&config_path);
    let cfg = Config::load(&config_path)?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .worker_threads(2)
        .build()
        .map_err(|e| Error::Runtime(e.to_string()))?;

    rt.block_on(main_loop::services_only_main(cfg))
}

/// Ensure `oxwrt.secrets.toml` is mode 0600 on every boot.
/// Defence-in-depth: an operator hand-edit might copy the file
/// with default umask, exposing the secrets to local non-root
/// processes. Called right after the migration shim, before
/// Config::load, so the permission is tight before anyone reads
/// the file. No-op if the file doesn't exist.
fn tighten_secrets_file_mode(public_path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let secrets = public_path.with_file_name("oxwrt.secrets.toml");
    let Ok(meta) = std::fs::metadata(&secrets) else {
        return;
    };
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o600 {
        if let Err(e) = std::fs::set_permissions(
            &secrets,
            std::fs::Permissions::from_mode(0o600),
        ) {
            tracing::error!(
                error = %e,
                path = %secrets.display(),
                prev_mode = format!("{mode:o}"),
                "failed to tighten oxwrt.secrets.toml mode to 0600"
            );
        } else {
            tracing::warn!(
                path = %secrets.display(),
                prev_mode = format!("{mode:o}"),
                "tightened oxwrt.secrets.toml mode to 0600 (was looser)"
            );
        }
    }
}

/// One-shot migration from the old single-file `oxwrt.toml` (inline
/// secrets) to the split public + `oxwrt.secrets.toml` layout.
///
/// Called once on boot, before `Config::load`. Idempotent:
/// subsequent boots find the public file already clean and
/// short-circuit. On error we log and continue — the loader's
/// merge path handles any partial state.
fn run_secrets_migration(public_path: &Path) {
    use oxwrt_api::secrets::{MigrationOutcome, migrate_public_to_split};
    match migrate_public_to_split(public_path) {
        Ok(MigrationOutcome::Migrated { count }) => {
            tracing::info!(
                count,
                public = %public_path.display(),
                secrets = %public_path.with_file_name("oxwrt.secrets.toml").display(),
                "migrated secrets out of public config; public file is now publishable"
            );
        }
        Ok(MigrationOutcome::AlreadyClean) => {} // steady state
        Ok(MigrationOutcome::NoPublicFile) => {}
        Ok(MigrationOutcome::BothPresentUnsafe) => {
            tracing::warn!(
                public = %public_path.display(),
                "oxwrt.toml contains inline secrets and oxwrt.secrets.toml \
                 already exists; leaving both alone. Delete oxwrt.secrets.toml \
                 to force re-migration, or remove the inline secrets from the \
                 public file by hand."
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "secrets migration failed; loader will merge whatever is on disk");
        }
    }
}

pub(super) fn parse_listen_addrs(listen: &[String]) -> Vec<SocketAddr> {
    listen
        .iter()
        .filter_map(|s| match s.parse::<SocketAddr>() {
            Ok(a) => Some(a),
            Err(e) => {
                tracing::warn!(addr = %s, error = %e, "skipping malformed control listen address");
                None
            }
        })
        .collect()
}

/// Write `/etc/resolv.conf` so libc-resolver-based code on the
/// router (ddns reqwest, sysupgrade fetches, etc.) uses the
/// on-device hickory-dns via the firewall's DNAT rule — the same
/// DoH upstream path LAN clients take. Idempotent.
///
/// Uses the first LAN bridge's address; falls back to the first
/// Simple network if there's no LAN (unusual) and skips entirely
/// if neither exists (router has no internal net to resolve
/// through; local libc queries will fail, but that's already the
/// reality today so no regression).
pub(super) fn write_self_resolv_conf(cfg: &Config) {
    use crate::config::Network;
    let ip = cfg.networks.iter().find_map(|n| match n {
        Network::Lan { address, .. } | Network::Simple { address, .. } => Some(*address),
        Network::Wan { .. } => None,
    });
    let Some(ip) = ip else {
        tracing::info!("no LAN/Simple network configured; skipping /etc/resolv.conf generation");
        return;
    };
    let text = format!(
        "# Auto-generated by oxwrtd at boot. Points at the on-device\n\
         # hickory-dns via the firewall's DNAT rule; do not edit\n\
         # manually — the file is rewritten every boot.\n\
         nameserver {ip}\n"
    );
    if let Err(e) = std::fs::write("/etc/resolv.conf", text) {
        tracing::warn!(error = %e, "failed to write /etc/resolv.conf");
    } else {
        tracing::info!(nameserver = %ip, "wrote /etc/resolv.conf");
    }
}
