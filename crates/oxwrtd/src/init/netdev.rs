//! Netdev rename from DTS labels + wifi AP interface creation.
//! Split out of init.rs in step 6.

use super::*;

pub(super) fn rename_netdevs_from_dts() {
    let rd = match std::fs::read_dir("/sys/class/net") {
        Ok(rd) => rd,
        Err(e) => {
            tracing::warn!(error = %e, "netdev_rename: read /sys/class/net failed");
            return;
        }
    };

    // Gather (current_name, desired_label) pairs by reading sysfs.
    // Two possible label sources match OpenWrt convention: `label`
    // (standard) and `openwrt,netdev-name` (target-overridden).
    let mut pairs: Vec<(String, String)> = Vec::new();
    for entry in rd.flatten() {
        let cur = match entry.file_name().into_string() {
            Ok(s) => s,
            Err(_) => continue,
        };
        // Try target-specific name first, then the standard label.
        let label =
            std::fs::read_to_string(entry.path().join("of_node").join("openwrt,netdev-name"))
                .or_else(|_| std::fs::read_to_string(entry.path().join("of_node").join("label")));
        let Ok(label) = label else {
            continue;
        };
        let label = label.trim().trim_end_matches('\0').to_string();
        if label.is_empty() || label == cur {
            continue;
        }
        pairs.push((cur, label));
    }
    if pairs.is_empty() {
        return;
    }

    // Spin a current-thread runtime just for these netlink ops; drop
    // it once all renames are dispatched.
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::warn!(error = %e, "netdev_rename: tokio runtime build failed");
            return;
        }
    };
    rt.block_on(async {
        use rtnetlink::{LinkUnspec, new_connection};
        let (connection, handle, _) = match new_connection() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "netdev_rename: rtnetlink connection failed");
                return;
            }
        };
        let conn_task = tokio::spawn(connection);

        for (cur, desired) in &pairs {
            use futures_util::TryStreamExt;
            let mut stream = handle
                .link()
                .get()
                .match_name(cur.clone())
                .execute();
            let idx = match stream.try_next().await {
                Ok(Some(msg)) => msg.header.index,
                Ok(None) => {
                    tracing::warn!(cur = %cur, "netdev_rename: link disappeared mid-scan");
                    continue;
                }
                Err(e) => {
                    tracing::warn!(cur = %cur, error = %e, "netdev_rename: link_get failed");
                    continue;
                }
            };
            // Rename. In rtnetlink 0.20, LinkUnspec::name() attaches
            // IFLA_IFNAME to the set() message — exact equivalent of
            // `ip link set dev <cur> name <desired>`.
            let req = LinkUnspec::new_with_index(idx)
                .name(desired.clone())
                .build();
            match handle.link().set(req).execute().await {
                Ok(()) => {
                    tracing::info!(cur = %cur, desired = %desired, "netdev renamed");
                }
                Err(e) => {
                    tracing::warn!(cur = %cur, desired = %desired, error = %e, "netdev rename failed");
                }
            }
        }

        drop(handle);
        conn_task.abort();
    });
}

/// If the rootfs overlay isn't already attached (i.e. /overlay has no
/// mount entry in /proc/mounts), do a full libfstools-equivalent setup:
/// find the rootfs partition, locate the overlay region after the
/// squashfs tail, create a loop device at that offset, detect the
/// f2fs filesystem on it (or format if first boot / DEADCODE marker),
/// mount the f2fs, stack overlayfs with `lowerdir=/,upperdir=/overlay/
/// upper,workdir=/overlay/work`, pivot_root into the stacked tree.
/// Finally restore any sysupgrade config-backup tgz into upper.
///
/// In coexist mode (Stage 1-3), procd-init's preinit pipeline has
/// already done all this before our pid-1 entry — /proc/mounts will
/// show an `overlay` mount on `/` and an f2fs mount on /overlay.
/// Detect and return early with a single info log.
///
/// Only the detect path is wired up at this stage. The hot path
/// is stubbed (with a clear error) until Stage 4, where we actually
/// remove procd-init and need to own the mount lifecycle. Landing
/// the function now lets us verify the detection against real boot

pub(super) fn create_wifi_ap_interfaces() {
    let iw_path = std::path::Path::new("/usr/bin/iw");
    if !iw_path.exists() {
        tracing::debug!("iw not present, skipping wifi AP interface creation");
        return;
    }
    let phys_dir = std::path::Path::new("/sys/class/ieee80211");
    let rd = match std::fs::read_dir(phys_dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::debug!("no /sys/class/ieee80211 (wifi driver not loaded); skipping");
            return;
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to enumerate wifi phys");
            return;
        }
    };
    for ent in rd.flatten() {
        let Some(phy) = ent.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let ifname = format!("{phy}-ap0");
        // If the iface already exists, skip — `iw` returns EEXIST via
        // exit code, but checking /sys avoids the process spawn.
        if std::path::Path::new(&format!("/sys/class/net/{ifname}")).exists() {
            tracing::info!(phy, ifname, "wifi AP iface already exists");
            continue;
        }
        let status = std::process::Command::new(iw_path)
            .args(["phy", &phy, "interface", "add", &ifname, "type", "__ap"])
            .status();
        match status {
            Ok(s) if s.success() => {
                tracing::info!(phy, ifname, "created wifi AP interface");
            }
            Ok(s) => {
                tracing::warn!(phy, ifname, exit = ?s.code(),
                    "iw interface add failed (phy may not support AP mode)");
            }
            Err(e) => {
                tracing::warn!(phy, ifname, error = %e, "failed to spawn iw");
            }
        }
    }
}
