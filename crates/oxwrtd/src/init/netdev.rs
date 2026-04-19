//! Netdev rename from DTS labels + wifi AP interface creation.
//! Split out of init.rs in step 6.

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

/// Create one AP-mode virtual iface per physical wifi radio — one
/// `{phy}-ap0` per entry under /sys/class/ieee80211. Matches the
/// naming convention consumed by collect_ap_status + hostapd
/// config. No-op if `iw` isn't present (dev/test boxes without
/// wifi kmods) so oxwrtd still boots cleanly.
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
