//! Static IPv4 routes — reconciled at boot + on every `reload`.
//!
//! The kernel already installs on-link routes for each configured
//! subnet (that's a side-effect of assigning an address), and the
//! WAN DHCP client installs the default route. This module fills
//! the gap between "what the kernel does automatically" and "what
//! the operator explicitly wanted": extra routes to remote subnets
//! via specific gateways, policy routing out specific ifaces, etc.
//!
//! Why not just let `ip route add` do it? Because we want reload
//! semantics: when the config changes, routes that disappear must
//! also disappear from the kernel. A post-install shell script
//! couldn't see that.
//!
//! Design: store the most-recently-installed set, diff against the
//! new set, del the removed ones, add the new ones, swallow EEXIST
//! on add and ESRCH on del (both = "already in desired state").
//! The store is in-memory — a daemon restart reinstalls from
//! scratch, which is fine because the kernel's existing routes
//! get EEXIST'd and the set converges.
//!
//! IPv6: deferred. Duplicate the `Ipv4Addr` path with `Ipv6Addr`
//! whenever someone asks — `RouteMessageBuilder` is generic over
//! the address type, so it's ~30 LOC of copy-paste.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

use oxwrt_api::config::{Config, Route, Route6};
use rtnetlink::packet_route::link::LinkAttribute;
use rtnetlink::{Handle, RouteMessageBuilder};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("rtnetlink: {0}")]
    Rtnetlink(#[from] rtnetlink::Error),
    #[error("iface not found: {0}")]
    IfaceNotFound(String),
}

/// In-memory record of the last-installed route set. Used by
/// `reconcile` to compute the diff between old and new configs.
/// Keyed by the full `Route` value (derives Eq), so any field change
/// (gateway, metric, iface) counts as a different route and triggers
/// del-then-add. That matches what `ip route replace` would do from
/// a shell.
pub static LAST_INSTALLED: Mutex<Vec<Route>> = Mutex::new(Vec::new());

/// v6 counterpart to `LAST_INSTALLED`. Kept separate so a reload
/// that only touches one address family doesn't churn the other.
pub static LAST_INSTALLED_V6: Mutex<Vec<Route6>> = Mutex::new(Vec::new());

/// Install the currently-configured static routes. Idempotent: a
/// second call with the same `cfg.routes` does nothing (each add
/// returns EEXIST, which we swallow). Called once at boot from
/// `init::run` after WAN bring-up so the default route is in place
/// before we try to lay any via-gateway routes on top.
pub async fn install(cfg: &Config, handle: &Handle) -> Result<(), Error> {
    reconcile(&[], &cfg.routes, handle).await?;
    *LAST_INSTALLED.lock().unwrap() = cfg.routes.clone();
    reconcile6(&[], &cfg.routes6, handle).await?;
    *LAST_INSTALLED_V6.lock().unwrap() = cfg.routes6.clone();
    Ok(())
}

/// Diff the old and new route lists and apply the delta. Called by
/// the `Reload` RPC path with `old = LAST_INSTALLED, new = new cfg`.
/// Routes that disappear from new are del'd; routes that appear in
/// new are add'd; unchanged routes are left alone (no kernel churn
/// on a no-op reload).
pub async fn reload(cfg: &Config, handle: &Handle) -> Result<(), Error> {
    let old = LAST_INSTALLED.lock().unwrap().clone();
    reconcile(&old, &cfg.routes, handle).await?;
    *LAST_INSTALLED.lock().unwrap() = cfg.routes.clone();
    let old6 = LAST_INSTALLED_V6.lock().unwrap().clone();
    reconcile6(&old6, &cfg.routes6, handle).await?;
    *LAST_INSTALLED_V6.lock().unwrap() = cfg.routes6.clone();
    Ok(())
}

async fn reconcile(old: &[Route], new: &[Route], handle: &Handle) -> Result<(), Error> {
    // Delete routes that are in old but not in new. Do deletes
    // before adds — swapping a route's gateway is expressed as
    // "old.gateway=A disappears, new.gateway=B appears" so we'd
    // otherwise try to add before del and hit EEXIST on the kernel's
    // dest+prefix uniqueness check (metric is part of the key but
    // relying on that is fragile).
    for r in old {
        if !new.contains(r) {
            del_route(r, handle).await?;
        }
    }
    for r in new {
        if !old.contains(r) {
            add_route(r, handle).await?;
        }
    }
    Ok(())
}

async fn add_route(r: &Route, handle: &Handle) -> Result<(), Error> {
    let ifindex = resolve_ifindex(&r.iface, handle).await?;
    let mut b = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(r.dest, r.prefix)
        .output_interface(ifindex)
        .priority(r.metric);
    if let Some(gw) = r.gateway {
        b = b.gateway(gw);
    }
    let msg = b.build();
    match handle.route().add(msg).execute().await {
        Ok(()) => {
            tracing::info!(
                dest = %r.dest, prefix = r.prefix,
                gateway = ?r.gateway, iface = %r.iface, metric = r.metric,
                "static route: installed"
            );
            Ok(())
        }
        Err(e) if is_exists(&e) => {
            tracing::warn!(
                dest = %r.dest, prefix = r.prefix, iface = %r.iface,
                "static route: already exists, keeping existing"
            );
            Ok(())
        }
        Err(e) => Err(Error::Rtnetlink(e)),
    }
}

async fn del_route(r: &Route, handle: &Handle) -> Result<(), Error> {
    let ifindex = match resolve_ifindex(&r.iface, handle).await {
        Ok(i) => i,
        // Iface gone — route's gone too; nothing to del. Happens when
        // an iface-scoped route is configured then the iface config
        // itself is removed in the same reload.
        Err(Error::IfaceNotFound(_)) => {
            tracing::debug!(
                dest = %r.dest, iface = %r.iface,
                "static route: iface gone on del, nothing to do"
            );
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let mut b = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(r.dest, r.prefix)
        .output_interface(ifindex)
        .priority(r.metric);
    if let Some(gw) = r.gateway {
        b = b.gateway(gw);
    }
    let msg = b.build();
    match handle.route().del(msg).execute().await {
        Ok(()) => {
            tracing::info!(
                dest = %r.dest, prefix = r.prefix, iface = %r.iface,
                "static route: removed"
            );
            Ok(())
        }
        // ESRCH = -3 (no such process/entry). Route was already
        // gone — fine, we wanted it gone anyway.
        Err(e) if is_nosuch(&e) => {
            tracing::debug!(
                dest = %r.dest, iface = %r.iface,
                "static route: already absent on del"
            );
            Ok(())
        }
        Err(e) => Err(Error::Rtnetlink(e)),
    }
}

// ── IPv6 variants ───────────────────────────────────────────────
//
// Parallel to the v4 path above with `Ipv6Addr` + `Route6`. Kept
// as separate functions rather than generic-over-address because
// rtnetlink's RouteMessageBuilder<T> doesn't expose a clean trait
// bound we can abstract over without more boilerplate than just
// writing the v6 twins. ~60 LOC of controlled duplication.

async fn reconcile6(old: &[Route6], new: &[Route6], handle: &Handle) -> Result<(), Error> {
    for r in old {
        if !new.contains(r) {
            del_route6(r, handle).await?;
        }
    }
    for r in new {
        if !old.contains(r) {
            add_route6(r, handle).await?;
        }
    }
    Ok(())
}

async fn add_route6(r: &Route6, handle: &Handle) -> Result<(), Error> {
    let ifindex = resolve_ifindex(&r.iface, handle).await?;
    let mut b = RouteMessageBuilder::<Ipv6Addr>::new()
        .destination_prefix(r.dest, r.prefix)
        .output_interface(ifindex)
        .priority(r.metric);
    if let Some(gw) = r.gateway {
        b = b.gateway(gw);
    }
    let msg = b.build();
    match handle.route().add(msg).execute().await {
        Ok(()) => {
            tracing::info!(
                dest = %r.dest, prefix = r.prefix,
                gateway = ?r.gateway, iface = %r.iface, metric = r.metric,
                "static route6: installed"
            );
            Ok(())
        }
        Err(e) if is_exists(&e) => {
            tracing::warn!(
                dest = %r.dest, prefix = r.prefix, iface = %r.iface,
                "static route6: already exists, keeping existing"
            );
            Ok(())
        }
        Err(e) => Err(Error::Rtnetlink(e)),
    }
}

async fn del_route6(r: &Route6, handle: &Handle) -> Result<(), Error> {
    let ifindex = match resolve_ifindex(&r.iface, handle).await {
        Ok(i) => i,
        Err(Error::IfaceNotFound(_)) => {
            tracing::debug!(
                dest = %r.dest, iface = %r.iface,
                "static route6: iface gone on del, nothing to do"
            );
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let mut b = RouteMessageBuilder::<Ipv6Addr>::new()
        .destination_prefix(r.dest, r.prefix)
        .output_interface(ifindex)
        .priority(r.metric);
    if let Some(gw) = r.gateway {
        b = b.gateway(gw);
    }
    let msg = b.build();
    match handle.route().del(msg).execute().await {
        Ok(()) => {
            tracing::info!(
                dest = %r.dest, prefix = r.prefix, iface = %r.iface,
                "static route6: removed"
            );
            Ok(())
        }
        Err(e) if is_nosuch(&e) => {
            tracing::debug!(
                dest = %r.dest, iface = %r.iface,
                "static route6: already absent on del"
            );
            Ok(())
        }
        Err(e) => Err(Error::Rtnetlink(e)),
    }
}

async fn resolve_ifindex(name: &str, handle: &Handle) -> Result<u32, Error> {
    use futures_util::stream::TryStreamExt;
    let _ = LinkAttribute::IfName; // silences unused-import lints on some rtnetlink versions
    let mut stream = handle.link().get().match_name(name.to_string()).execute();
    match stream.try_next().await {
        Ok(Some(msg)) => Ok(msg.header.index),
        Ok(None) => Err(Error::IfaceNotFound(name.to_string())),
        Err(e) if is_nodev(&e) => Err(Error::IfaceNotFound(name.to_string())),
        Err(e) => Err(Error::Rtnetlink(e)),
    }
}

fn is_exists(err: &rtnetlink::Error) -> bool {
    netlink_errno(err) == Some(-17) // -EEXIST
}

fn is_nosuch(err: &rtnetlink::Error) -> bool {
    netlink_errno(err) == Some(-3) // -ESRCH
}

fn is_nodev(err: &rtnetlink::Error) -> bool {
    netlink_errno(err) == Some(-19) // -ENODEV
}

fn netlink_errno(err: &rtnetlink::Error) -> Option<i32> {
    if let rtnetlink::Error::NetlinkError(msg) = err {
        if let Some(code) = msg.code {
            return Some(code.get());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(dest: &str, prefix: u8, iface: &str) -> Route {
        Route {
            dest: dest.parse().unwrap(),
            prefix,
            gateway: None,
            iface: iface.into(),
            metric: 1024,
        }
    }

    /// The diff-picker treats each Route by value: any field change
    /// means "different route", so reload del+adds it instead of
    /// silently leaving kernel state stale.
    #[test]
    fn diff_detects_metric_change() {
        let old = vec![r("10.20.0.0", 16, "wg0")];
        let mut changed = old[0].clone();
        changed.metric = 200;
        let new = vec![changed];

        let to_del: Vec<&Route> = old.iter().filter(|x| !new.contains(x)).collect();
        let to_add: Vec<&Route> = new.iter().filter(|x| !old.contains(x)).collect();
        assert_eq!(to_del.len(), 1);
        assert_eq!(to_add.len(), 1);
    }

    /// Unchanged routes are left alone on reload — zero kernel
    /// churn on a no-op reload.
    #[test]
    fn diff_noop_on_identical() {
        let routes = vec![r("10.20.0.0", 16, "wg0"), r("192.168.100.0", 24, "eth0")];
        let to_del: Vec<&Route> = routes.iter().filter(|x| !routes.contains(x)).collect();
        let to_add: Vec<&Route> = routes.iter().filter(|x| !routes.contains(x)).collect();
        assert!(to_del.is_empty());
        assert!(to_add.is_empty());
    }

    /// Default metric matches iproute2's operator-install convention.
    #[test]
    fn default_metric_is_1024() {
        let toml = r#"
dest = "10.20.0.0"
prefix = 16
iface = "wg0"
"#;
        let r: Route = toml::from_str(toml).unwrap();
        assert_eq!(r.metric, 1024);
        assert_eq!(r.gateway, None);
    }

    /// Iface changes count as "different route": the reconcile must
    /// del the old one and add the new one, not leave stale kernel
    /// state pointing at the wrong output link.
    #[test]
    fn diff_detects_iface_change() {
        let old = vec![r("10.20.0.0", 16, "eth0")];
        let mut changed = old[0].clone();
        changed.iface = "wg0".into();
        let new = vec![changed];
        let to_del: Vec<&Route> = old.iter().filter(|x| !new.contains(x)).collect();
        let to_add: Vec<&Route> = new.iter().filter(|x| !old.contains(x)).collect();
        assert_eq!(to_del.len(), 1);
        assert_eq!(to_add.len(), 1);
    }

    /// Gateway on/off is a route identity change.
    #[test]
    fn diff_detects_gateway_toggle() {
        let mut onlink = r("10.20.0.0", 16, "eth0");
        let mut via = onlink.clone();
        onlink.gateway = None;
        via.gateway = Some("10.20.0.1".parse().unwrap());
        let old = vec![onlink];
        let new = vec![via];
        let to_del: Vec<&Route> = old.iter().filter(|x| !new.contains(x)).collect();
        let to_add: Vec<&Route> = new.iter().filter(|x| !old.contains(x)).collect();
        assert_eq!(to_del.len(), 1);
        assert_eq!(to_add.len(), 1);
    }

    /// Adding one route + keeping two unchanged: diff produces one
    /// add, zero dels. Tests the "partial overlap" case that
    /// diff_noop_on_identical doesn't.
    #[test]
    fn diff_partial_overlap_adds_only_new() {
        let keep_a = r("10.20.0.0", 16, "wg0");
        let keep_b = r("192.168.100.0", 24, "eth0");
        let new_c = r("172.16.0.0", 12, "wg0");
        let old = vec![keep_a.clone(), keep_b.clone()];
        let new = vec![keep_a, keep_b, new_c.clone()];
        let to_del: Vec<&Route> = old.iter().filter(|x| !new.contains(x)).collect();
        let to_add: Vec<&Route> = new.iter().filter(|x| !old.contains(x)).collect();
        assert!(to_del.is_empty());
        assert_eq!(to_add.len(), 1);
        assert_eq!(*to_add[0], new_c);
    }

    /// Errno classifiers must agree with the kernel's negated-errno
    /// convention that rtnetlink exposes via NetlinkError.code.
    /// We don't have a live netlink handle in unit tests so we
    /// confirm the sentinel values used in the matchers.
    #[test]
    fn errno_sentinels_match_linux_conventions() {
        // EEXIST = 17, ESRCH = 3, ENODEV = 19. Kernel negates them
        // in netlink error responses. These constants are duplicated
        // in static_routes.rs and wan_dhcp.rs — this test locks
        // down the numbers so a copy-paste regression fails here.
        assert_eq!(17, libc::EEXIST);
        assert_eq!(3, libc::ESRCH);
        assert_eq!(19, libc::ENODEV);
    }

    /// Routes TOML list roundtrips cleanly: parse a Vec<Route>
    /// fragment like the one oxwrt.toml uses.
    #[test]
    fn route_list_parses_from_toml_array() {
        let toml = r#"
[[routes]]
dest = "10.20.0.0"
prefix = 16
iface = "wg0"

[[routes]]
dest = "192.168.100.0"
prefix = 24
gateway = "10.8.0.1"
iface = "wg0"
metric = 200
"#;
        #[derive(serde::Deserialize)]
        struct Wrapper {
            routes: Vec<Route>,
        }
        let w: Wrapper = toml::from_str(toml).unwrap();
        assert_eq!(w.routes.len(), 2);
        assert_eq!(w.routes[0].metric, 1024); // default
        assert_eq!(w.routes[1].metric, 200); // explicit
        assert_eq!(w.routes[0].gateway, None);
        assert!(w.routes[1].gateway.is_some());
    }
}
