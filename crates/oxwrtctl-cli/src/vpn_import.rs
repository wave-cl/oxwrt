//! `oxctl <remote> vpn-profile import <name> <conf-path>` — client-
//! side orchestration for dropping a provider-supplied WireGuard
//! `.conf` into the router as a new `[[vpn_client]]` profile plus
//! its private key.
//!
//! Runs three RPCs in sequence on the same sQUIC connection:
//!
//! 1. VpnKeyUpload — writes /etc/oxwrt/vpn/<name>.key at 0600.
//! 2. ConfigDump — pulls the live oxwrt.toml text.
//! 3. ConfigPush — sends back the TOML with a `[[vpn_client]]`
//!    block for <name> added-or-replaced.
//!
//! Parsing is pragmatic: the wg-quick `.conf` grammar is an INI
//! subset, and providers (Mullvad, Proton) write the same fields
//! in the same order every time. We scan for `Key = Value` lines,
//! pick out what we need, ignore the rest. IPv6 Address entries
//! are dropped (v1 is v4-only); operators who want full-tunnel v6
//! need the follow-up commit that adds routes6 for vpn_client.
//!
//! TOML editing uses `toml_edit` so the operator's inline comments
//! and section ordering survive the round-trip. That matters
//! because the oxwrt.toml shipped as a cookbook has ~900 lines of
//! operator-facing commentary that a plain `toml` parse-and-
//! reserialize would wipe.

use std::net::Ipv4Addr;

/// What we pulled out of a wg-quick-style `.conf`. Every field
/// except `preshared_key` + `keepalive` corresponds to something
/// a provider always emits; PSK + keepalive are optional.
#[derive(Debug, Default)]
pub struct ParsedConf {
    pub private_key: String,
    pub public_key: String,
    pub address_v4: Option<String>,
    pub address_v6: Option<String>,
    pub dns_v4: Vec<Ipv4Addr>,
    pub endpoint: String,
    pub preshared_key: Option<String>,
    pub persistent_keepalive: Option<u16>,
    pub mtu: Option<u32>,
}

/// Parse a wg-quick `.conf`. Returns the fields we need to emit a
/// `[[vpn_client]]` TOML block. Intentionally strict on the key
/// fields — if PrivateKey or Endpoint is missing, the output
/// wouldn't work anyway, so fail early with a clear message.
pub fn parse_conf(text: &str) -> Result<ParsedConf, String> {
    let mut out = ParsedConf::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        // Split on the FIRST '=' — base64 keys end with '='
        // padding which a naive split would shred.
        let (k, v) = match line.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        let key = k.trim();
        let val = v.trim();
        match key {
            "PrivateKey" => out.private_key = val.to_string(),
            "PublicKey" => out.public_key = val.to_string(),
            "PresharedKey" => out.preshared_key = Some(val.to_string()),
            "Endpoint" => out.endpoint = val.to_string(),
            "PersistentKeepalive" => out.persistent_keepalive = val.parse().ok(),
            "MTU" => out.mtu = val.parse().ok(),
            "Address" => {
                // Mullvad emits both v4 and v6 comma-separated:
                //   "10.66.24.93/32,fc00:bbbb:bbbb:bb01::/128"
                // Capture both; v4 is required for v1 to work,
                // v6 enables the optional v6 full-tunnel path.
                for part in val.split(',') {
                    let t = part.trim();
                    let Some((ip, _)) = t.split_once('/') else {
                        continue;
                    };
                    if ip.parse::<Ipv4Addr>().is_ok() {
                        out.address_v4 = Some(t.to_string());
                    } else if ip.parse::<std::net::Ipv6Addr>().is_ok() {
                        out.address_v6 = Some(t.to_string());
                    }
                }
            }
            "DNS" => {
                for part in val.split(',') {
                    if let Ok(v4) = part.trim().parse::<Ipv4Addr>() {
                        out.dns_v4.push(v4);
                    }
                }
            }
            _ => {}
        }
    }
    if out.private_key.is_empty() {
        return Err("conf parse: missing PrivateKey".into());
    }
    if out.public_key.is_empty() {
        return Err("conf parse: missing PublicKey".into());
    }
    if out.endpoint.is_empty() {
        return Err("conf parse: missing Endpoint".into());
    }
    if out.address_v4.is_none() {
        return Err("conf parse: no IPv4 Address found".into());
    }
    if out.dns_v4.is_empty() {
        return Err("conf parse: no IPv4 DNS entry found".into());
    }
    Ok(out)
}

/// Produce a `[[vpn_client]]` TOML block for the imported profile.
/// Iface and priority default to sensible values if caller passes
/// None (auto-assign). Probe target defaults to the first DNS
/// entry — conventional on commercial VPNs where DNS is only
/// reachable through the tunnel, so probing it is equivalent to
/// "is the tunnel really carrying traffic?"
pub fn render_block(
    name: &str,
    iface: &str,
    priority: u32,
    parsed: &ParsedConf,
    key_path: &str,
) -> String {
    use std::fmt::Write as _;
    let probe_target = parsed
        .dns_v4
        .first()
        .copied()
        .unwrap_or(Ipv4Addr::new(1, 1, 1, 1));
    let mut out = String::new();
    writeln!(out, "[[vpn_client]]").unwrap();
    writeln!(out, "name = {:?}", name).unwrap();
    writeln!(out, "iface = {:?}", iface).unwrap();
    writeln!(out, "priority = {}", priority).unwrap();
    writeln!(out, "key_path = {:?}", key_path).unwrap();
    writeln!(
        out,
        "address = {:?}",
        parsed.address_v4.as_deref().unwrap_or("")
    )
    .unwrap();
    if let Some(a6) = &parsed.address_v6 {
        writeln!(out, "address_v6 = {:?}", a6).unwrap();
    }
    let dns_list: Vec<String> = parsed
        .dns_v4
        .iter()
        .map(|d| format!("{:?}", d.to_string()))
        .collect();
    writeln!(out, "dns = [{}]", dns_list.join(", ")).unwrap();
    if let Some(mtu) = parsed.mtu {
        writeln!(out, "mtu = {}", mtu).unwrap();
    }
    writeln!(out, "probe_target = {:?}", probe_target.to_string()).unwrap();
    writeln!(out, "endpoint = {:?}", parsed.endpoint).unwrap();
    writeln!(out, "public_key = {:?}", parsed.public_key).unwrap();
    if let Some(psk) = &parsed.preshared_key {
        // PSK as raw base64 is a secret; we don't write it into
        // oxwrt.toml. The schema has `preshared_key_path`, not a
        // PSK value — operator stages the file separately if they
        // need one.
        let _ = psk;
        writeln!(
            out,
            "# preshared_key_path = \"/etc/oxwrt/vpn/{}.psk\"   # PSK was in the .conf but not imported — stage manually if needed",
            name
        )
        .unwrap();
    }
    if let Some(ka) = parsed.persistent_keepalive {
        writeln!(out, "persistent_keepalive = {}", ka).unwrap();
    }
    out
}

/// Merge a freshly-rendered `[[vpn_client]]` block into an
/// existing oxwrt.toml text. If a block with `name = <n>` already
/// exists, it's replaced; otherwise the new block is appended.
/// Uses toml_edit to preserve comments + ordering in the rest of
/// the file.
pub fn merge_vpn_block(existing_toml: &str, name: &str, new_block: &str) -> Result<String, String> {
    let mut doc: toml_edit::DocumentMut = existing_toml
        .parse()
        .map_err(|e| format!("parse existing oxwrt.toml: {e}"))?;
    // Parse the new block in isolation so we get a typed Item we
    // can splice in.
    let new_doc: toml_edit::DocumentMut = new_block
        .parse()
        .map_err(|e| format!("parse new [[vpn_client]]: {e}"))?;
    let new_arr = new_doc
        .get("vpn_client")
        .and_then(|i| i.as_array_of_tables())
        .ok_or_else(|| "new block didn't produce an array of tables".to_string())?
        .clone();
    let new_item = new_arr
        .iter()
        .next()
        .ok_or_else(|| "new block is empty".to_string())?
        .clone();

    // Find the target array-of-tables in the existing doc.
    // toml_edit stores [[foo]] arrays as Item::ArrayOfTables, but
    // a struct-serialized empty Vec<T> lands as Item::Value(Array
    // []) — which is also how `handle_config_dump` on the router
    // emits an absent vpn_client field. Replace either variant
    // with a fresh ArrayOfTables so push() works.
    use toml_edit::{ArrayOfTables, Item};
    let replace = match doc.get("vpn_client") {
        None => true,
        Some(Item::ArrayOfTables(_)) => false,
        Some(Item::Value(v)) => v.as_array().map(|a| a.is_empty()).unwrap_or(true),
        Some(_) => true,
    };
    if replace {
        doc.insert("vpn_client", Item::ArrayOfTables(ArrayOfTables::new()));
    }
    let arr: &mut ArrayOfTables = match doc
        .get_mut("vpn_client")
        .expect("just inserted or verified")
    {
        Item::ArrayOfTables(a) => a,
        other => {
            return Err(format!(
                "vpn_client exists but isn't [[array]] after normalize ({:?})",
                other.type_name()
            ));
        }
    };
    // toml_edit's ArrayOfTables has push + remove but no insert;
    // replace is therefore "remove at idx, push to end". Ordering
    // among vpn_client entries is operator-cosmetic only (the
    // failover coordinator scans by `priority`, not by position),
    // so the re-position is harmless.
    let replace_idx = arr.iter().position(|t| {
        t.get("name")
            .and_then(|i| i.as_value())
            .and_then(|v| v.as_str())
            == Some(name)
    });
    if let Some(idx) = replace_idx {
        arr.remove(idx);
    }
    arr.push(new_item);
    Ok(doc.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MULLVAD_SAMPLE: &str = "\
[Interface]
# Device: Decent Ox
PrivateKey = XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX=
Address = 10.66.24.93/32,fc00:bbbb:bbbb:bb01::3:185c/128
DNS = 10.64.0.1
[Peer]
PublicKey = ddv7vosBlf396nOa79nWn6qXQu2LzezGXfNUDO3hAXQ=
AllowedIPs = 0.0.0.0/0,::0/0
Endpoint = 103.251.26.127:51820
";

    #[test]
    fn parses_mullvad_conf() {
        let p = parse_conf(MULLVAD_SAMPLE).unwrap();
        assert_eq!(
            p.private_key,
            "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX="
        );
        assert_eq!(p.public_key, "ddv7vosBlf396nOa79nWn6qXQu2LzezGXfNUDO3hAXQ=");
        assert_eq!(p.address_v4.as_deref(), Some("10.66.24.93/32"));
        assert_eq!(
            p.address_v6.as_deref(),
            Some("fc00:bbbb:bbbb:bb01::3:185c/128")
        );
        assert_eq!(p.dns_v4, vec![Ipv4Addr::new(10, 64, 0, 1)]);
        assert_eq!(p.endpoint, "103.251.26.127:51820");
    }

    #[test]
    fn rejects_missing_fields() {
        let err = parse_conf("[Interface]\nAddress = 10.0.0.1/32\n").unwrap_err();
        assert!(err.contains("PrivateKey"), "got: {err}");
    }

    #[test]
    fn renders_block_with_quoted_strings() {
        let parsed = parse_conf(MULLVAD_SAMPLE).unwrap();
        let out = render_block(
            "mullvad-se",
            "wgvpn0",
            100,
            &parsed,
            "/etc/oxwrt/vpn/mullvad-se.key",
        );
        assert!(out.contains(r#"name = "mullvad-se""#), "got: {out}");
        assert!(out.contains(r#"iface = "wgvpn0""#));
        assert!(out.contains(r#"address = "10.66.24.93/32""#));
        assert!(out.contains("probe_target"));
        assert!(out.contains("priority = 100"));
    }

    #[test]
    fn merge_appends_when_absent() {
        let existing = "hostname = \"box\"\n\n[control]\nlisten = []\nauthorized_keys = \"/x\"\n";
        let new_block = "[[vpn_client]]\nname = \"mullvad-se\"\niface = \"wgvpn0\"\npriority = 100\naddress = \"10.64.0.2/32\"\ndns = [\"10.64.0.1\"]\nprobe_target = \"10.64.0.1\"\nendpoint = \"1.2.3.4:51820\"\npublic_key = \"AAA=\"\nkey_path = \"/etc/oxwrt/vpn/mullvad-se.key\"\n";
        let out = merge_vpn_block(existing, "mullvad-se", new_block).unwrap();
        assert!(out.contains("hostname = \"box\""), "preserves existing");
        assert!(out.contains("[[vpn_client]]"), "has the new block");
        assert!(out.contains("mullvad-se"));
    }

    #[test]
    fn merge_replaces_when_present() {
        let existing = "hostname = \"box\"\n\n[[vpn_client]]\nname = \"mullvad-se\"\nendpoint = \"OLD:51820\"\n\n[control]\nlisten = []\nauthorized_keys = \"/x\"\n";
        let new_block = "[[vpn_client]]\nname = \"mullvad-se\"\nendpoint = \"NEW:51820\"\n";
        let out = merge_vpn_block(existing, "mullvad-se", new_block).unwrap();
        assert!(out.contains("NEW:51820"), "has the new endpoint: {out}");
        assert!(!out.contains("OLD:51820"), "old endpoint gone: {out}");
    }
}
