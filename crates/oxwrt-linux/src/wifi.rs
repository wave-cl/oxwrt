//! Wifi config generator: translates `[[radios]]` + `[[wifi]]` entries
//! from the TOML config into per-phy hostapd.conf files that the
//! hostapd-5g / hostapd-2g services consume via bind-mount.
//!
//! Why runtime-generated rather than baked into the image: wifi config
//! (SSID, passphrase, channel, enabled/disabled) is the highest-turnover
//! user-facing setting on a router. Gating it on a reflash would make
//! the operator experience miserable. Instead:
//!
//!   - User edits via CRUD RPC (`wifi add`, `wifi update`, etc.) or
//!     `config-push` with a new TOML.
//!   - `reload` (or boot) calls `write_all()` which regenerates every
//!     per-phy hostapd.conf at /etc/oxwrt/hostapd/ (overlayfs — writable).
//!   - The hostapd-5g / hostapd-2g services bind-mount these files and
//!     get restarted by the supervisor, picking up the new config.
//!
//! On first boot after a clean flash, the overlay has no /etc/oxwrt/
//! hostapd/ yet; `write_all()` creates the dir + populates it before
//! the supervisor tries to start the hostapd services.

use oxwrt_api::config::{Config, Radio, Wifi, WifiSecurity};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};

/// Directory where generated hostapd configs live. On overlayfs, matches
/// the bind-mount source in [[services.binds]] for hostapd-5g / -2g.
pub const CONF_DIR: &str = "/etc/oxwrt/hostapd";

/// Generate the hostapd.conf content for every radio that has at least
/// one non-hidden, non-disabled SSID. Returns a map of `phy → config
/// text`. Radios with no wifi entries are omitted (caller should not
/// write a file for them).
///
/// The first `[[wifi]]` entry for a radio becomes the primary BSS
/// (single-BSS for now; multi-SSID via `bss=` subsections is future
/// work). If a radio is marked `disabled = true` in config, no file is
/// emitted for it.
pub fn generate_all(cfg: &Config) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    // Index [[wifi]] by radio (phy name).
    let mut wifi_by_phy: BTreeMap<&str, Vec<&Wifi>> = BTreeMap::new();
    for w in &cfg.wifi {
        wifi_by_phy.entry(w.radio.as_str()).or_default().push(w);
    }
    for radio in &cfg.radios {
        if radio.disabled {
            continue;
        }
        let Some(wifis) = wifi_by_phy.get(radio.phy.as_str()) else {
            continue;
        };
        if wifis.is_empty() {
            continue;
        }
        // First wifi becomes the primary BSS (phyN-ap0). Any additional
        // [[wifi]] entries for this radio land as `bss=phyN-apM`
        // sub-sections — hostapd auto-creates the child netdevs via
        // nl80211. MT7976 supports up to 16 VAPs per radio.
        let conf = build_hostapd_conf(radio, wifis);
        out.insert(radio.phy.clone(), conf);
    }
    out
}

/// Write generated configs to `CONF_DIR`, creating the dir if needed.
/// Overwrites existing files atomically (write-to-.tmp + rename).
/// Stale files for phys that no longer have config get removed so a
/// subsequent hostapd start for that phy fails fast rather than running
/// with out-of-date credentials.
pub fn write_all(cfg: &Config) -> io::Result<()> {
    std::fs::create_dir_all(CONF_DIR)?;
    let configs = generate_all(cfg);
    let dir = Path::new(CONF_DIR);

    // First, remove any stale hostapd-*.conf not in the new set.
    let desired: std::collections::BTreeSet<PathBuf> = configs
        .keys()
        .map(|phy| dir.join(format!("{phy}.conf")))
        .collect();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for ent in rd.flatten() {
            let p = ent.path();
            if p.extension().and_then(|s| s.to_str()) == Some("conf")
                && !desired.contains(&p)
            {
                let _ = std::fs::remove_file(&p);
                tracing::info!(path = %p.display(), "wifi: removed stale hostapd config");
            }
        }
    }

    // Then write/overwrite current ones.
    for (phy, conf) in &configs {
        let final_path = dir.join(format!("{phy}.conf"));
        let tmp_path = dir.join(format!("{phy}.conf.tmp"));
        std::fs::write(&tmp_path, conf.as_bytes())?;
        std::fs::rename(&tmp_path, &final_path)?;
        tracing::info!(phy, path = %final_path.display(), bytes = conf.len(),
            "wifi: wrote hostapd config");
    }
    Ok(())
}

/// Build one hostapd.conf from a radio + one or more SSIDs.
///
/// The first `Wifi` entry becomes the primary BSS and lives in the top-
/// level section (binding to `phy<N>-ap0`). Every subsequent entry
/// becomes a `bss=phy<N>-apM` sub-section — hostapd auto-creates those
/// child netdevs via nl80211. Used for "one radio, multiple SSIDs" (main
/// + guest, or iot + per-vlan segmentation).
///
/// Layering per BSS: every typed field in `Wifi` is applied if `Some`,
/// otherwise falls through to a sensible security-derived default. Phy-
/// level fields from `Radio` are written once in the top section (they
/// describe the physical radio, not the BSS). `extra` lines on both
/// structs are appended verbatim so operators can pass hostapd options
/// we haven't surfaced as typed fields.
fn build_hostapd_conf(radio: &Radio, wifis: &[&Wifi]) -> String {
    assert!(!wifis.is_empty(), "build_hostapd_conf called with no wifi entries");

    let mut s = String::with_capacity(2048);
    writeln!(s, "# Auto-generated by oxwrtctl wifi::generate_all; do not edit.").unwrap();
    writeln!(s, "# Source: [[radios]] phy={} + {} [[wifi]] entries",
        radio.phy, wifis.len()).unwrap();
    writeln!(s).unwrap();

    // ── phy-level header + primary BSS ──
    // hostapd's config format requires the phy-level options (hw_mode,
    // channel, HT/VHT/HE caps, country_code) to appear BEFORE any
    // `bss=` sub-section. So we emit the full primary BSS here, then
    // append bss= blocks.
    let primary = wifis[0];
    writeln!(s, "interface={}-ap0", radio.phy).unwrap();
    write_bss_bridge(&mut s, primary);
    writeln!(s, "driver=nl80211").unwrap();
    writeln!(s, "ctrl_interface=/tmp/hostapd").unwrap();
    writeln!(s, "ctrl_interface_group=0").unwrap();
    writeln!(s).unwrap();

    write_bss_ssid_block(&mut s, primary);
    // Phy-level settings: country, regdom, hw_mode + channel + HT/VHT/HE.
    write_phy_block(&mut s, radio);
    writeln!(s).unwrap();

    write_bss_security_block(&mut s, primary);

    // ── additional BSSes on the same radio ──
    for (idx, extra_bss) in wifis.iter().enumerate().skip(1) {
        writeln!(s).unwrap();
        writeln!(s, "# ── Additional BSS: ssid={} ──", extra_bss.ssid).unwrap();
        writeln!(s, "bss={}-ap{idx}", radio.phy).unwrap();
        write_bss_bridge(&mut s, extra_bss);
        write_bss_ssid_block(&mut s, extra_bss);
        write_bss_security_block(&mut s, extra_bss);
    }

    s
}

fn write_bss_bridge(s: &mut String, w: &Wifi) {
    let bridge = w.bridge.as_deref().unwrap_or("br-lan");
    writeln!(s, "bridge={bridge}").unwrap();
}

fn write_bss_ssid_block(s: &mut String, w: &Wifi) {
    writeln!(s, "ssid={}", w.ssid).unwrap();
    writeln!(s, "ignore_broadcast_ssid={}", if w.hidden { 1 } else { 0 }).unwrap();
}

fn write_phy_block(s: &mut String, radio: &Radio) {
    let cc = radio.country_code.as_deref().unwrap_or("US");
    writeln!(s, "country_code={cc}").unwrap();
    writeln!(s, "ieee80211d={}", bool_to_01(radio.ieee80211d.unwrap_or(true))).unwrap();
    writeln!(s, "ieee80211h={}", bool_to_01(radio.ieee80211h.unwrap_or(true))).unwrap();

    let is_5g = radio.band.as_str() != "2g";
    if is_5g {
        writeln!(s, "hw_mode=a").unwrap();
    } else {
        writeln!(s, "hw_mode=g").unwrap();
    }
    writeln!(s, "channel={}", radio.channel).unwrap();

    let n_default = true;
    let ac_default = is_5g;
    let ax_default = true;
    writeln!(s, "ieee80211n={}", bool_to_01(radio.ieee80211n.unwrap_or(n_default))).unwrap();
    if radio.ieee80211ac.unwrap_or(ac_default) {
        writeln!(s, "ieee80211ac=1").unwrap();
    }
    if radio.ieee80211ax.unwrap_or(ax_default) {
        writeln!(s, "ieee80211ax=1").unwrap();
    }

    let ht_capab_default_2g =
        "[HT40+][SHORT-GI-20][SHORT-GI-40][TX-STBC][RX-STBC1][MAX-AMSDU-7935]";
    let ht_capab_default_5g =
        "[HT40+][SHORT-GI-40][TX-STBC][RX-STBC1][MAX-AMSDU-7935][DSSS_CCK-40]";
    let ht_capab = radio
        .ht_capab
        .as_deref()
        .unwrap_or(if is_5g { ht_capab_default_5g } else { ht_capab_default_2g });
    writeln!(s, "ht_capab={ht_capab}").unwrap();

    if is_5g {
        let seg0_default = vht_seg0(radio.channel);
        let vht_chwidth = radio.vht_oper_chwidth.unwrap_or(1);
        let vht_seg0 = radio.vht_oper_centr_freq_seg0_idx.unwrap_or(seg0_default);
        writeln!(s, "vht_oper_chwidth={vht_chwidth}").unwrap();
        writeln!(s, "vht_oper_centr_freq_seg0_idx={vht_seg0}").unwrap();
        let vht_capab_default =
            "[SHORT-GI-80][TX-STBC-2BY1][RX-STBC-1][RX-ANTENNA-PATTERN][TX-ANTENNA-PATTERN]";
        let vht_capab = radio.vht_capab.as_deref().unwrap_or(vht_capab_default);
        writeln!(s, "vht_capab={vht_capab}").unwrap();
        let he_chwidth = radio.he_oper_chwidth.unwrap_or(vht_chwidth);
        let he_seg0 = radio.he_oper_centr_freq_seg0_idx.unwrap_or(vht_seg0);
        writeln!(s, "he_oper_chwidth={he_chwidth}").unwrap();
        writeln!(s, "he_oper_centr_freq_seg0_idx={he_seg0}").unwrap();
    }
    if let Some(b) = radio.beacon_int {
        writeln!(s, "beacon_int={b}").unwrap();
    }
    if let Some(d) = radio.dtim_period {
        writeln!(s, "dtim_period={d}").unwrap();
    }
    for line in &radio.extra {
        writeln!(s, "{line}").unwrap();
    }
}

fn write_bss_security_block(s: &mut String, w: &Wifi) {
    let (default_wpa, default_key_mgmt, default_mfp, default_sae_require): (
        u8, &str, u8, bool,
    ) = match w.security {
        WifiSecurity::Open => (0, "", 0, false),
        WifiSecurity::Wpa2 => (2, "WPA-PSK", 1, false),
        WifiSecurity::Wpa3Sae => (2, "SAE", 2, true),
        WifiSecurity::Wpa2Wpa3 => (2, "WPA-PSK SAE", 1, false),
    };
    if default_wpa != 0 {
        writeln!(s, "wpa={default_wpa}").unwrap();
        writeln!(s, "wpa_passphrase={}", w.passphrase).unwrap();
        let key_mgmt = w.wpa_key_mgmt.as_deref().unwrap_or(default_key_mgmt);
        writeln!(s, "wpa_key_mgmt={key_mgmt}").unwrap();
        let pairwise = w.rsn_pairwise.as_deref().unwrap_or("CCMP");
        writeln!(s, "rsn_pairwise={pairwise}").unwrap();
        let mfp = w.ieee80211w.unwrap_or(default_mfp);
        writeln!(s, "ieee80211w={mfp}").unwrap();
        if w.sae_require_mfp.unwrap_or(default_sae_require) {
            writeln!(s, "sae_require_mfp=1").unwrap();
        }
    } else {
        writeln!(s, "wpa=0").unwrap();
    }
    if let Some(pwe) = w.sae_pwe {
        writeln!(s, "sae_pwe={pwe}").unwrap();
    }
    writeln!(s, "auth_algs={}", w.auth_algs.unwrap_or(1)).unwrap();
    writeln!(s, "macaddr_acl={}", w.macaddr_acl.unwrap_or(0)).unwrap();
    writeln!(s, "ap_isolate={}", bool_to_01(w.ap_isolate.unwrap_or(false))).unwrap();
    if let Some(max) = w.max_num_sta {
        writeln!(s, "max_num_sta={max}").unwrap();
    }
    if let Some(wmm) = w.wmm_enabled {
        writeln!(s, "wmm_enabled={}", bool_to_01(wmm)).unwrap();
    }
    if w.ft_over_ds == Some(true) {
        writeln!(s, "ft_over_ds=1").unwrap();
    }
    for line in &w.extra {
        writeln!(s, "{line}").unwrap();
    }
}

fn bool_to_01(b: bool) -> u8 {
    if b { 1 } else { 0 }
}

/// Map a primary 5 GHz channel (20 MHz anchor) to its VHT80
/// center_freq_seg0 channel index (the center of the 4-channel 80 MHz
/// group). For channels that aren't the lowest of an 80 MHz group we
/// still return a sensible value (the canonical anchor). If the
/// operator picked a channel we don't recognise, fall back to the
/// channel itself so hostapd gets *something* and logs its own error
/// rather than us silently defaulting.
fn vht_seg0(channel: u16) -> u16 {
    match channel {
        36 | 40 | 44 | 48 => 42,
        52 | 56 | 60 | 64 => 58,
        100 | 104 | 108 | 112 => 106,
        116 | 120 | 124 | 128 => 122,
        132 | 136 | 140 | 144 => 138,
        149 | 153 | 157 | 161 => 155,
        165 | 169 | 173 | 177 => 171,
        _ => channel,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxwrt_api::config::{Radio, Wifi, WifiSecurity};

    fn mk_radio(phy: &str, band: &str, channel: u16, disabled: bool) -> Radio {
        Radio {
            phy: phy.into(),
            band: band.into(),
            channel,
            disabled,
            country_code: None,
            ht_capab: None,
            vht_capab: None,
            vht_oper_centr_freq_seg0_idx: None,
            vht_oper_chwidth: None,
            he_oper_centr_freq_seg0_idx: None,
            he_oper_chwidth: None,
            ieee80211n: None,
            ieee80211ac: None,
            ieee80211ax: None,
            ieee80211d: None,
            ieee80211h: None,
            beacon_int: None,
            dtim_period: None,
            extra: Vec::new(),
        }
    }
    fn mk_wifi(radio: &str, ssid: &str, sec: WifiSecurity) -> Wifi {
        Wifi {
            radio: radio.into(),
            ssid: ssid.into(),
            security: sec,
            passphrase: "pass1234".into(),
            network: "lan".into(),
            hidden: false,
            bridge: None,
            wpa_key_mgmt: None,
            rsn_pairwise: None,
            ieee80211w: None,
            sae_require_mfp: None,
            macaddr_acl: None,
            auth_algs: None,
            ap_isolate: None,
            max_num_sta: None,
            wmm_enabled: None,
            ft_over_ds: None,
            sae_pwe: None,
            extra: Vec::new(),
        }
    }

    #[test]
    fn conf_2g_wpa2_has_hw_mode_g() {
        let r = mk_radio("phy0", "2g", 6, false);
        let w = mk_wifi("phy0", "test2g", WifiSecurity::Wpa2);
        let c = build_hostapd_conf(&r, &[&w]);
        assert!(c.contains("hw_mode=g"));
        assert!(c.contains("channel=6"));
        assert!(c.contains("ssid=test2g"));
        assert!(c.contains("wpa_key_mgmt=WPA-PSK"));
        assert!(c.contains("interface=phy0-ap0"));
        assert!(c.contains("bridge=br-lan"));
    }

    #[test]
    fn conf_5g_wpa3_has_sae_and_vht() {
        let r = mk_radio("phy1", "5g", 36, false);
        let w = mk_wifi("phy1", "test5g", WifiSecurity::Wpa3Sae);
        let c = build_hostapd_conf(&r, &[&w]);
        assert!(c.contains("hw_mode=a"));
        assert!(c.contains("channel=36"));
        assert!(c.contains("wpa_key_mgmt=SAE"));
        assert!(c.contains("ieee80211w=2"));
        assert!(c.contains("vht_oper_centr_freq_seg0_idx=42"));
    }

    #[test]
    fn conf_open_has_no_passphrase() {
        let r = mk_radio("phy0", "2g", 6, false);
        let w = mk_wifi("phy0", "open", WifiSecurity::Open);
        let c = build_hostapd_conf(&r, &[&w]);
        assert!(c.contains("wpa=0"));
        assert!(!c.contains("wpa_passphrase"));
    }

    #[test]
    fn radio_typed_overrides_win_over_defaults() {
        let mut r = mk_radio("phy1", "5g", 36, false);
        r.country_code = Some("JP".into());
        r.ht_capab = Some("[HT40+][CUSTOM]".into());
        r.vht_capab = Some("[CUSTOM-VHT]".into());
        r.vht_oper_centr_freq_seg0_idx = Some(999);
        r.vht_oper_chwidth = Some(2);
        r.ieee80211ax = Some(false);
        r.ieee80211d = Some(false);
        r.beacon_int = Some(250);
        r.dtim_period = Some(3);
        let w = mk_wifi("phy1", "s", WifiSecurity::Wpa2);
        let c = build_hostapd_conf(&r, &[&w]);
        assert!(c.contains("country_code=JP"));
        assert!(c.contains("ht_capab=[HT40+][CUSTOM]"));
        assert!(c.contains("vht_capab=[CUSTOM-VHT]"));
        assert!(c.contains("vht_oper_chwidth=2"));
        assert!(c.contains("vht_oper_centr_freq_seg0_idx=999"));
        assert!(!c.contains("ieee80211ax=1"));
        assert!(c.contains("ieee80211d=0"));
        assert!(c.contains("beacon_int=250"));
        assert!(c.contains("dtim_period=3"));
    }

    #[test]
    fn wifi_typed_overrides_win_over_security_derived() {
        let r = mk_radio("phy1", "5g", 36, false);
        let mut w = mk_wifi("phy1", "s", WifiSecurity::Wpa3Sae);
        w.wpa_key_mgmt = Some("SAE FT-SAE".into());
        w.rsn_pairwise = Some("CCMP GCMP-256".into());
        w.ieee80211w = Some(1);
        w.sae_require_mfp = Some(false);
        w.macaddr_acl = Some(1);
        w.ap_isolate = Some(true);
        w.max_num_sta = Some(64);
        w.wmm_enabled = Some(false);
        w.sae_pwe = Some(2);
        w.bridge = Some("br-guest".into());
        let c = build_hostapd_conf(&r, &[&w]);
        assert!(c.contains("bridge=br-guest"));
        assert!(c.contains("wpa_key_mgmt=SAE FT-SAE"));
        assert!(c.contains("rsn_pairwise=CCMP GCMP-256"));
        assert!(c.contains("ieee80211w=1"));
        assert!(!c.contains("sae_require_mfp=1"));
        assert!(c.contains("macaddr_acl=1"));
        assert!(c.contains("ap_isolate=1"));
        assert!(c.contains("max_num_sta=64"));
        assert!(c.contains("wmm_enabled=0"));
        assert!(c.contains("sae_pwe=2"));
    }

    #[test]
    fn extra_raw_lines_appended() {
        let mut r = mk_radio("phy0", "2g", 6, false);
        r.extra.push("obss_interval=300".into());
        r.extra.push("# phy comment passed through".into());
        let mut w = mk_wifi("phy0", "s", WifiSecurity::Wpa2);
        w.extra.push("rrm_neighbor_report=1".into());
        w.extra.push("rrm_beacon_report=1".into());
        let c = build_hostapd_conf(&r, &[&w]);
        assert!(c.contains("obss_interval=300"));
        assert!(c.contains("# phy comment passed through"));
        assert!(c.contains("rrm_neighbor_report=1"));
        assert!(c.contains("rrm_beacon_report=1"));
    }

    #[test]
    fn multi_bss_emits_bss_stanzas_and_keeps_phy_header_once() {
        let r = mk_radio("phy1", "5g", 36, false);
        let main = mk_wifi("phy1", "Main", WifiSecurity::Wpa2);
        let mut guest = mk_wifi("phy1", "Guest", WifiSecurity::Wpa2);
        guest.passphrase = "guest-pass".into();
        guest.bridge = Some("br-guest".into());
        guest.ap_isolate = Some(true);
        let mut iot = mk_wifi("phy1", "IoT", WifiSecurity::Wpa2);
        iot.passphrase = "iot-pass".into();
        iot.bridge = Some("br-iot".into());
        iot.extra.push("multi_ap_profile=1".into());

        let c = build_hostapd_conf(&r, &[&main, &guest, &iot]);

        // Primary BSS header: interface= must be exactly one, phy-level
        // options (hw_mode, channel, vht_oper_*) appear in the top
        // section only.
        assert_eq!(c.matches("interface=phy1-ap0").count(), 1);
        assert_eq!(c.matches("hw_mode=a").count(), 1);
        assert_eq!(c.matches("channel=36").count(), 1);
        assert_eq!(c.matches("vht_oper_centr_freq_seg0_idx=42").count(), 1);

        // bss= stanzas for guest + iot, numbered sequentially.
        assert!(c.contains("bss=phy1-ap1"));
        assert!(c.contains("bss=phy1-ap2"));

        // Each BSS carries its own ssid + bridge + security.
        assert!(c.contains("ssid=Main"));
        assert!(c.contains("ssid=Guest"));
        assert!(c.contains("ssid=IoT"));
        assert!(c.contains("bridge=br-lan"));
        assert!(c.contains("bridge=br-guest"));
        assert!(c.contains("bridge=br-iot"));
        assert!(c.contains("guest-pass"));
        assert!(c.contains("iot-pass"));
        assert!(c.contains("multi_ap_profile=1"));
        // ap_isolate on guest only.
        let ap_isolate_1 = c.matches("ap_isolate=1").count();
        assert_eq!(ap_isolate_1, 1, "ap_isolate should be on one BSS only");
    }

    #[test]
    fn vht_seg0_known_anchors() {
        assert_eq!(vht_seg0(36), 42);
        assert_eq!(vht_seg0(44), 42);
        assert_eq!(vht_seg0(149), 155);
        assert_eq!(vht_seg0(165), 171);
        assert_eq!(vht_seg0(999), 999);
    }
}
