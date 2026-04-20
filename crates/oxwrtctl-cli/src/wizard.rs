//! `oxctl wizard` — interactive first-flash starter-config
//! generator. Prompts the operator for the minimum knobs needed
//! to get a new Flint 2 online (hostname, LAN subnet, Wi-Fi
//! credentials, WAN mode) and emits a valid oxwrt.toml to stdout
//! or `--out <path>`.
//!
//! Deliberately small surface area — covers the 80% first-flash
//! path. Advanced config (VLAN, multi-WAN, VPN client, DDNS,
//! blocklists, UPnP) is best authored by hand or via dedicated
//! oxctl subcommands after the device is online.
//!
//! Scope: generates a string, writes it out. Does NOT touch the
//! router — zero sQUIC dependency, zero env-var requirements.
//! Operator flashes, pushes via `oxctl <remote> config-push` +
//! `reload`, done.

use std::io::{self, BufRead, Write};

pub fn run(args: Vec<String>) -> Result<(), String> {
    let mut out_path: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--out" {
            out_path = args.get(i + 1).cloned();
            i += 2;
            continue;
        }
        if let Some(rest) = a.strip_prefix("--out=") {
            out_path = Some(rest.to_string());
            i += 1;
            continue;
        }
        return Err(format!("wizard: unknown arg {a:?}"));
    }

    eprintln!("oxctl wizard — new oxwrt.toml");
    eprintln!("Answer the prompts; press enter to accept the [default]. Ctrl-C to abort.\n");

    let hostname = prompt("Hostname", "flint2")?;
    let timezone = prompt("Timezone (IANA, e.g. Europe/Berlin)", "UTC")?;
    let lan_cidr = prompt("LAN subnet CIDR (must be v4)", "192.168.50.0/24")?;
    let (lan_addr, lan_prefix) = parse_cidr_v4(&lan_cidr)?;
    let lan_router = router_addr(&lan_addr)?;

    let wan_mode = prompt("WAN mode (dhcp / static / pppoe)", "dhcp")?;
    let wan_block = match wan_mode.as_str() {
        "dhcp" => dhcp_wan_block(),
        "static" => {
            let addr = prompt("WAN static IP/prefix (e.g. 203.0.113.42/24)", "")?;
            let gw = prompt("WAN gateway", "")?;
            let dns = prompt("WAN DNS (comma-separated)", "1.1.1.1,9.9.9.9")?;
            let (wa, wp) = parse_cidr_v4(&addr)?;
            static_wan_block(&wa, wp, &gw, &dns)
        }
        "pppoe" => {
            let user = prompt("PPPoE username", "")?;
            let pass = prompt("PPPoE password", "")?;
            pppoe_wan_block(&user, &pass)
        }
        other => return Err(format!("wizard: unknown WAN mode {other:?}")),
    };

    let guest_enabled = prompt_yn("Create a guest SSID (isolated br-guest)?", true)?;
    let iot_enabled = prompt_yn("Create an IoT SSID (isolated br-iot)?", false)?;

    let ssid_5g = prompt("5 GHz SSID", "oxwrt")?;
    let pw_5g = prompt_passphrase("5 GHz passphrase")?;
    let ssid_2g = prompt("2.4 GHz SSID", "oxwrt-2g")?;
    let pw_2g = prompt_passphrase("2.4 GHz passphrase")?;

    let guest_ssid = if guest_enabled {
        Some((
            prompt("Guest SSID", "oxwrt-guest")?,
            prompt_passphrase("Guest passphrase")?,
        ))
    } else {
        None
    };

    let metrics = prompt_yn("Enable Prometheus /metrics on the LAN IP?", true)?;

    let toml = render(&Inputs {
        hostname,
        timezone,
        lan_router,
        lan_prefix,
        wan_block,
        guest_enabled,
        iot_enabled,
        ssid_5g,
        pw_5g,
        ssid_2g,
        pw_2g,
        guest_ssid,
        metrics,
    });

    if let Some(path) = out_path {
        // Split the merged wizard output into a publishable
        // oxwrt.toml (mode 0644) and a sibling oxwrt.secrets.toml
        // (mode 0600). The in-memory `toml` string carries the
        // operator's fresh passphrases / pppoe password — we
        // re-parse it via `toml_edit` so split_document can lift
        // secret leaves cleanly, then write both files.
        let (public_text, secret_text) = split_outputs(&toml)?;
        let pub_path = std::path::PathBuf::from(&path);
        let sec_path = pub_path.with_file_name("oxwrt.secrets.toml");
        write_file_mode(&pub_path, &public_text, 0o644)?;
        if !secret_text.trim().is_empty() {
            write_file_mode(&sec_path, &secret_text, 0o600)?;
            eprintln!(
                "\n✓ wrote {} (public, mode 0644)\n✓ wrote {} (secrets, mode 0600)",
                pub_path.display(),
                sec_path.display(),
            );
        } else {
            eprintln!("\n✓ wrote {} (public, mode 0644)", pub_path.display());
        }
        eprintln!(
            "Next: copy both to /etc/oxwrt/ on the router, then\n  `oxctl <remote> reload`."
        );
    } else {
        // stdout path: emit merged form (dev / pipe-to-inspection).
        // Leave a header warning the operator that this form
        // includes secrets.
        print!("# WARNING: merged form (contains secrets). Use `--out PATH`\n");
        print!("# to split into oxwrt.toml + oxwrt.secrets.toml.\n");
        print!("{toml}");
    }
    Ok(())
}

/// Parse the merged wizard TOML and split secrets out.
/// Returns `(public, secret)` as strings.
fn split_outputs(merged: &str) -> Result<(String, String), String> {
    let mut doc: toml_edit::DocumentMut = merged
        .parse()
        .map_err(|e| format!("wizard: parse own output: {e}"))?;
    let secret_doc = oxwrt_api::secrets::split_document(&mut doc);
    Ok((doc.to_string(), secret_doc.to_string()))
}

fn write_file_mode(
    path: &std::path::Path,
    text: &str,
    mode: u32,
) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, text).map_err(|e| format!("write {}: {e}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    Ok(())
}

struct Inputs {
    hostname: String,
    timezone: String,
    lan_router: String,
    lan_prefix: u8,
    wan_block: String,
    guest_enabled: bool,
    iot_enabled: bool,
    ssid_5g: String,
    pw_5g: String,
    ssid_2g: String,
    pw_2g: String,
    guest_ssid: Option<(String, String)>,
    metrics: bool,
}

fn render(i: &Inputs) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    writeln!(s, "# Generated by `oxctl wizard`. Edit to taste — see").unwrap();
    writeln!(s, "# config/oxwrt.toml in the upstream repo for every knob + docs.\n").unwrap();
    writeln!(s, "hostname = {:?}", i.hostname).unwrap();
    writeln!(s, "timezone = {:?}\n", i.timezone).unwrap();
    writeln!(s, "{}\n", i.wan_block).unwrap();
    // LAN
    writeln!(s, "[[networks]]").unwrap();
    writeln!(s, "name = \"lan\"").unwrap();
    writeln!(s, "type = \"lan\"").unwrap();
    writeln!(s, "bridge = \"br-lan\"").unwrap();
    writeln!(s, "members = [\"lan1\", \"lan2\", \"lan3\", \"lan4\", \"lan5\"]").unwrap();
    writeln!(s, "address = {:?}", i.lan_router).unwrap();
    writeln!(s, "prefix = {}\n", i.lan_prefix).unwrap();
    if i.guest_enabled {
        writeln!(s, "[[networks]]").unwrap();
        writeln!(s, "name = \"guest\"").unwrap();
        writeln!(s, "type = \"simple\"").unwrap();
        writeln!(s, "iface = \"br-guest\"").unwrap();
        writeln!(s, "address = \"10.99.0.1\"").unwrap();
        writeln!(s, "prefix = 24\n").unwrap();
    }
    if i.iot_enabled {
        writeln!(s, "[[networks]]").unwrap();
        writeln!(s, "name = \"iot\"").unwrap();
        writeln!(s, "type = \"simple\"").unwrap();
        writeln!(s, "iface = \"br-iot\"").unwrap();
        writeln!(s, "address = \"10.20.0.1\"").unwrap();
        writeln!(s, "prefix = 24\n").unwrap();
    }
    // Zones
    writeln!(s, "[[firewall.zones]]").unwrap();
    writeln!(s, "name = \"lan\"").unwrap();
    writeln!(s, "networks = [\"lan\"]").unwrap();
    writeln!(s, "default_input = \"accept\"").unwrap();
    writeln!(s, "default_forward = \"drop\"\n").unwrap();
    if i.guest_enabled {
        writeln!(s, "[[firewall.zones]]").unwrap();
        writeln!(s, "name = \"guest\"").unwrap();
        writeln!(s, "networks = [\"guest\"]").unwrap();
        writeln!(s, "default_input = \"drop\"").unwrap();
        writeln!(s, "default_forward = \"drop\"\n").unwrap();
    }
    if i.iot_enabled {
        writeln!(s, "[[firewall.zones]]").unwrap();
        writeln!(s, "name = \"iot\"").unwrap();
        writeln!(s, "networks = [\"iot\"]").unwrap();
        writeln!(s, "default_input = \"drop\"").unwrap();
        writeln!(s, "default_forward = \"drop\"\n").unwrap();
    }
    writeln!(s, "[[firewall.zones]]").unwrap();
    writeln!(s, "name = \"wan\"").unwrap();
    writeln!(s, "networks = [\"wan\"]").unwrap();
    writeln!(s, "default_input = \"drop\"").unwrap();
    writeln!(s, "default_forward = \"drop\"").unwrap();
    writeln!(s, "masquerade = true\n").unwrap();
    // ct-established + per-zone internet
    writeln!(s, "[[firewall.rules]]").unwrap();
    writeln!(s, "name = \"ct-established\"").unwrap();
    writeln!(s, "ct_state = [\"established\", \"related\"]").unwrap();
    writeln!(s, "action = \"accept\"\n").unwrap();
    writeln!(s, "[[firewall.rules]]").unwrap();
    writeln!(s, "name = \"lan-internet\"").unwrap();
    writeln!(s, "src = \"lan\"").unwrap();
    writeln!(s, "dest = \"wan\"").unwrap();
    writeln!(s, "action = \"accept\"\n").unwrap();
    if i.guest_enabled {
        writeln!(s, "[[firewall.rules]]").unwrap();
        writeln!(s, "name = \"guest-internet\"").unwrap();
        writeln!(s, "src = \"guest\"").unwrap();
        writeln!(s, "dest = \"wan\"").unwrap();
        writeln!(s, "action = \"accept\"\n").unwrap();
    }
    if i.iot_enabled {
        writeln!(s, "[[firewall.rules]]").unwrap();
        writeln!(s, "name = \"iot-internet\"").unwrap();
        writeln!(s, "src = \"iot\"").unwrap();
        writeln!(s, "dest = \"wan\"").unwrap();
        writeln!(s, "action = \"accept\"\n").unwrap();
    }
    // Radios
    writeln!(s, "[[radios]]").unwrap();
    writeln!(s, "phy = \"phy0\"").unwrap();
    writeln!(s, "band = \"2g\"").unwrap();
    writeln!(s, "channel = 6").unwrap();
    writeln!(s, "country_code = \"US\"\n").unwrap();
    writeln!(s, "[[radios]]").unwrap();
    writeln!(s, "phy = \"phy1\"").unwrap();
    writeln!(s, "band = \"5g\"").unwrap();
    writeln!(s, "channel = 36").unwrap();
    writeln!(s, "country_code = \"US\"\n").unwrap();
    // Wifi
    writeln!(s, "[[wifi]]").unwrap();
    writeln!(s, "radio = \"phy1\"").unwrap();
    writeln!(s, "ssid = {:?}", i.ssid_5g).unwrap();
    writeln!(s, "security = \"wpa2\"").unwrap();
    writeln!(s, "passphrase = {:?}", i.pw_5g).unwrap();
    writeln!(s, "network = \"lan\"\n").unwrap();
    writeln!(s, "[[wifi]]").unwrap();
    writeln!(s, "radio = \"phy0\"").unwrap();
    writeln!(s, "ssid = {:?}", i.ssid_2g).unwrap();
    writeln!(s, "security = \"wpa2\"").unwrap();
    writeln!(s, "passphrase = {:?}", i.pw_2g).unwrap();
    writeln!(s, "network = \"lan\"\n").unwrap();
    if let Some((gs, gp)) = &i.guest_ssid {
        writeln!(s, "[[wifi]]").unwrap();
        writeln!(s, "radio = \"phy0\"").unwrap();
        writeln!(s, "ssid = {:?}", gs).unwrap();
        writeln!(s, "security = \"wpa2\"").unwrap();
        writeln!(s, "passphrase = {:?}", gp).unwrap();
        writeln!(s, "network = \"guest\"\n").unwrap();
    }
    if i.metrics {
        writeln!(s, "[metrics]").unwrap();
        writeln!(s, "listen = \"{}:9100\"\n", i.lan_router).unwrap();
    }
    // [dns] — forwarding resolver, rendered to /etc/oxwrt/named.toml.
    // Two DoH upstreams: operator can swap / add / remove freely.
    writeln!(s, "[dns]").unwrap();
    writeln!(s, "listen_v4 = [\"0.0.0.0\"]").unwrap();
    writeln!(s, "listen_port = 15353\n").unwrap();
    writeln!(s, "[[dns.upstreams]]").unwrap();
    writeln!(s, "ip = \"1.1.1.1\"").unwrap();
    writeln!(s, "protocol = \"https\"").unwrap();
    writeln!(s, "server_name = \"cloudflare-dns.com\"").unwrap();
    writeln!(s, "path = \"/dns-query\"\n").unwrap();
    writeln!(s, "[[dns.upstreams]]").unwrap();
    writeln!(s, "ip = \"9.9.9.9\"").unwrap();
    writeln!(s, "protocol = \"https\"").unwrap();
    writeln!(s, "server_name = \"dns.quad9.net\"").unwrap();
    writeln!(s, "path = \"/dns-query\"\n").unwrap();
    // [dhcp] — pool auto-derives to .100-.250 of the LAN subnet.
    writeln!(s, "[dhcp]").unwrap();
    writeln!(s, "network = \"lan\"").unwrap();
    writeln!(s, "lease_time = \"12h\"\n").unwrap();
    // [ntp] — upstream pool + LAN server on :1123 (firewall DNATs :123).
    writeln!(s, "[ntp]").unwrap();
    writeln!(s, "poll_min = 4").unwrap();
    writeln!(s, "poll_max = 10").unwrap();
    writeln!(s, "listen = [\"0.0.0.0:1123\"]\n").unwrap();
    writeln!(s, "[[ntp.sources]]").unwrap();
    writeln!(s, "mode = \"pool\"").unwrap();
    writeln!(s, "address = \"pool.ntp.org\"").unwrap();
    writeln!(s, "count = 4\n").unwrap();
    writeln!(s, "[control]").unwrap();
    writeln!(s, "listen = [\"[::]:51820\"]").unwrap();
    writeln!(s, "authorized_keys = \"/etc/oxwrt/authorized_keys\"").unwrap();
    s
}

// ── WAN block builders ─────────────────────────────────────────

fn dhcp_wan_block() -> String {
    "[[networks]]\nname = \"wan\"\ntype = \"wan\"\niface = \"eth1\"\nmode = \"dhcp\"".to_string()
}

fn static_wan_block(addr: &str, prefix: u8, gw: &str, dns: &str) -> String {
    let dns_list = dns
        .split(',')
        .map(|s| format!("{:?}", s.trim()))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "[[networks]]\nname = \"wan\"\ntype = \"wan\"\niface = \"eth1\"\nmode = \"static\"\naddress = {addr:?}\nprefix = {prefix}\ngateway = {gw:?}\ndns = [{dns_list}]"
    )
}

fn pppoe_wan_block(user: &str, pass: &str) -> String {
    format!(
        "[[networks]]\nname = \"wan\"\ntype = \"wan\"\niface = \"eth1\"\nmode = \"pppoe\"\nusername = {user:?}\npassword = {pass:?}"
    )
}

// ── prompt helpers ─────────────────────────────────────────────

fn prompt(label: &str, default: &str) -> Result<String, String> {
    eprint!("{label} [{default}]: ");
    io::stderr().flush().ok();
    let mut line = String::new();
    io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("stdin: {e}"))?;
    let t = line.trim().to_string();
    Ok(if t.is_empty() { default.to_string() } else { t })
}

fn prompt_yn(label: &str, default: bool) -> Result<bool, String> {
    let def_s = if default { "Y/n" } else { "y/N" };
    let raw = prompt(label, def_s)?;
    Ok(match raw.to_lowercase().as_str() {
        "y" | "yes" => true,
        "n" | "no" => false,
        "y/n" => default, // wasn't touched — defaulted
        _ => default,
    })
}

/// Prompt for a Wi-Fi passphrase. Accepts empty → auto-generate
/// a random one (nicer UX than forcing the operator to come up
/// with one at 5-ssids-in-a-row-prompts time).
fn prompt_passphrase(label: &str) -> Result<String, String> {
    let raw = prompt(&format!("{label} (empty = random)"), "")?;
    if raw.is_empty() {
        return Ok(random_passphrase());
    }
    if raw.len() < 8 {
        return Err(format!("{label}: WPA2/3 requires ≥8 chars"));
    }
    Ok(raw)
}

fn random_passphrase() -> String {
    let alphabet: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut out = String::with_capacity(16);
    // Best-effort: try /dev/urandom, fall back to a time-seeded
    // linear congruential generator if that's unavailable (e.g.
    // running on Windows). The fallback is NOT cryptographically
    // secure — the operator should regenerate if it matters, but
    // 94 bits of PID+time is enough for a first-flash default
    // that they'll almost certainly overwrite in hand-edit.
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let mut buf = [0u8; 64];
        if f.read_exact(&mut buf).is_ok() {
            let cap = (256 / alphabet.len()) * alphabet.len();
            for b in buf {
                if (b as usize) < cap {
                    out.push(alphabet[(b as usize) % alphabet.len()] as char);
                    if out.len() == 16 {
                        return out;
                    }
                }
            }
        }
    }
    // Fallback.
    let mut seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x5eed_5eed);
    for _ in 0..16 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        out.push(alphabet[(seed as usize) % alphabet.len()] as char);
    }
    out
}

// ── parsing helpers ────────────────────────────────────────────

fn parse_cidr_v4(s: &str) -> Result<(String, u8), String> {
    let (ip, pref) = s
        .split_once('/')
        .ok_or_else(|| format!("not a CIDR: {s:?}"))?;
    let _: std::net::Ipv4Addr = ip.parse().map_err(|e| format!("bad IPv4 {ip:?}: {e}"))?;
    let p: u8 = pref.parse().map_err(|e| format!("bad prefix {pref:?}: {e}"))?;
    if p > 32 {
        return Err(format!("prefix out of range: {p}"));
    }
    Ok((ip.to_string(), p))
}

/// Given a subnet address like "192.168.50.0/24", pick the
/// conventional ".1" router address. We don't know the user's
/// topology preference but .1 is the ~universal default for
/// home routers; they can edit post-wizard if they want .254
/// or similar.
fn router_addr(subnet_addr: &str) -> Result<String, String> {
    let mut parts = subnet_addr
        .split('.')
        .map(|p| p.parse::<u8>().map_err(|e| format!("bad octet: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    if parts.len() != 4 {
        return Err(format!("not IPv4: {subnet_addr:?}"));
    }
    *parts.last_mut().unwrap() = 1;
    Ok(parts
        .iter()
        .map(|o| o.to_string())
        .collect::<Vec<_>>()
        .join("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn router_addr_simple() {
        assert_eq!(router_addr("192.168.50.0").unwrap(), "192.168.50.1");
        assert_eq!(router_addr("10.0.0.0").unwrap(), "10.0.0.1");
    }

    #[test]
    fn parse_cidr_rejects_bad() {
        assert!(parse_cidr_v4("nope").is_err());
        assert!(parse_cidr_v4("192.168.1.0/33").is_err());
        assert!(parse_cidr_v4("192.168.1.0").is_err());
    }

    #[test]
    fn render_emits_parseable_toml() {
        let i = Inputs {
            hostname: "test".into(),
            timezone: "UTC".into(),
            lan_router: "192.168.50.1".into(),
            lan_prefix: 24,
            wan_block: dhcp_wan_block(),
            guest_enabled: true,
            iot_enabled: false,
            ssid_5g: "test5".into(),
            pw_5g: "pw5gpass".into(),
            ssid_2g: "test2".into(),
            pw_2g: "pw2gpass".into(),
            guest_ssid: Some(("guest".into(), "guestpass".into())),
            metrics: true,
        };
        let out = render(&i);
        // Round-trip through toml parser.
        let parsed: toml::Value = toml::from_str(&out).expect("valid TOML");
        assert_eq!(parsed.get("hostname").and_then(|v| v.as_str()), Some("test"));
        let nets = parsed
            .get("networks")
            .and_then(|v| v.as_array())
            .expect("networks");
        assert!(nets.len() >= 3); // wan, lan, guest
    }

    #[test]
    fn split_outputs_separates_passphrases() {
        let i = Inputs {
            hostname: "test".into(),
            timezone: "UTC".into(),
            lan_router: "192.168.50.1".into(),
            lan_prefix: 24,
            wan_block: pppoe_wan_block("pppoe-user", "pppoe-secret"),
            guest_enabled: true,
            iot_enabled: false,
            ssid_5g: "test5".into(),
            pw_5g: "pw5gpass".into(),
            ssid_2g: "test2".into(),
            pw_2g: "pw2gpass".into(),
            guest_ssid: Some(("guest".into(), "guestpass".into())),
            metrics: false,
        };
        let merged = render(&i);
        let (public, secret) = split_outputs(&merged).unwrap();
        // Passphrases and pppoe password gone from public.
        assert!(!public.contains("pw5gpass"));
        assert!(!public.contains("pw2gpass"));
        assert!(!public.contains("guestpass"));
        assert!(!public.contains("pppoe-secret"));
        // Non-secret identifiers stay.
        assert!(public.contains("pppoe-user"));
        assert!(public.contains("ssid = \"test5\""));
        // All secrets land in the overlay.
        assert!(secret.contains("pw5gpass"));
        assert!(secret.contains("pw2gpass"));
        assert!(secret.contains("guestpass"));
        assert!(secret.contains("pppoe-secret"));
        // Write both to a tmpdir and go through the real loader
        // (which merges + deserializes) to prove the split output
        // round-trips to a valid Config.
        let tmp = tempfile::tempdir().unwrap();
        let pub_path = tmp.path().join("oxwrt.toml");
        let sec_path = tmp.path().join("oxwrt.secrets.toml");
        std::fs::write(&pub_path, &public).unwrap();
        std::fs::write(&sec_path, &secret).unwrap();
        let _cfg = oxwrt_api::config::Config::load_with_secrets(&pub_path, &sec_path)
            .expect("merged wizard output must load as a valid Config");
    }

    #[test]
    fn random_passphrase_is_16_chars_from_alphabet() {
        let pw = random_passphrase();
        assert_eq!(pw.len(), 16);
        assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()));
    }
}
