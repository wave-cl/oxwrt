use std::net::SocketAddr;

use oxwrt_api::rpc::{Request, Response};
use oxwrt_proto::{FrameError, format_response, parse_request, read_frame, write_frame};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("usage: oxctl [--client] <addr> <cmd> [args...]")]
    Usage,
    #[error("invalid remote address: {0}")]
    Address(String),
    #[error("missing SQUIC_SERVER_KEY environment variable (32-byte hex)")]
    MissingServerKey,
    #[error("invalid server key: {0}")]
    InvalidServerKey(String),
    #[error("squic: {0}")]
    Squic(#[from] squic::Error),
    #[error("frame: {0}")]
    Frame(#[from] FrameError),
    #[error("rpc: {0}")]
    Rpc(String),
}

pub async fn run(args: Vec<String>) -> Result<(), Error> {
    let mut it = args.into_iter();
    let remote = it.next().ok_or(Error::Usage)?;
    let cmd = it.next().ok_or(Error::Usage)?;
    let rest_raw: Vec<String> = it.collect();

    // Intercept client-only flags before parse_request sees them.
    //   --qr on `wg-enroll`: after getting the wg-quick config
    //   back from the server, render it as an ASCII QR and print
    //   it for the user to scan with a phone camera. The flag
    //   isn't forwarded on the wire (server doesn't need to know),
    //   so we strip it here.
    let mut qr_mode = false;
    let rest: Vec<String> = rest_raw
        .into_iter()
        .filter(|a| {
            if a == "--qr" {
                qr_mode = true;
                false
            } else {
                true
            }
        })
        .collect();
    if qr_mode && cmd != "wg-enroll" {
        eprintln!("oxctl: --qr ignored; only meaningful with `wg-enroll`");
        qr_mode = false;
    }

    let addr: SocketAddr = remote.parse().map_err(|_| Error::Address(remote.clone()))?;

    // Intercept `vpn-profile import <name> <conf>` before parse_request
    // sees it — this is a multi-RPC orchestration (key upload + config
    // dump + config push), not a single RPC, and doesn't fit the
    // Request enum.
    if cmd == "vpn-profile" && rest.first().map(|s| s.as_str()) == Some("import") {
        let name = rest
            .get(1)
            .cloned()
            .ok_or_else(|| Error::Rpc("vpn-profile import: missing <name>".into()))?;
        let conf_path = rest
            .get(2)
            .cloned()
            .ok_or_else(|| Error::Rpc("vpn-profile import: missing <conf-path>".into()))?;
        return handle_vpn_profile_import(addr, name, conf_path).await;
    }

    // Mullvad relay list — hits api.mullvad.net, no router RPC.
    // Supports --country=XX --city=XX --limit=N --include-inactive.
    if cmd == "mullvad-relays" {
        return handle_mullvad_relays(&rest).await;
    }

    // Switch an existing vpn_client profile to a different Mullvad
    // relay by hostname. Looks up via API, updates endpoint +
    // public_key in place, config-dumps + merges + config-pushes.
    // Private key / address / DNS stay as-is because Mullvad uses
    // one account-level keypair for all relays.
    if cmd == "vpn-switch-relay" {
        let profile = rest
            .first()
            .cloned()
            .ok_or_else(|| Error::Rpc("vpn-switch-relay: missing <profile>".into()))?;
        let hostname = rest
            .get(1)
            .cloned()
            .ok_or_else(|| Error::Rpc("vpn-switch-relay: missing <relay-hostname>".into()))?;
        return handle_vpn_switch_relay(addr, profile, hostname).await;
    }

    let server_key_hex = std::env::var("SQUIC_SERVER_KEY").map_err(|_| Error::MissingServerKey)?;
    let server_key = parse_pubkey(&server_key_hex)?;

    // Stash the firmware image path before parse_request consumes the args.
    // parse_request for "update" reads the file to compute SHA-256 but
    // we need the path again to stream the bytes.
    let fw_image_path = if cmd == "update" {
        rest.first().cloned()
    } else {
        None
    };

    let request = parse_request(&cmd, &rest).map_err(Error::Rpc)?;

    let mut config = squic::Config::default();
    if let Ok(client_key) = std::env::var("SQUIC_CLIENT_KEY") {
        config.client_key = Some(client_key);
    }
    let conn = squic::dial(addr, &server_key, config).await?;
    let (mut send, mut recv) = conn.open_bi().await.map_err(squic::Error::from)?;

    // Write the metadata frame.
    write_frame(&mut send, &request).await?;

    // For FwUpdate: stream the raw firmware bytes before finishing.
    if let (Request::FwUpdate { size, .. }, Some(path)) = (&request, &fw_image_path) {
        eprintln!("uploading {path} ({size} bytes)...");
        let mut file = tokio::fs::File::open(path)
            .await
            .map_err(|e| Error::Rpc(format!("open {path}: {e}")))?;
        let mut buf = vec![0u8; 64 * 1024];
        let mut sent: u64 = 0;
        loop {
            let n = tokio::io::AsyncReadExt::read(&mut file, &mut buf)
                .await
                .map_err(|e| Error::Rpc(format!("read: {e}")))?;
            if n == 0 {
                break;
            }
            quinn::SendStream::write_all(&mut send, &buf[..n])
                .await
                .map_err(|e| Error::Rpc(format!("send: {e}")))?;
            sent += n as u64;
        }
        if sent != *size {
            return Err(Error::Rpc(format!(
                "file size changed during upload: expected {size}, sent {sent}"
            )));
        }
    }

    send.finish().map_err(|e| Error::Rpc(e.to_string()))?;

    // Read responses.
    loop {
        match read_frame::<_, Response>(&mut recv).await {
            Ok(resp) => {
                let last = matches!(
                    resp,
                    Response::Ok
                        | Response::Err { .. }
                        | Response::Value { .. }
                        | Response::Status { .. }
                );
                // FwProgress: display inline progress, don't print as
                // a normal response line.
                if let Response::FwProgress { bytes_received } = &resp {
                    if let Some(Request::FwUpdate { size, .. }) =
                        fw_image_path.as_ref().and(Some(&request))
                    {
                        let pct = (*bytes_received as f64 / *size as f64 * 100.0) as u32;
                        eprint!("\r  {bytes_received}/{size} bytes ({pct}%)");
                    }
                    continue;
                }
                // Backup response is base64-encoded tar.gz — decode
                // and write raw bytes to stdout so the operator can
                // redirect: `oxctl .. backup > backup.tar.gz`. For
                // any other Value response, fall through to the
                // normal text-formatting path.
                if matches!(request, Request::Backup) {
                    if let Response::Value { value } = &resp {
                        use base64::Engine as _;
                        match base64::engine::general_purpose::STANDARD.decode(value) {
                            Ok(bytes) => {
                                use std::io::Write as _;
                                let mut out = std::io::stdout().lock();
                                if let Err(e) = out.write_all(&bytes) {
                                    eprintln!("oxctl: write stdout: {e}");
                                }
                            }
                            Err(e) => {
                                eprintln!("oxctl: backup decode: {e}");
                            }
                        }
                        if last {
                            break;
                        }
                        continue;
                    }
                }
                let formatted = format_response(&resp);
                print!("{formatted}");
                if !formatted.ends_with('\n') {
                    println!();
                }
                // If --qr was requested on wg-enroll, render the
                // returned .conf as an ASCII QR after the normal
                // print so the operator can scan it directly with
                // a phone camera instead of copy-pasting text.
                if qr_mode {
                    if let oxwrt_api::rpc::Response::Value { value } = &resp {
                        match crate::qr::render(value) {
                            Ok(q) => {
                                println!();
                                print!("{q}");
                            }
                            Err(e) => {
                                eprintln!("oxctl: QR render failed: {e}");
                            }
                        }
                    }
                }
                if last {
                    break;
                }
            }
            Err(FrameError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // For FwApply, connection drop = reboot = success.
                if matches!(request, Request::FwApply { .. }) {
                    eprintln!("connection closed — router is rebooting");
                }
                break;
            }
            Err(e) => return Err(Error::Frame(e)),
        }
    }

    conn.close(0u32.into(), b"bye");
    Ok(())
}

fn parse_pubkey(hex_str: &str) -> Result<[u8; 32], Error> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| Error::InvalidServerKey(e.to_string()))?;
    bytes
        .try_into()
        .map_err(|_| Error::InvalidServerKey("expected 32 bytes".to_string()))
}

/// Drive the three-RPC `vpn-profile import` orchestration on a
/// single sQUIC connection. Each RPC goes on its own bi-stream.
///
/// If any step fails the function returns Err and the operator
/// sees a clear message — we don't try to unwind / rollback
/// partial state (e.g. a succeeded key upload + failed config push
/// leaves a stray key file on the router, which is harmless: the
/// key isn't wired to any profile until a corresponding config
/// push names it, and the operator can re-run the same command).
async fn handle_vpn_profile_import(
    addr: SocketAddr,
    name: String,
    conf_path: String,
) -> Result<(), Error> {
    use crate::vpn_import::{merge_vpn_block, parse_conf, render_block};

    // Name validation mirrors the server's (see handle_vpn_key_upload
    // in oxwrtd/src/control/server/mod.rs). Rejecting locally is
    // friendlier than round-tripping and seeing a remote error.
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Error::Rpc(format!(
            "vpn-profile import: invalid name {:?} (alphanum + _ - only)",
            name
        )));
    }

    // 1. Parse the .conf locally. Fails fast on missing fields
    //    before we waste a round trip.
    let text = std::fs::read_to_string(&conf_path)
        .map_err(|e| Error::Rpc(format!("read {conf_path}: {e}")))?;
    let parsed = parse_conf(&text).map_err(Error::Rpc)?;

    // 2. Dial once, run all three RPCs on separate bi-streams.
    let server_key_hex = std::env::var("SQUIC_SERVER_KEY").map_err(|_| Error::MissingServerKey)?;
    let server_key = parse_pubkey(&server_key_hex)?;
    let mut config = squic::Config::default();
    if let Ok(client_key) = std::env::var("SQUIC_CLIENT_KEY") {
        config.client_key = Some(client_key);
    }
    let conn = squic::dial(addr, &server_key, config).await?;

    // 2a. VpnKeyUpload.
    {
        let (mut send, mut recv) = conn.open_bi().await.map_err(squic::Error::from)?;
        let req = Request::VpnKeyUpload {
            name: name.clone(),
            private_key_b64: parsed.private_key.clone(),
        };
        write_frame(&mut send, &req).await?;
        send.finish().map_err(|e| Error::Rpc(e.to_string()))?;
        match read_frame::<_, Response>(&mut recv).await {
            Ok(Response::Ok) => eprintln!("vpn-profile import: key uploaded"),
            Ok(Response::Err { message }) => {
                return Err(Error::Rpc(format!("vpn-key-upload: {message}")));
            }
            Ok(other) => return Err(Error::Rpc(format!("unexpected response: {other:?}"))),
            Err(e) => return Err(Error::Frame(e)),
        }
    }

    // 2b. ConfigDump — get current oxwrt.toml text.
    let existing_toml: String = {
        let (mut send, mut recv) = conn.open_bi().await.map_err(squic::Error::from)?;
        write_frame(&mut send, &Request::ConfigDump).await?;
        send.finish().map_err(|e| Error::Rpc(e.to_string()))?;
        match read_frame::<_, Response>(&mut recv).await {
            Ok(Response::Value { value }) => value,
            Ok(Response::Err { message }) => {
                return Err(Error::Rpc(format!("config-dump: {message}")));
            }
            Ok(other) => return Err(Error::Rpc(format!("unexpected response: {other:?}"))),
            Err(e) => return Err(Error::Frame(e)),
        }
    };

    // 3. Merge the new [[vpn_client]] block.
    //    Default iface = "wgvpn<N>" where N is the current count
    //    of vpn_client entries (so a first import gets wgvpn0, a
    //    second wgvpn1, etc.). Priority defaults to 100 for the
    //    first, 200 for the second, etc. — matches the mwan2
    //    convention so failover "just works" when the operator
    //    imports multiple profiles.
    let existing_count = existing_toml
        .lines()
        .filter(|l| l.trim() == "[[vpn_client]]")
        .count();
    // If the profile name already exists we're REPLACING it, so
    // the count doesn't grow — reuse the existing iface + priority
    // rather than bumping.
    let existing_idx = find_existing_profile_idx(&existing_toml, &name);
    let (iface, priority) = match existing_idx {
        Some(i) => (format!("wgvpn{i}"), 100u32 + (i as u32) * 100),
        None => (
            format!("wgvpn{existing_count}"),
            100u32 + (existing_count as u32) * 100,
        ),
    };
    let key_path = format!("/etc/oxwrt/vpn/{}.key", name);
    let new_block = render_block(&name, &iface, priority, &parsed, &key_path);
    let merged = merge_vpn_block(&existing_toml, &name, &new_block).map_err(Error::Rpc)?;

    // 4. ConfigPush the merged TOML.
    {
        let (mut send, mut recv) = conn.open_bi().await.map_err(squic::Error::from)?;
        let req = Request::ConfigPush { toml: merged };
        write_frame(&mut send, &req).await?;
        send.finish().map_err(|e| Error::Rpc(e.to_string()))?;
        match read_frame::<_, Response>(&mut recv).await {
            Ok(Response::Ok) => {}
            Ok(Response::Err { message }) => {
                return Err(Error::Rpc(format!("config-push: {message}")));
            }
            Ok(other) => return Err(Error::Rpc(format!("unexpected response: {other:?}"))),
            Err(e) => return Err(Error::Frame(e)),
        }
    }

    conn.close(0u32.into(), b"bye");
    eprintln!(
        "vpn-profile import: profile {:?} merged as iface {} priority {}",
        name, iface, priority
    );
    eprintln!("vpn-profile import: run `oxctl {} reload` to activate.", addr);
    Ok(())
}

/// Scan an oxwrt.toml text for an existing `[[vpn_client]]` block
/// with the given name; return its zero-based index among all
/// `[[vpn_client]]` entries, or None. Matches what `merge_vpn_block`
/// does for replace semantics — we just need the index to reuse
/// the iface + priority slot.
fn find_existing_profile_idx(toml: &str, name: &str) -> Option<usize> {
    let doc: toml_edit::DocumentMut = toml.parse().ok()?;
    let arr = doc.get("vpn_client")?.as_array_of_tables()?;
    arr.iter().position(|t| {
        t.get("name")
            .and_then(|i| i.as_value())
            .and_then(|v| v.as_str())
            == Some(name)
    })
}

/// Parse `--flag=value` or `--flag value` pairs out of a slice of
/// argv tokens. Returns the matched value and the remaining args
/// minus the flag. Simple — oxctl isn't a general-purpose CLI
/// framework; clap/structopt would be overkill for two
/// subcommands with ≤3 flags apiece.
fn pull_flag(args: &[String], name: &str) -> Option<String> {
    for (i, a) in args.iter().enumerate() {
        if let Some(rest) = a.strip_prefix(&format!("--{name}=")) {
            return Some(rest.to_string());
        }
        if a == &format!("--{name}") {
            return args.get(i + 1).cloned();
        }
    }
    None
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == &format!("--{name}"))
}

/// Handle `oxctl <remote> mullvad-relays [--country=XX] [--city=XX]
/// [--limit=N] [--include-inactive]`.
///
/// Takes a remote address parameter only for syntactic symmetry
/// with other oxctl commands — the router isn't involved. Hits
/// api.mullvad.net directly, prints a formatted table to stdout.
async fn handle_mullvad_relays(rest: &[String]) -> Result<(), Error> {
    use crate::mullvad;
    let country = pull_flag(rest, "country");
    let city = pull_flag(rest, "city");
    let include_inactive = has_flag(rest, "include-inactive");
    let limit: usize = pull_flag(rest, "limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(usize::MAX);

    let relays = mullvad::fetch_relays().await.map_err(Error::Rpc)?;
    let filtered = mullvad::filter_relays(
        &relays.wireguard.relays,
        country.as_deref(),
        city.as_deref(),
        include_inactive,
    );
    // Header + one line per relay. Fixed-width columns so the
    // output pipes into `column -t` / `awk` without surprises.
    println!(
        "{:<22} {:<3} {:<4} {:<20} {:<6} {}",
        "hostname", "cc", "city", "ipv4", "active", "pubkey"
    );
    for r in filtered.iter().take(limit) {
        println!(
            "{:<22} {:<3} {:<4} {:<20} {:<6} {}",
            r.hostname,
            r.country_code().unwrap_or("?"),
            r.city_code().unwrap_or("?"),
            r.ipv4_addr_in.as_deref().unwrap_or("?"),
            if r.active { "yes" } else { "no" },
            r.public_key.as_deref().unwrap_or("?"),
        );
    }
    eprintln!(
        "({} relays, {} shown)",
        filtered.len(),
        filtered.len().min(limit)
    );
    Ok(())
}

/// Handle `oxctl <remote> vpn-switch-relay <profile> <hostname>`.
///
/// Looks up the relay in Mullvad's list, confirms it exists,
/// then does ConfigDump + toml_edit patch + ConfigPush to rewrite
/// JUST `endpoint` and `public_key` on the named profile. All
/// other fields (private_key path, address, DNS, probe_target,
/// priority) are preserved — Mullvad uses one account-level
/// keypair across all relays.
async fn handle_vpn_switch_relay(
    addr: SocketAddr,
    profile: String,
    hostname: String,
) -> Result<(), Error> {
    use crate::mullvad;

    // 1. API lookup — fail early before touching the router.
    let relays = mullvad::fetch_relays().await.map_err(Error::Rpc)?;
    let relay = mullvad::find_by_hostname(&relays.wireguard.relays, &hostname)
        .ok_or_else(|| {
            Error::Rpc(format!(
                "vpn-switch-relay: no Mullvad relay with hostname {:?}",
                hostname
            ))
        })?;
    let new_endpoint_ip = relay
        .ipv4_addr_in
        .clone()
        .ok_or_else(|| Error::Rpc(format!("relay {hostname} has no ipv4_addr_in")))?;
    let new_pubkey = relay
        .public_key
        .clone()
        .ok_or_else(|| Error::Rpc(format!("relay {hostname} has no public_key")))?;
    let new_endpoint = format!("{}:{}", new_endpoint_ip, mullvad::MULLVAD_WG_PORT);

    // 2. Dial router, ConfigDump, patch, ConfigPush. Same pattern
    //    as vpn-profile import but smaller — only two field edits.
    let server_key_hex = std::env::var("SQUIC_SERVER_KEY").map_err(|_| Error::MissingServerKey)?;
    let server_key = parse_pubkey(&server_key_hex)?;
    let mut squic_config = squic::Config::default();
    if let Ok(client_key) = std::env::var("SQUIC_CLIENT_KEY") {
        squic_config.client_key = Some(client_key);
    }
    let conn = squic::dial(addr, &server_key, squic_config).await?;

    let existing_toml: String = {
        let (mut send, mut recv) = conn.open_bi().await.map_err(squic::Error::from)?;
        write_frame(&mut send, &Request::ConfigDump).await?;
        send.finish().map_err(|e| Error::Rpc(e.to_string()))?;
        match read_frame::<_, Response>(&mut recv).await {
            Ok(Response::Value { value }) => value,
            Ok(Response::Err { message }) => {
                return Err(Error::Rpc(format!("config-dump: {message}")));
            }
            Ok(other) => return Err(Error::Rpc(format!("unexpected: {other:?}"))),
            Err(e) => return Err(Error::Frame(e)),
        }
    };

    // 3. Patch the matching [[vpn_client]] block's endpoint +
    //    public_key via toml_edit so comments/order elsewhere
    //    survive. Reject if the profile isn't found — don't
    //    silently append as a new one, that's `vpn-profile import`
    //    territory.
    let mut doc: toml_edit::DocumentMut = existing_toml
        .parse()
        .map_err(|e| Error::Rpc(format!("parse oxwrt.toml: {e}")))?;
    let arr = doc
        .get_mut("vpn_client")
        .and_then(|i| i.as_array_of_tables_mut())
        .ok_or_else(|| Error::Rpc("no [[vpn_client]] entries in config".into()))?;
    let target = arr.iter_mut().find(|t| {
        t.get("name")
            .and_then(|i| i.as_value())
            .and_then(|v| v.as_str())
            == Some(profile.as_str())
    });
    let Some(target) = target else {
        return Err(Error::Rpc(format!(
            "vpn-switch-relay: profile {:?} not found",
            profile
        )));
    };
    target["endpoint"] = toml_edit::value(new_endpoint.clone());
    target["public_key"] = toml_edit::value(new_pubkey.clone());
    let merged = doc.to_string();

    // 4. ConfigPush.
    {
        let (mut send, mut recv) = conn.open_bi().await.map_err(squic::Error::from)?;
        write_frame(&mut send, &Request::ConfigPush { toml: merged }).await?;
        send.finish().map_err(|e| Error::Rpc(e.to_string()))?;
        match read_frame::<_, Response>(&mut recv).await {
            Ok(Response::Ok) => {}
            Ok(Response::Err { message }) => {
                return Err(Error::Rpc(format!("config-push: {message}")));
            }
            Ok(other) => return Err(Error::Rpc(format!("unexpected: {other:?}"))),
            Err(e) => return Err(Error::Frame(e)),
        }
    }
    conn.close(0u32.into(), b"bye");
    eprintln!(
        "vpn-switch-relay: profile {:?} → {} ({})",
        profile, hostname, new_endpoint
    );
    eprintln!("vpn-switch-relay: run `oxctl {} reload` to activate.", addr);
    Ok(())
}
