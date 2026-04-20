//! Secret-field inventory and TOML split/merge helpers.
//!
//! The oxwrt config lives in **two** files on disk:
//!
//! - `/etc/oxwrt/oxwrt.toml` (mode 0644) — the public, publishable
//!   config. Safe to commit, paste into an issue, or share with a
//!   collaborator. Contains every non-secret setting.
//! - `/etc/oxwrt/oxwrt.secrets.toml` (mode 0600) — the secret
//!   overlay. Same TOML schema but sparse: only the leaves listed
//!   in [`SECRET_FIELDS`] appear, plus whatever identity fields
//!   are needed to associate each leaf with its parent entry (ssid
//!   for wifi, name for wg/ddns/networks, etc.).
//!
//! The loader ([`crate::config::Config::load_with_secrets`])
//! deep-merges the two. This module provides the inverse direction
//! — [`split_document`] takes a single merged `toml_edit`
//! `DocumentMut` and pulls every secret leaf out into a second
//! doc, returning `(public, secret)`. Writers atomic-write each
//! to its own file.

use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Table, Value};

/// Placeholder inserted into the public file at dump-config /
/// redaction time. Also used by some writers when they want to
/// leave a trace that "a value used to be here, look in secrets".
pub const REDACTED: &str = "<redacted>";

/// Authoritative list of every field treated as a secret.
///
/// When adding a new field to [`crate::config::Config`] that holds
/// a password, token, API key, passphrase, or pre-shared key, add
/// an entry here. The split/merge machinery is driven entirely by
/// this table — writers, loaders, and the redactor all consult it.
///
/// Fields are identified by `(section, field)`. `section` is a
/// dotted path into the TOML tree; `field` is the leaf key to move.
/// For enum-tagged sections (DDNS providers, WAN modes) the
/// `variant_filter` narrows to entries whose `tag` field equals
/// `value` — so we don't touch a Cloudflare DDNS entry's
/// nonexistent `password` just because Namecheap has one.
pub struct SecretField {
    pub section: &'static str,
    pub identity: &'static str,
    pub field: &'static str,
    /// `Some((tag_key, tag_value))` to match only variant entries
    /// where `entry[tag_key] == tag_value`. `None` = all entries.
    pub variant_filter: Option<(&'static str, &'static str)>,
}

pub const SECRET_FIELDS: &[SecretField] = &[
    // [[wifi]]
    SecretField {
        section: "wifi",
        identity: "ssid",
        field: "passphrase",
        variant_filter: None,
    },
    // [[wireguard.peers]] (nested under [[wireguard]]; split_document
    // handles the nested array traversal explicitly).
    SecretField {
        section: "wireguard.peers",
        identity: "name",
        field: "preshared_key",
        variant_filter: None,
    },
    // [[ddns]] — tagged enum: one field per provider variant.
    SecretField {
        section: "ddns",
        identity: "name",
        field: "token",
        variant_filter: Some(("provider", "duckdns")),
    },
    SecretField {
        section: "ddns",
        identity: "name",
        field: "api_token",
        variant_filter: Some(("provider", "cloudflare")),
    },
    SecretField {
        section: "ddns",
        identity: "name",
        field: "password",
        variant_filter: Some(("provider", "namecheap")),
    },
    SecretField {
        section: "ddns",
        identity: "name",
        field: "token",
        variant_filter: Some(("provider", "dynv6")),
    },
    SecretField {
        section: "ddns",
        identity: "name",
        field: "key",
        variant_filter: Some(("provider", "he")),
    },
    // [[networks]] — PPPoE password is flattened into the wan entry.
    SecretField {
        section: "networks",
        identity: "name",
        field: "password",
        variant_filter: Some(("mode", "pppoe")),
    },
];

/// Test whether a TOML table entry matches a SecretField's
/// variant filter. Returns true if there is no filter.
fn variant_matches(entry: &Table, filter: Option<(&str, &str)>) -> bool {
    let Some((tag, value)) = filter else {
        return true;
    };
    entry
        .get(tag)
        .and_then(|i| i.as_value())
        .and_then(|v| v.as_str())
        == Some(value)
}

fn get_str_field<'a>(entry: &'a Table, name: &str) -> Option<&'a str> {
    entry
        .get(name)
        .and_then(|i| i.as_value())
        .and_then(|v| v.as_str())
}

/// Ensure that `doc` contains an `ArrayOfTables` at `section` and
/// return a mutable reference. Creates an empty one if absent.
/// For top-level arrays only (single-level path like `"wifi"`).
fn ensure_aot<'a>(doc: &'a mut DocumentMut, section: &str) -> &'a mut ArrayOfTables {
    if !doc.contains_key(section) {
        doc.insert(section, Item::ArrayOfTables(ArrayOfTables::new()));
    }
    doc.get_mut(section)
        .unwrap()
        .as_array_of_tables_mut()
        .expect("section exists but is not an array-of-tables")
}

/// Same, but for an `ArrayOfTables` nested inside a parent
/// `Table`. Creates if absent.
fn ensure_aot_in_table<'a>(parent: &'a mut Table, key: &str) -> &'a mut ArrayOfTables {
    if !parent.contains_key(key) {
        parent.insert(key, Item::ArrayOfTables(ArrayOfTables::new()));
    }
    parent
        .get_mut(key)
        .unwrap()
        .as_array_of_tables_mut()
        .expect("nested key exists but is not an array-of-tables")
}

/// Find-or-create an entry inside a secret `ArrayOfTables` whose
/// `identity` field equals `id`. The entry is returned mutable so
/// the caller can insert the secret leaf into it.
fn ensure_entry<'a>(aot: &'a mut ArrayOfTables, identity: &str, id: &str) -> &'a mut Table {
    let existing = aot
        .iter()
        .position(|t| get_str_field(t, identity) == Some(id));
    match existing {
        Some(i) => aot.get_mut(i).unwrap(),
        None => {
            let mut t = Table::new();
            t.insert(identity, Item::Value(Value::from(id)));
            aot.push(t);
            let n = aot.len();
            aot.get_mut(n - 1).unwrap()
        }
    }
}

/// Pull every secret leaf out of `public` into a new `DocumentMut`
/// representing the secrets overlay. The public doc retains every
/// comment, every non-secret field, and every section's ordering —
/// only the secret leaves are removed.
///
/// The secret doc is built from scratch: it has entries only where
/// a secret was found, each entry carries just its identity key +
/// the moved leaves. That's enough for the loader's merge to
/// reassemble the original on next boot.
pub fn split_document(public: &mut DocumentMut) -> DocumentMut {
    let mut secret = DocumentMut::new();
    for sf in SECRET_FIELDS {
        split_one(public, &mut secret, sf);
    }
    secret
}

fn split_one(public: &mut DocumentMut, secret: &mut DocumentMut, sf: &SecretField) {
    match sf.section {
        // Special-case the one nested array-of-tables path v1 has.
        "wireguard.peers" => split_wireguard_peers(public, secret, sf),
        // Everything else is a top-level array-of-tables.
        section => split_top_level_aot(public, secret, sf, section),
    }
}

fn split_top_level_aot(
    public: &mut DocumentMut,
    secret: &mut DocumentMut,
    sf: &SecretField,
    section: &str,
) {
    let Some(aot) = public
        .get_mut(section)
        .and_then(|i| i.as_array_of_tables_mut())
    else {
        return;
    };
    // Collect (id, moved_value) pairs without holding a mut ref to
    // the secret doc during iteration of public.
    let mut moves: Vec<(String, Item)> = Vec::new();
    for entry in aot.iter_mut() {
        if !variant_matches(entry, sf.variant_filter) {
            continue;
        }
        let Some(id) = get_str_field(entry, sf.identity).map(|s| s.to_string()) else {
            continue;
        };
        if let Some(moved) = entry.remove(sf.field) {
            moves.push((id, moved));
        }
    }
    if moves.is_empty() {
        return;
    }
    let sec_aot = ensure_aot(secret, section);
    for (id, moved) in moves {
        let e = ensure_entry(sec_aot, sf.identity, &id);
        e.insert(sf.field, moved);
    }
}

fn split_wireguard_peers(public: &mut DocumentMut, secret: &mut DocumentMut, sf: &SecretField) {
    let Some(wg_aot) = public
        .get_mut("wireguard")
        .and_then(|i| i.as_array_of_tables_mut())
    else {
        return;
    };
    // Collect (wg_name, peer_name, moved) up front, then apply to
    // the secret doc — keeps borrow lifetimes clean.
    let mut moves: Vec<(String, String, Item)> = Vec::new();
    for wg in wg_aot.iter_mut() {
        let Some(wg_name) = get_str_field(wg, "name").map(|s| s.to_string()) else {
            continue;
        };
        let Some(peers) = wg
            .get_mut("peers")
            .and_then(|i| i.as_array_of_tables_mut())
        else {
            continue;
        };
        for peer in peers.iter_mut() {
            let Some(peer_name) = get_str_field(peer, sf.identity).map(|s| s.to_string()) else {
                continue;
            };
            if let Some(moved) = peer.remove(sf.field) {
                moves.push((wg_name.clone(), peer_name, moved));
            }
        }
    }
    if moves.is_empty() {
        return;
    }
    let sec_wg = ensure_aot(secret, "wireguard");
    // Group moves by wireguard name so we emit one secret wg entry
    // per instance rather than one per peer.
    use std::collections::BTreeMap;
    let mut by_wg: BTreeMap<String, Vec<(String, Item)>> = BTreeMap::new();
    for (wg, peer, moved) in moves {
        by_wg.entry(wg).or_default().push((peer, moved));
    }
    for (wg_name, peer_moves) in by_wg {
        let wg_entry = ensure_entry(sec_wg, "name", &wg_name);
        let sec_peers = ensure_aot_in_table(wg_entry, "peers");
        for (peer_name, moved) in peer_moves {
            let pe = ensure_entry(sec_peers, sf.identity, &peer_name);
            pe.insert(sf.field, moved);
        }
    }
}

/// Replace every secret leaf in `doc` with the literal string
/// [`REDACTED`]. Used by `oxctl dump-config` to print a merged
/// view safely.
pub fn redact_document(doc: &mut DocumentMut) {
    for sf in SECRET_FIELDS {
        redact_one(doc, sf);
    }
}

fn redact_one(doc: &mut DocumentMut, sf: &SecretField) {
    match sf.section {
        "wireguard.peers" => {
            let Some(wg_aot) = doc
                .get_mut("wireguard")
                .and_then(|i| i.as_array_of_tables_mut())
            else {
                return;
            };
            for wg in wg_aot.iter_mut() {
                let Some(peers) = wg
                    .get_mut("peers")
                    .and_then(|i| i.as_array_of_tables_mut())
                else {
                    continue;
                };
                for peer in peers.iter_mut() {
                    if peer.contains_key(sf.field) {
                        peer.insert(sf.field, Item::Value(Value::from(REDACTED)));
                    }
                }
            }
        }
        section => {
            let Some(aot) = doc.get_mut(section).and_then(|i| i.as_array_of_tables_mut()) else {
                return;
            };
            for entry in aot.iter_mut() {
                if !variant_matches(entry, sf.variant_filter) {
                    continue;
                }
                if entry.contains_key(sf.field) {
                    entry.insert(sf.field, Item::Value(Value::from(REDACTED)));
                }
            }
        }
    }
}

/// Helper so callers don't have to depend on `toml_edit` directly
/// to assemble an empty `Array` for doc scaffolding.
#[allow(dead_code)]
pub fn empty_array() -> Array {
    Array::new()
}

/// Possible outcomes of a one-shot `migrate_public_to_split` call.
#[derive(Debug, PartialEq, Eq)]
pub enum MigrationOutcome {
    /// Public file doesn't exist — nothing to do (fresh flash / dev).
    NoPublicFile,
    /// Public file has no secret leaves — the split already happened
    /// in a previous boot, or this config never had secrets.
    AlreadyClean,
    /// Public file contains secrets AND the secrets file already
    /// exists. Refuse to touch — the secrets file might have newer
    /// values the operator deliberately put there; a merge would be
    /// guesswork. Caller should log a warning and leave things to
    /// operator intervention.
    BothPresentUnsafe,
    /// Migrated `count` secret leaves from public to a newly-created
    /// secrets file. Public is now publishable; secrets file is
    /// mode 0600.
    Migrated { count: usize },
}

/// One-shot migration helper: if `public_path` contains live secret
/// leaves AND there's no sibling `oxwrt.secrets.toml`, split the
/// public file in place and write both halves to disk.
///
/// Called from the daemon's boot path before `Config::load` so the
/// loader always sees the split layout. Idempotent: subsequent
/// boots find `oxwrt.secrets.toml` present and short-circuit.
pub fn migrate_public_to_split(
    public_path: &std::path::Path,
) -> Result<MigrationOutcome, std::io::Error> {
    use std::io::ErrorKind;
    use std::os::unix::fs::PermissionsExt;
    let secrets_path = public_path.with_file_name("oxwrt.secrets.toml");
    let public_text = match std::fs::read_to_string(public_path) {
        Ok(s) => s,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return Ok(MigrationOutcome::NoPublicFile);
        }
        Err(e) => return Err(e),
    };
    let mut doc: DocumentMut = public_text
        .parse()
        .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, format!("parse public: {e}")))?;
    let secret_doc = split_document(&mut doc);
    let secret_count = count_entries(&secret_doc);
    if secret_count == 0 {
        return Ok(MigrationOutcome::AlreadyClean);
    }
    if secrets_path.exists() {
        return Ok(MigrationOutcome::BothPresentUnsafe);
    }
    // Write atomically: tmp → fsync → rename, pair of files.
    write_tmp_rename(public_path, &doc.to_string(), 0o644)?;
    write_tmp_rename(&secrets_path, &secret_doc.to_string(), 0o600)?;
    // Double-check mode post-rename (some filesystems / umasks leak
    // through tmp-rename; cheap insurance).
    let _ =
        std::fs::set_permissions(&secrets_path, std::fs::Permissions::from_mode(0o600));
    Ok(MigrationOutcome::Migrated {
        count: secret_count,
    })
}

/// Count the number of secret entries in a (freshly-split) overlay
/// doc. Entries are flat: one per secret leaf across all top-level
/// arrays + the nested `wireguard.peers` path. Used by
/// `migrate_public_to_split` to decide whether the migration has
/// work to do, and by the dump-config path to emit an honest
/// `secrets: N` header.
pub fn count_entries(doc: &DocumentMut) -> usize {
    let mut n = 0;
    for (_, item) in doc.iter() {
        let Some(aot) = item.as_array_of_tables() else {
            continue;
        };
        for entry in aot.iter() {
            // Count every field on each entry except the identity
            // key. Multiple secret leaves per entry (impossible
            // today but future-proof) count separately.
            let identity_keys = ["ssid", "name"];
            n += entry
                .iter()
                .filter(|(k, _)| !identity_keys.contains(k))
                .count();
            // Recurse into nested peers arrays for wireguard.
            if let Some(peers) = entry.get("peers").and_then(|i| i.as_array_of_tables()) {
                for peer in peers.iter() {
                    n += peer
                        .iter()
                        .filter(|(k, _)| !identity_keys.contains(k))
                        .count();
                }
            }
        }
    }
    n
}

fn write_tmp_rename(
    path: &std::path::Path,
    text: &str,
    mode: u32,
) -> Result<(), std::io::Error> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let tmp = path.with_extension(match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => format!("{ext}.mig-tmp"),
        None => "mig-tmp".to_string(),
    });
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    std::fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> DocumentMut {
        s.parse().unwrap()
    }

    #[test]
    fn split_moves_wifi_passphrase() {
        let mut pub_doc = parse(
            r#"
hostname = "x"

[[wifi]]
ssid = "main"
phy = "phy0"
passphrase = "secret-main-pw"

[[wifi]]
ssid = "guest"
phy = "phy0"
passphrase = "secret-guest-pw"
"#,
        );
        let secret = split_document(&mut pub_doc);
        // Public doc: no passphrases anywhere.
        let pub_s = pub_doc.to_string();
        assert!(!pub_s.contains("secret-main-pw"));
        assert!(!pub_s.contains("secret-guest-pw"));
        assert!(pub_s.contains("ssid = \"main\""));
        assert!(pub_s.contains("phy = \"phy0\""));
        // Secret doc: two wifi entries, just ssid + passphrase.
        let sec_s = secret.to_string();
        assert!(sec_s.contains("ssid = \"main\""));
        assert!(sec_s.contains("secret-main-pw"));
        assert!(sec_s.contains("ssid = \"guest\""));
        assert!(sec_s.contains("secret-guest-pw"));
        // Secret doc should NOT carry the non-secret phy field.
        assert!(!sec_s.contains("phy"));
    }

    #[test]
    fn split_roundtrips_through_loader() {
        // Start with a merged-shape doc, split, then reassemble via
        // the toml::Value-level merge in config.rs. Result must be
        // identical to the original at the toml::Value level
        // (comments + whitespace can differ, but data shouldn't).
        let original = r#"
hostname = "test"

[[wifi]]
ssid = "main"
phy = "phy0"
network = "lan"
passphrase = "pw"
"#;
        let mut doc: DocumentMut = original.parse().unwrap();
        let sec = split_document(&mut doc);

        let mut base: toml::Value = toml::from_str(&doc.to_string()).unwrap();
        let overlay: toml::Value = toml::from_str(&sec.to_string()).unwrap();
        crate::config::merge_toml(&mut base, overlay, "");

        let want: toml::Value = toml::from_str(original).unwrap();
        assert_eq!(base, want);
    }

    #[test]
    fn split_ddns_variant_filter() {
        let mut doc = parse(
            r#"
[[ddns]]
provider = "duckdns"
name = "home"
domain = "me.duckdns.org"
token = "DUCK-TOKEN"

[[ddns]]
provider = "cloudflare"
name = "work"
zone_id = "Z"
record_id = "R"
domain = "me.example.com"
api_token = "CF-TOKEN"
"#,
        );
        let secret = split_document(&mut doc);
        let pub_s = doc.to_string();
        let sec_s = secret.to_string();
        // Both secrets gone from public…
        assert!(!pub_s.contains("DUCK-TOKEN"));
        assert!(!pub_s.contains("CF-TOKEN"));
        // …and present in the secrets overlay, each filed against
        // its correct name.
        assert!(sec_s.contains("DUCK-TOKEN"));
        assert!(sec_s.contains("CF-TOKEN"));
        // And public still has the non-secret structure.
        assert!(pub_s.contains("zone_id"));
        assert!(pub_s.contains("duckdns"));
    }

    #[test]
    fn split_wireguard_peer_psk() {
        let mut doc = parse(
            r#"
[[wireguard]]
name = "wg0"

[[wireguard.peers]]
name = "laptop"
public_key = "LAPTOP-PUB"

[[wireguard.peers]]
name = "phone"
public_key = "PHONE-PUB"
preshared_key = "PHONE-PSK"
"#,
        );
        let secret = split_document(&mut doc);
        let pub_s = doc.to_string();
        let sec_s = secret.to_string();
        assert!(!pub_s.contains("PHONE-PSK"));
        // public_key (not a secret) stays inline.
        assert!(pub_s.contains("LAPTOP-PUB"));
        assert!(pub_s.contains("PHONE-PUB"));
        // Secret doc carries the nested peer-PSK skeleton.
        assert!(sec_s.contains("PHONE-PSK"));
        assert!(sec_s.contains("[[wireguard]]"));
        assert!(sec_s.contains("[[wireguard.peers]]"));
        // Laptop peer has no PSK → should not appear in secrets.
        assert!(!sec_s.contains("laptop"));
    }

    #[test]
    fn split_pppoe_password() {
        let mut doc = parse(
            r#"
[[networks]]
type = "wan"
name = "wan"
iface = "eth0"
mode = "pppoe"
username = "user@isp"
password = "isp-pw"

[[networks]]
type = "wan"
name = "backup"
iface = "eth1"
mode = "dhcp"
"#,
        );
        let secret = split_document(&mut doc);
        let pub_s = doc.to_string();
        let sec_s = secret.to_string();
        assert!(!pub_s.contains("isp-pw"));
        assert!(pub_s.contains("user@isp"));
        assert!(sec_s.contains("isp-pw"));
        // DHCP network has no password, shouldn't leak into secrets.
        assert!(!sec_s.contains("backup"));
    }

    #[test]
    fn redact_replaces_leaves() {
        let mut doc = parse(
            r#"
[[wifi]]
ssid = "main"
passphrase = "hunter2"
"#,
        );
        redact_document(&mut doc);
        let s = doc.to_string();
        assert!(!s.contains("hunter2"));
        assert!(s.contains(REDACTED));
    }

    #[test]
    fn migrate_splits_in_place() {
        let tmp = tempfile::tempdir().unwrap();
        let public = tmp.path().join("oxwrt.toml");
        std::fs::write(
            &public,
            concat!(
                "hostname = \"x\"\n",
                "[[wifi]]\nssid = \"main\"\npassphrase = \"hunter2\"\n",
            ),
        )
        .unwrap();
        let outcome = migrate_public_to_split(&public).unwrap();
        assert_eq!(outcome, MigrationOutcome::Migrated { count: 1 });
        let pub_after = std::fs::read_to_string(&public).unwrap();
        assert!(!pub_after.contains("hunter2"));
        let sec = std::fs::read_to_string(tmp.path().join("oxwrt.secrets.toml")).unwrap();
        assert!(sec.contains("hunter2"));
        // Mode check (Unix only).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(tmp.path().join("oxwrt.secrets.toml"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn migrate_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let public = tmp.path().join("oxwrt.toml");
        std::fs::write(&public, "hostname = \"x\"\n[[wifi]]\nssid = \"m\"\npassphrase = \"p\"\n")
            .unwrap();
        let _first = migrate_public_to_split(&public).unwrap();
        let second = migrate_public_to_split(&public).unwrap();
        // Second call: public is already clean.
        assert_eq!(second, MigrationOutcome::AlreadyClean);
    }

    #[test]
    fn migrate_refuses_when_both_present() {
        let tmp = tempfile::tempdir().unwrap();
        let public = tmp.path().join("oxwrt.toml");
        let secrets = tmp.path().join("oxwrt.secrets.toml");
        std::fs::write(&public, "hostname = \"x\"\n[[wifi]]\nssid = \"m\"\npassphrase = \"p\"\n")
            .unwrap();
        std::fs::write(&secrets, "").unwrap();
        let outcome = migrate_public_to_split(&public).unwrap();
        assert_eq!(outcome, MigrationOutcome::BothPresentUnsafe);
        // Public not modified.
        assert!(std::fs::read_to_string(&public).unwrap().contains("p"));
    }

    #[test]
    fn migrate_missing_public_is_ok() {
        let tmp = tempfile::tempdir().unwrap();
        let public = tmp.path().join("oxwrt.toml"); // absent
        let outcome = migrate_public_to_split(&public).unwrap();
        assert_eq!(outcome, MigrationOutcome::NoPublicFile);
    }

    #[test]
    fn split_is_noop_when_no_secrets_present() {
        let mut doc = parse(
            r#"
hostname = "bare"

[[networks]]
type = "wan"
name = "wan"
iface = "eth0"
mode = "dhcp"
"#,
        );
        let before = doc.to_string();
        let sec = split_document(&mut doc);
        assert_eq!(doc.to_string(), before);
        // Empty secrets doc serializes to an empty string.
        assert!(sec.to_string().trim().is_empty());
    }
}
