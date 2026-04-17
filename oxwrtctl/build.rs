//! Build script: bakes the binary's build time (epoch seconds) into
//! `BUILD_EPOCH_SECS` so init code can use it as a clock floor.
//!
//! Why we need this: the GL-MT6000 has no battery-backed RTC, so every
//! cold boot starts with the kernel clock at Jan 1 1970. The sQUIC
//! server rejects any client handshake with a timestamp more than ±120
//! seconds off from the server clock — which is every client, when the
//! server thinks it's 56 years in the past. NTP can't fix it either,
//! because NTP runs as a supervised service that depends on WAN DHCP,
//! which depends on… a working network stack. Chicken and egg.
//!
//! Bumping the clock to the binary build time at init gives us a floor
//! that's almost certainly "recent enough" for an operator who just
//! flashed the image to talk to the device. Stale images (week+ old)
//! still need real NTP — tracked as a separate follow-up.
//!
//! Uses SOURCE_DATE_EPOCH if set (reproducible builds), otherwise the
//! current UNIX time at build.

use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // Honor SOURCE_DATE_EPOCH so reproducible builds get the same
    // clock floor everywhere. Falls back to live time if unset.
    let epoch = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock before UNIX epoch")
                .as_secs()
        });

    println!("cargo:rustc-env=BUILD_EPOCH_SECS={epoch}");
    // Re-run only if the env var changes (normal rebuilds pick up
    // the default "now" fallback on every build automatically).
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
}
