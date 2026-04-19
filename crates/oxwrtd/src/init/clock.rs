//! Clock bootstrapping: SNTP via anycast + build-epoch floor.
//! Split out of init.rs in step 6.

pub(super) async fn sntp_bootstrap_clock(addr: &str) -> Result<(), String> {
    use tokio::net::UdpSocket;
    use tokio::time::{Duration, timeout};

    // SNTP request: 48 zero bytes except the first, which is the
    // LI/VN/Mode header. 0x1B = LI=0, VN=3, Mode=3 (client).
    let mut req = [0u8; 48];
    req[0] = 0x1B;

    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("bind: {e}"))?;
    sock.connect(addr)
        .await
        .map_err(|e| format!("connect {addr}: {e}"))?;

    timeout(Duration::from_secs(5), sock.send(&req))
        .await
        .map_err(|_| "send timeout".to_string())?
        .map_err(|e| format!("send: {e}"))?;

    let mut buf = [0u8; 48];
    timeout(Duration::from_secs(5), sock.recv(&mut buf))
        .await
        .map_err(|_| "recv timeout".to_string())?
        .map_err(|e| format!("recv: {e}"))?;

    // Transmit timestamp: offset 40, 8 bytes (32-bit seconds since
    // NTP epoch 1900, 32-bit fractional seconds).
    let ntp_secs = u32::from_be_bytes([buf[40], buf[41], buf[42], buf[43]]);
    let ntp_frac = u32::from_be_bytes([buf[44], buf[45], buf[46], buf[47]]);
    if ntp_secs == 0 {
        return Err("reply had zero transmit timestamp".to_string());
    }

    // NTP epoch is Jan 1 1900; UNIX epoch is Jan 1 1970 —
    // 2_208_988_800 seconds earlier.
    const NTP_TO_UNIX_EPOCH: u64 = 2_208_988_800;
    let unix_secs = u64::from(ntp_secs).saturating_sub(NTP_TO_UNIX_EPOCH);
    // Fractional seconds → nanoseconds: (frac / 2^32) * 1e9.
    let unix_nsec = ((u64::from(ntp_frac) * 1_000_000_000) >> 32) as u32;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let skew = unix_secs as i64 - now as i64;

    let tv = rustix::time::Timespec {
        tv_sec: unix_secs as i64,
        tv_nsec: unix_nsec as i64,
    };
    rustix::time::clock_settime(rustix::time::ClockId::Realtime, tv)
        .map_err(|e| format!("clock_settime: {e}"))?;

    tracing::info!(
        server = %addr,
        unix_secs,
        skew_secs = skew,
        "sntp bootstrap: clock set from ntp reply"
    );
    Ok(())
}

/// If the system clock is earlier than `BUILD_EPOCH_SECS` (embedded at
/// build time via the env var), bump it forward. Keeps TLS handshakes
/// from failing on first boot before SNTP completes, since cert
/// validation rejects clocks from 1970.
pub(super) fn bootstrap_clock_floor() {
    const BUILD_EPOCH_SECS: u64 = match u64::from_str_radix(env!("BUILD_EPOCH_SECS"), 10) {
        Ok(v) => v,
        Err(_) => 0,
    };
    if BUILD_EPOCH_SECS == 0 {
        return;
    }

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if now_secs >= BUILD_EPOCH_SECS {
        // Clock is already at or past build time — NTP probably synced
        // us earlier (warm reboot preserving /var/lib/oxwrt), or the
        // operator ran `date -s` over UART. Nothing to do.
        return;
    }

    // Pre-check: don't bother calling settimeofday(2) if the delta is
    // less than a second — avoids noise in logs on the normal case
    // where the clock is already set.
    let delta = BUILD_EPOCH_SECS - now_secs;

    let tv = rustix::time::Timespec {
        tv_sec: BUILD_EPOCH_SECS as i64,
        tv_nsec: 0,
    };
    match rustix::time::clock_settime(rustix::time::ClockId::Realtime, tv) {
        Ok(()) => {
            tracing::info!(
                from_secs = now_secs,
                to_secs = BUILD_EPOCH_SECS,
                forward_by_secs = delta,
                "clock bootstrapped to build-time floor"
            );
        }
        Err(e) => {
            // EPERM on a system that doesn't let us clock_settime —
            // shouldn't happen when we're PID 1, but could happen when
            // running as a side binary for development. Not fatal.
            tracing::warn!(
                error = %e,
                from_secs = now_secs,
                to_secs = BUILD_EPOCH_SECS,
                "clock bootstrap failed (clock_settime EPERM?) — sQUIC may reject clients with real timestamps"
            );
        }
    }
}
