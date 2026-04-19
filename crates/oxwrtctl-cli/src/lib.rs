//! oxwrtctl-cli — the operator-facing CLI client.
//!
//! Exposed both as a library (`oxwrtctl_cli::run`) and as a binary
//! (`oxctl`). The library form exists so the on-device daemon can keep
//! its `oxwrtctl --client …` subcommand working by calling into the
//! same code — operators' muscle memory, CI scripts, and shell aliases
//! all continue to work, and this crate is the single source of truth
//! for the client protocol.
//!
//! The binary form (`oxctl`) is what developers install on their
//! machines. It's small (no rustix/netlink/nft/seccomp/landlock/tar/
//! flate2 in the compile graph) and builds on every target — macOS,
//! Linux-glibc, Linux-musl — without cross toolchains.

pub mod client;
pub mod mullvad;
pub mod qr;
pub mod vpn_import;

pub use client::{Error, run};

use std::process::ExitCode;

/// Read the Ed25519 signing-key seed from disk and print the derived
/// **public** key as hex to stdout. Used to bootstrap sQUIC clients —
/// the public key has to be known out-of-band before `dial()` can pin
/// it, so an operator would typically run this once over a serial or
/// physical channel right after first boot to learn the server key.
///
/// Default path is `/etc/oxwrt/key.ed25519`; a different path can be
/// supplied as a single positional argument.
pub fn print_server_key(args: Vec<String>) -> ExitCode {
    let path = args
        .into_iter()
        .next()
        .unwrap_or_else(|| "/etc/oxwrt/key.ed25519".to_string());
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("oxctl: read {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    if bytes.len() != 32 {
        eprintln!(
            "oxctl: {path}: expected 32-byte Ed25519 seed, got {} bytes",
            bytes.len()
        );
        return ExitCode::FAILURE;
    }
    let seed: [u8; 32] = bytes.as_slice().try_into().unwrap();
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let verifying = signing.verifying_key();
    println!("{}", hex::encode(verifying.to_bytes()));
    ExitCode::SUCCESS
}

/// Drive the client end-to-end from an argv-style `Vec<String>`.
/// Spins up a current-thread tokio runtime, dials, runs the RPC,
/// returns an exit code suitable for `std::process::ExitCode`.
pub fn run_client_sync(args: Vec<String>) -> ExitCode {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("oxctl: failed to build tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(run(args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("oxctl: client failed: {e}");
            ExitCode::FAILURE
        }
    }
}
