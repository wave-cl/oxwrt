//! oxctl — operator-facing CLI for the oxwrt control plane.
//!
//! The vast majority of invocations are of the form:
//!
//! ```text
//! SQUIC_SERVER_KEY=<hex> oxctl <remote> <cmd> [args...]
//! ```
//!
//! The `--client` flag is also accepted as the first argument for
//! backward compatibility with `oxwrtctl --client <remote> <cmd>`
//! muscle memory — if it's present, it's just stripped.

use std::process::ExitCode;

fn main() -> ExitCode {
    init_tracing();
    let mut args: Vec<String> = std::env::args().skip(1).collect();

    // Drop the leading "--client" if the operator typed it out of
    // habit — the binary is already a client, it's redundant.
    if args.first().map(|s| s.as_str()) == Some("--client") {
        args.remove(0);
    }

    match args.first().map(|s| s.as_str()) {
        Some("--version") => {
            println!("oxctl {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("--help") | Some("-h") | None => {
            print_usage();
            ExitCode::SUCCESS
        }
        Some("--print-server-key") => {
            oxwrtctl_cli::print_server_key(args.into_iter().skip(1).collect())
        }
        // `wizard`: client-local, no sQUIC. Prompts stdin, emits
        // a starter oxwrt.toml. Takes [--out <path>] optionally.
        Some("wizard") => match oxwrtctl_cli::wizard::run(args.into_iter().skip(1).collect()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("oxctl wizard: {e}");
                ExitCode::FAILURE
            }
        },
        // `dump-config`: client-local, no sQUIC. Reads the split
        // pair (public + secrets + env overlay), merges, redacts
        // every secret leaf, and prints the result. Safe to paste
        // into a bug report.
        Some("dump-config") => {
            match oxwrtctl_cli::dump_config::run(args.into_iter().skip(1).collect()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("oxctl dump-config: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        // Anything else: treat args as `<remote> <cmd> [args...]`.
        _ => {
            // `watch` intercepts here (second position — it's
            // `oxctl <remote> watch [inner]`). The watch loop
            // re-issues the inner command on a timer; doing
            // that through run_client_sync would spin up + tear
            // down a tokio runtime every tick, so we handle it
            // inline with its own runtime.
            if args.get(1).map(|s| s.as_str()) == Some("watch") {
                let mut watch_args = Vec::with_capacity(args.len() - 1);
                watch_args.push(args.remove(0)); // remote
                args.remove(0); // "watch"
                watch_args.extend(args);
                return match oxwrtctl_cli::watch::run(watch_args) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => {
                        eprintln!("oxctl watch: {e}");
                        ExitCode::FAILURE
                    }
                };
            }
            oxwrtctl_cli::run_client_sync(args)
        }
    }
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    // Default to warn so the CLI stays quiet; operators can set
    // RUST_LOG=oxwrtctl_cli=debug for verbose output.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}

fn print_usage() {
    eprintln!(
        "usage: oxctl <remote> <cmd> [args...]\n\
                oxctl <remote> watch [--interval N] [cmd args...]\n\
                oxctl wizard [--out <path>]\n\
                oxctl dump-config [--public PATH] [--secrets PATH]\n\
                oxctl --print-server-key [path]\n\
                oxctl --version\n\
                oxctl --help\n\
         \n\
         Environment:\n\
         \n\
           SQUIC_SERVER_KEY  Required. 32-byte hex, the server's ed25519\n\
                             public key. Obtain via `oxctl --print-server-key`\n\
                             on the device, or from UART output on first boot.\n\
           SQUIC_CLIENT_KEY  Optional. Operator's client-side signing key.\n\
         \n\
         Example:\n\
           SQUIC_SERVER_KEY=deadbeef... oxctl 192.168.50.1:51820 status"
    );
}
