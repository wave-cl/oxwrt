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
    let rest: Vec<String> = it.collect();

    let addr: SocketAddr = remote.parse().map_err(|_| Error::Address(remote.clone()))?;

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
    if let (Request::FwUpdate { size, .. }, Some(path)) =
        (&request, &fw_image_path)
    {
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
                    if let Some(Request::FwUpdate { size, .. }) = fw_image_path.as_ref().and(Some(&request)) {
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
