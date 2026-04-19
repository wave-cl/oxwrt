//! Log streaming + tailing. Split out in step 7.

use super::*;

pub(super) async fn stream_follow_logs(
    state: &ControlState,
    send: &mut quinn::SendStream,
    service: &str,
) -> Result<(), Error> {
    // First replay the last-N buffered lines so the client sees recent
    // context, then subscribe to the live channel for anything new.
    for entry in state.logd.tail(service, LOG_TAIL_LIMIT) {
        let resp = Response::LogLine { line: entry.line };
        write_frame(send, &resp).await?;
    }
    let mut subscription = state.logd.subscribe();
    loop {
        match subscription.recv().await {
            Ok(entry) if entry.service == service => {
                let resp = Response::LogLine { line: entry.line };
                if write_frame(send, &resp).await.is_err() {
                    break;
                }
            }
            Ok(_) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                // Client fell behind; send a marker and keep going.
                let resp = Response::LogLine {
                    line: "[…lagged, some lines dropped…]".to_string(),
                };
                if write_frame(send, &resp).await.is_err() {
                    break;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
    Ok(())
}

const LOG_TAIL_LIMIT: usize = 200;

pub(super) fn handle_logs(state: &ControlState, service: &str, follow: bool) -> Vec<Response> {
    // `follow = true` is special-cased upstream in `handle_incoming` so the
    // bi stream can stay open. This path only services non-follow logs.
    let _ = follow;
    let mut out: Vec<Response> = state
        .logd
        .tail(service, LOG_TAIL_LIMIT)
        .into_iter()
        .map(|l| Response::LogLine { line: l.line })
        .collect();
    out.push(Response::Ok);
    out
}
