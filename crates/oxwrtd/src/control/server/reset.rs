//! Factory reset. Split out in step 7.

use super::*;

pub(super) async fn handle_reset(state: &std::sync::Arc<ControlState>, confirm: bool) -> Response {
    use crate::config;

    if !confirm {
        return Response::Err {
            message: "reset: refusing to reset without confirm=true".to_string(),
        };
    }

    // Snapshot the current control block so it survives the reset.
    // Without this the new config would have empty `listen` and the
    // operator would lose the management path the moment the reload
    // tears down the old listener.
    let cfg_arc = state.config_snapshot();
    let preserved_control = cfg_arc.control.clone();
    let default_text = crate::control::default_config_text(&preserved_control);

    // Sanity: the text we just generated must round-trip into a Config
    // before we touch the disk. If this fails it's a bug in
    // `default_config_text` — better to catch it here than to leave the
    // operator with an unparseable file on disk.
    if let Err(e) = toml::from_str::<config::Config>(&default_text) {
        tracing::error!(error = %e, "BUG: default_config_text produced invalid TOML");
        return Response::Err {
            message: format!("reset: refusing to write invalid default config: {e}"),
        };
    }

    if let Err(e) = atomic_write_config(&default_text) {
        return Response::Err {
            message: format!("reset: {e}"),
        };
    }

    tracing::warn!("factory reset: config wiped to defaults");

    // Reuse the existing reload path — it re-reads from disk, reconciles
    // network state, reinstalls the firewall, swaps the supervisor, and
    // republishes the in-memory config snapshot. If reload fails, the
    // on-disk default config is still in place and a future Reload will
    // pick it up; we report the underlying error.
    handle_reload_async(state).await
}
