use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, trace, warn};

use crate::AppState;

/// Minimal TCP health listener for kubelet probes.
///
/// Accepts connections and immediately closes them (tcpSocket probe only
/// needs a successful TCP handshake). No TLS, no auth, no logging above
/// trace level — keeping probe traffic out of application logs.
pub async fn run_health_listener(state: Arc<AppState>) {
    let listener = TcpListener::bind(&state.health_bind_addr)
        .await
        .unwrap_or_else(|e| panic!("Failed to bind health TCP {}: {e}", state.health_bind_addr));
    let local_addr = listener.local_addr().expect("Failed to get local health address");
    info!("Health probe listener on {local_addr}");

    loop {
        match listener.accept().await {
            Ok((_stream, _src)) => {
                trace!("Health probe from {_src}");
                // Drop the stream immediately — tcpSocket probe only needs the handshake.
            }
            Err(e) => {
                warn!("Health accept error: {e}");
            }
        }
    }
}
