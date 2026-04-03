use crate::netpol::close_auth_port;
use crate::services::patch_services;
use crate::AppState;
use kcd_proto::TCP_ACCEPT_WINDOW_SECS;
use std::{sync::Arc, time::Duration};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader},
    net::TcpListener,
    time,
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

pub(crate) async fn run_auth_listener(state: Arc<AppState>) {
    let listener = TcpListener::bind("0.0.0.0:9001")
        .await
        .expect("Failed to bind TCP :9001");
    info!("TLS auth listener on :9001");

    loop {
        let (stream, src) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("TCP accept error: {e}");
                continue;
            }
        };

        let src_ip = src.ip();

        // Check if this IP completed the knock sequence within the window.
        {
            let knocked = state.knocked_ips.read().await;
            match knocked.get(&src_ip) {
                Some(when) if when.elapsed() < Duration::from_secs(TCP_ACCEPT_WINDOW_SECS) => {}
                _ => {
                    debug!("TCP connection from {src_ip} rejected: no valid knock");
                    drop(stream);
                    continue;
                }
            }
        }

        // Build a TlsAcceptor from the current (possibly reloaded) config.
        let acceptor = TlsAcceptor::from(state.tls_config.load_full());
        let state = state.clone();

        tokio::spawn(async move {
            // Remove from knocked set (one-time use).
            state.knocked_ips.write().await.remove(&src_ip);

            // Revoke NetworkPolicy access now that the knock is consumed.
            close_auth_port(&state, src_ip).await;

            let tls_stream =
                match time::timeout(Duration::from_secs(10), acceptor.accept(stream)).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        warn!("TLS handshake failed from {src_ip}: {e}");
                        return;
                    }
                    Err(_) => {
                        warn!("TLS handshake timeout from {src_ip}");
                        return;
                    }
                };

            let (reader, mut writer) = tokio::io::split(tls_stream);
            let mut reader = TokioBufReader::new(reader);

            if writer.write_all(b"Ready\n").await.is_err() {
                return;
            }

            let mut password_line = String::new();
            match time::timeout(
                Duration::from_secs(10),
                reader.read_line(&mut password_line),
            )
            .await
            {
                Ok(Ok(0)) | Err(_) => {
                    warn!("Auth timeout or disconnect from {src_ip}");
                    return;
                }
                Ok(Err(e)) => {
                    warn!("Read error from {src_ip}: {e}");
                    return;
                }
                Ok(Ok(_)) => {}
            }

            let password_bytes = password_line.trim_end().as_bytes();

            if password_bytes.ct_eq(&state.access_password).into() {
                info!("Access password valid from {src_ip} — patching services");
                match patch_services(&state, src_ip).await {
                    Ok(()) => {
                        let _ = writer.write_all(b"AUTHORIZED\n").await;
                        info!("AUTHORIZED {src_ip}");
                    }
                    Err(e) => {
                        error!("Failed to patch services for {src_ip}: {e}");
                        let _ = writer.write_all(b"ERROR\n").await;
                    }
                }
            } else {
                warn!("Access password mismatch from {src_ip}");
                let _ = writer.write_all(b"DENIED\n").await;
            }
        });
    }
}
