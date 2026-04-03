use crate::netpol::open_auth_port;
use crate::state::{AppState, KnockProgress, MAX_KNOCK_PROGRESS_ENTRIES};
use kcd_proto::{
    assemble_knock, KnockPacket, KNOCK_WINDOW_SECS, PROTOCOL_VERSION, TCP_ACCEPT_WINDOW_SECS,
};
use std::{
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

pub(crate) async fn run_knock_listener(state: Arc<AppState>) {
    let sock = UdpSocket::bind("0.0.0.0:9000")
        .await
        .expect("Failed to bind UDP :9000");
    info!("UDP knock listener on :9000");

    let mut buf = [0u8; 1500];
    loop {
        let (len, src) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!("UDP recv error: {e}");
                continue;
            }
        };

        let pkt = match KnockPacket::from_bytes(&buf[..len]) {
            Some(p) => p,
            None => {
                debug!("Invalid knock packet from {src}");
                continue;
            }
        };

        if pkt.version != PROTOCOL_VERSION {
            debug!("Wrong protocol version from {src}");
            continue;
        }

        // Replay protection: reject packets with timestamps too far from now.
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now_secs.abs_diff(pkt.timestamp) > KNOCK_WINDOW_SECS {
            debug!("Knock packet from {src} rejected: timestamp too old/future");
            continue;
        }

        let src_ip = src.ip();
        let key = (src_ip, pkt.timestamp);
        let total = pkt.total as usize;

        let mut progress = state.knock_progress.write().await;
        if !progress.contains_key(&key) && progress.len() >= MAX_KNOCK_PROGRESS_ENTRIES {
            debug!(
                "Knock state at capacity ({} entries), dropping new sequence from {}",
                MAX_KNOCK_PROGRESS_ENTRIES,
                src_ip
            );
            continue;
        }

        let entry = progress.entry(key).or_insert_with(|| KnockProgress {
            received: vec![false; total],
            payloads: vec![vec![]; total],
            created: Instant::now(),
        });

        // Validate total matches the existing entry.
        if entry.received.len() != total {
            debug!("Knock packet total mismatch from {src}");
            continue;
        }

        let seq = pkt.seq as usize;
        entry.received[seq] = true;
        entry.payloads[seq] = pkt.payload;

        // Check if all chunks received.
        if entry.received.iter().all(|&r| r) {
            let assembled = assemble_knock(&entry.payloads);
            progress.remove(&key);
            drop(progress);

            // Constant-time comparison of knock password.
            if assembled.ct_eq(&state.knock_password).into() {
                info!("Knock sequence valid from {src_ip} — opening TCP window for {TCP_ACCEPT_WINDOW_SECS}s");
                state
                    .knocked_ips
                    .write()
                    .await
                    .insert(src_ip, Instant::now());

                // Open the auth port in the NetworkPolicy (non-blocking).
                let state_clone = state.clone();
                tokio::spawn(async move {
                    open_auth_port(&state_clone, src_ip).await;
                });
            } else {
                warn!(
                    "Knock sequence from {src_ip}: password mismatch (received {} bytes, expected {} bytes)",
                    assembled.len(),
                    state.knock_password.len(),
                );
            }
        }
    }
}
