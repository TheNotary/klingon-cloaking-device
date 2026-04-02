use futures::StreamExt;
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::networking::v1::NetworkPolicy;
use kcd_proto::{
    assemble_knock, KnockPacket, KNOCK_WINDOW_SECS, PROTOCOL_VERSION, TCP_ACCEPT_WINDOW_SECS,
};
use kube::{
    api::{Patch, PatchParams},
    runtime::watcher,
    runtime::WatchStreamExt,
    Api,
};
use arc_swap::ArcSwap;
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde_json::json;
use std::{
    collections::HashMap,
    env,
    fs,
    io::BufReader,
    net::IpAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader},
    net::{TcpListener, UdpSocket},
    sync::RwLock,
    time,
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

mod crd;
use crd::CloakingDevice;

/// Maximum number of in-flight knock sequences tracked at once.
const MAX_KNOCK_PROGRESS_ENTRIES: usize = 10_000;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Tracks progress of an in-flight knock sequence from a single IP.
struct KnockProgress {
    received: Vec<bool>,
    payloads: Vec<Vec<u8>>,
    created: Instant,
}

/// An IP that has been authorized and added to loadBalancerSourceRanges.
struct AuthorizedIp {
    authorized_at: Instant,
}

struct AppState {
    /// knock_password read from env/secret.
    knock_password: Vec<u8>,
    /// access_password read from env/secret.
    access_password: Vec<u8>,
    /// Target services to patch (namespace, name) pairs, updated by CRD watcher.
    target_services: RwLock<Vec<(String, String)>>,
    /// IP TTL in hours (0 = no expiry).
    ip_ttl_hours: u64,
    /// Hot-swappable TLS configuration, reloaded when cert files change.
    tls_config: ArcSwap<ServerConfig>,
    /// Path to the TLS certificate file.
    cert_path: PathBuf,
    /// Path to the TLS private key file.
    key_path: PathBuf,

    /// Name of the auth NetworkPolicy managed by this operator.
    auth_netpol_name: String,
    /// Namespace where the auth NetworkPolicy lives.
    auth_netpol_namespace: String,

    /// In-flight knock sequences: (src_ip, timestamp) → progress.
    knock_progress: RwLock<HashMap<(IpAddr, u64), KnockProgress>>,
    /// IPs that completed the knock and may connect via TCP (30s TTL).
    knocked_ips: RwLock<HashMap<IpAddr, Instant>>,
    /// IPs that have been authorized (patched into Services).
    authorized_ips: RwLock<HashMap<IpAddr, AuthorizedIp>>,
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

fn load_tls_config_from_paths(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error>> {
    let cert_file = std::fs::File::open(cert_path)?;
    let key_file = std::fs::File::open(key_path)?;

    let certs_chain: Vec<_> = certs(&mut BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()?;
    let private_key = pkcs8_private_keys(&mut BufReader::new(key_file))
        .next()
        .ok_or("No PKCS8 private key found in PEM file")??;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs_chain, private_key.into())?;

    Ok(Arc::new(config))
}

// ---------------------------------------------------------------------------
// UDP Knock Listener
// ---------------------------------------------------------------------------

async fn run_knock_listener(state: Arc<AppState>) {
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

// ---------------------------------------------------------------------------
// TCP/TLS Auth Listener
// ---------------------------------------------------------------------------

async fn run_auth_listener(state: Arc<AppState>) {
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

// ---------------------------------------------------------------------------
// K8s Service Patcher
// ---------------------------------------------------------------------------

async fn patch_services(state: &AppState, ip: IpAddr) -> Result<(), kube::Error> {
    let client = kube::Client::try_default().await?;
    let cidr = format!("{ip}/32");
    let targets = state.target_services.read().await;

    for (ns, name) in targets.iter() {
        let api: Api<Service> = Api::namespaced(client.clone(), ns);
        let svc = api.get(name).await?;

        let existing: Vec<String> = svc
            .spec
            .as_ref()
            .and_then(|s| s.load_balancer_source_ranges.as_ref())
            .cloned()
            .unwrap_or_default();

        if existing.contains(&cidr) {
            info!("IP {cidr} already in {ns}/{name} loadBalancerSourceRanges — skipping");
            continue;
        }

        let mut updated = existing;
        updated.push(cidr.clone());

        let patch = json!({
            "spec": {
                "loadBalancerSourceRanges": updated
            }
        });

        api.patch(name, &PatchParams::default(), &Patch::Merge(patch))
            .await?;

        info!("Patched {ns}/{name}: added {cidr} to loadBalancerSourceRanges");
    }

    // Track for TTL expiry.
    state.authorized_ips.write().await.insert(
        ip,
        AuthorizedIp {
            authorized_at: Instant::now(),
        },
    );

    Ok(())
}

async fn remove_ip_from_services(client: &kube::Client, targets: &[(String, String)], ip: IpAddr) {
    let cidr = format!("{ip}/32");

    for (ns, name) in targets {
        let api: Api<Service> = Api::namespaced(client.clone(), ns);
        let svc = match api.get(name).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to get {ns}/{name} for IP removal: {e}");
                continue;
            }
        };

        let existing: Vec<String> = svc
            .spec
            .as_ref()
            .and_then(|s| s.load_balancer_source_ranges.as_ref())
            .cloned()
            .unwrap_or_default();

        if !existing.contains(&cidr) {
            continue;
        }

        let updated: Vec<String> = existing.into_iter().filter(|r| r != &cidr).collect();

        let patch = if updated.is_empty() {
            // Remove the field entirely to restore open access.
            json!({ "spec": { "loadBalancerSourceRanges": null } })
        } else {
            json!({ "spec": { "loadBalancerSourceRanges": updated } })
        };

        match api
            .patch(name, &PatchParams::default(), &Patch::Merge(patch))
            .await
        {
            Ok(_) => info!("Removed {cidr} from {ns}/{name} loadBalancerSourceRanges"),
            Err(e) => warn!("Failed to remove {cidr} from {ns}/{name}: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Auth NetworkPolicy Management
// ---------------------------------------------------------------------------

/// Open TCP 9001 in the auth NetworkPolicy for the given IP.
async fn open_auth_port(state: &AppState, ip: IpAddr) {
    let client = match kube::Client::try_default().await {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to create K8s client for open_auth_port: {e}");
            return;
        }
    };

    let cidr = format!("{ip}/32");
    let api: Api<NetworkPolicy> = Api::namespaced(client, &state.auth_netpol_namespace);

    let np = match api.get(&state.auth_netpol_name).await {
        Ok(np) => np,
        Err(e) => {
            warn!("Failed to get auth NetworkPolicy {}: {e}", state.auth_netpol_name);
            return;
        }
    };

    // Collect existing ipBlock CIDRs from the first ingress rule (if any).
    let mut from_blocks: Vec<serde_json::Value> = Vec::new();
    if let Some(spec) = &np.spec {
        if let Some(ingress_rules) = &spec.ingress {
            if let Some(rule) = ingress_rules.first() {
                if let Some(from) = &rule.from {
                    for peer in from {
                        if let Some(ip_block) = &peer.ip_block {
                            if ip_block.cidr == cidr {
                                info!("IP {cidr} already in auth NetworkPolicy — skipping");
                                return;
                            }
                            from_blocks.push(json!({ "ipBlock": { "cidr": ip_block.cidr } }));
                        }
                    }
                }
            }
        }
    }

    from_blocks.push(json!({ "ipBlock": { "cidr": cidr } }));

    let patch = json!({
        "spec": {
            "ingress": [{
                "from": from_blocks,
                "ports": [{ "port": 9001, "protocol": "TCP" }]
            }]
        }
    });

    match api
        .patch(
            &state.auth_netpol_name,
            &PatchParams::default(),
            &Patch::Merge(patch),
        )
        .await
    {
        Ok(_) => info!("Opened auth port for {cidr} in NetworkPolicy"),
        Err(e) => warn!("Failed to patch auth NetworkPolicy for {cidr}: {e}"),
    }
}

/// Close TCP 9001 in the auth NetworkPolicy for the given IP.
async fn close_auth_port(state: &AppState, ip: IpAddr) {
    let client = match kube::Client::try_default().await {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to create K8s client for close_auth_port: {e}");
            return;
        }
    };

    let cidr = format!("{ip}/32");
    let api: Api<NetworkPolicy> = Api::namespaced(client, &state.auth_netpol_namespace);

    let np = match api.get(&state.auth_netpol_name).await {
        Ok(np) => np,
        Err(e) => {
            warn!("Failed to get auth NetworkPolicy {}: {e}", state.auth_netpol_name);
            return;
        }
    };

    // Collect existing ipBlock CIDRs, filtering out the one being removed.
    let mut from_blocks: Vec<serde_json::Value> = Vec::new();
    if let Some(spec) = &np.spec {
        if let Some(ingress_rules) = &spec.ingress {
            if let Some(rule) = ingress_rules.first() {
                if let Some(from) = &rule.from {
                    for peer in from {
                        if let Some(ip_block) = &peer.ip_block {
                            if ip_block.cidr != cidr {
                                from_blocks.push(json!({ "ipBlock": { "cidr": ip_block.cidr } }));
                            }
                        }
                    }
                }
            }
        }
    }

    let patch = if from_blocks.is_empty() {
        json!({ "spec": { "ingress": [] } })
    } else {
        json!({
            "spec": {
                "ingress": [{
                    "from": from_blocks,
                    "ports": [{ "port": 9001, "protocol": "TCP" }]
                }]
            }
        })
    };

    match api
        .patch(
            &state.auth_netpol_name,
            &PatchParams::default(),
            &Patch::Merge(patch),
        )
        .await
    {
        Ok(_) => info!("Closed auth port for {cidr} in NetworkPolicy"),
        Err(e) => warn!("Failed to remove {cidr} from auth NetworkPolicy: {e}"),
    }
}

/// Reset the auth NetworkPolicy to empty ingress (used on startup for crash recovery).
async fn clean_auth_networkpolicy(state: &AppState) {
    let client = match kube::Client::try_default().await {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to create K8s client for auth NP cleanup: {e}");
            return;
        }
    };

    let api: Api<NetworkPolicy> = Api::namespaced(client, &state.auth_netpol_namespace);
    let patch = json!({ "spec": { "ingress": [] } });

    match api
        .patch(
            &state.auth_netpol_name,
            &PatchParams::default(),
            &Patch::Merge(patch),
        )
        .await
    {
        Ok(_) => info!("Auth NetworkPolicy cleaned on startup (empty ingress)"),
        Err(e) => warn!("Failed to clean auth NetworkPolicy on startup: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Background Sweepers
// ---------------------------------------------------------------------------

/// Sweep stale knock progress and expired knocked IPs.
async fn sweep_knock_state(state: Arc<AppState>) {
    let mut interval = time::interval(Duration::from_secs(5));
    loop {
        interval.tick().await;

        // Remove stale knock progress (older than KNOCK_WINDOW_SECS).
        {
            let mut progress = state.knock_progress.write().await;
            progress
                .retain(|_, v| v.created.elapsed() < Duration::from_secs(KNOCK_WINDOW_SECS * 2));
        }

        // Remove expired knocked IPs (older than TCP_ACCEPT_WINDOW_SECS)
        // and close their auth port in the NetworkPolicy.
        {
            let mut knocked = state.knocked_ips.write().await;
            let expired: Vec<IpAddr> = knocked
                .iter()
                .filter(|(_, when)| when.elapsed() >= Duration::from_secs(TCP_ACCEPT_WINDOW_SECS))
                .map(|(ip, _)| *ip)
                .collect();
            for ip in &expired {
                knocked.remove(ip);
            }
            drop(knocked);
            for ip in expired {
                close_auth_port(&state, ip).await;
            }
        }
    }
}

/// Periodically remove expired authorized IPs from target Services.
async fn sweep_authorized_ips(state: Arc<AppState>) {
    if state.ip_ttl_hours == 0 {
        info!("IP TTL is 0 — authorized IPs never expire");
        return;
    }

    let ttl = Duration::from_secs(state.ip_ttl_hours * 3600);
    let mut interval = time::interval(Duration::from_secs(300)); // Check every 5 minutes.

    loop {
        interval.tick().await;

        let expired: Vec<IpAddr> = {
            let ips = state.authorized_ips.read().await;
            ips.iter()
                .filter(|(_, auth)| auth.authorized_at.elapsed() >= ttl)
                .map(|(ip, _)| *ip)
                .collect()
        };

        if expired.is_empty() {
            continue;
        }

        let client = match kube::Client::try_default().await {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to create K8s client for IP sweep: {e}");
                continue;
            }
        };

        for ip in &expired {
            info!("IP {ip} TTL expired — removing from target services");
            let targets = state.target_services.read().await;
            remove_ip_from_services(&client, &targets, *ip).await;
            drop(targets);
            state.authorized_ips.write().await.remove(ip);
        }
    }
}

/// On startup, read existing loadBalancerSourceRanges from target services
/// and seed the authorized_ips map so TTL tracking works across restarts.
async fn seed_authorized_ips(state: &AppState) {
    let client = match kube::Client::try_default().await {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to create K8s client for seeding authorized IPs: {e}");
            return;
        }
    };

    let targets = state.target_services.read().await;
    for (ns, name) in targets.iter() {
        let api: Api<Service> = Api::namespaced(client.clone(), ns);
        match api.get(name).await {
            Ok(svc) => {
                if let Some(ranges) = svc
                    .spec
                    .as_ref()
                    .and_then(|s| s.load_balancer_source_ranges.as_ref())
                {
                    for cidr in ranges {
                        if let Some(ip_str) = cidr.strip_suffix("/32") {
                            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                                info!("Seeded authorized IP {ip} from {ns}/{name} (will expire after full TTL cycle)");
                                state.authorized_ips.write().await.insert(
                                    ip,
                                    AuthorizedIp {
                                        authorized_at: Instant::now(),
                                    },
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => warn!("Failed to read {ns}/{name} for IP seeding: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// CRD Watcher
// ---------------------------------------------------------------------------

/// Watch all CloakingDevice CRs cluster-wide and keep the target_services
/// list up to date. Uses kube::runtime::watcher for real-time updates.
async fn watch_cloaking_devices(state: Arc<AppState>) {
    info!("Starting CloakingDevice CRD watcher");

    loop {
        // (Re-)create the watcher on each iteration for restart resilience.
        let client = match kube::Client::try_default().await {
            Ok(c) => c,
            Err(e) => {
                warn!("CRD watcher: failed to create K8s client: {e}");
                time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        let api: Api<CloakingDevice> = Api::all(client);
        let watcher_config = watcher::Config::default();
        let mut stream = watcher(api, watcher_config).applied_objects().boxed();

        while let Some(result) = futures::StreamExt::next(&mut stream).await {
            match result {
                Ok(ps) => {
                    let ns = ps.metadata.namespace.unwrap_or_default();
                    let svc_name = ps.spec.service_name.clone();
                    let entry = (ns.clone(), svc_name.clone());

                    let mut targets = state.target_services.write().await;
                    if !targets.contains(&entry) {
                        targets.push(entry);
                        info!(
                            "CRD watcher: added target {ns}/{svc_name} ({} total)",
                            targets.len()
                        );
                    }
                }
                Err(e) => {
                    warn!("CRD watcher stream error: {e} — restarting watcher");
                    break;
                }
            }
        }

        // If we get here the stream ended or errored; rebuild the full list
        // from a fresh list call before re-entering the watch loop.
        match rebuild_targets_from_list(&state).await {
            Ok(count) => info!("CRD watcher: rebuilt target list from API ({count} targets)"),
            Err(e) => warn!("CRD watcher: failed to rebuild target list: {e}"),
        }

        time::sleep(Duration::from_secs(5)).await;
    }
}

/// Do a full list of CloakingDevice CRs and replace the target_services vec.
async fn rebuild_targets_from_list(state: &AppState) -> Result<usize, kube::Error> {
    let client = kube::Client::try_default().await?;
    let api: Api<CloakingDevice> = Api::all(client);
    let list = api.list(&Default::default()).await?;

    let mut new_targets = Vec::new();
    for ps in &list.items {
        let ns = ps.metadata.namespace.clone().unwrap_or_default();
        let svc_name = ps.spec.service_name.clone();
        new_targets.push((ns, svc_name));
    }

    let count = new_targets.len();
    let mut targets = state.target_services.write().await;
    *targets = new_targets;
    Ok(count)
}

// ---------------------------------------------------------------------------
// TLS Certificate Hot-Reload
// ---------------------------------------------------------------------------

/// Poll cert/key files for changes and reload TLS config when modified.
/// Uses mtime polling because inotify is unreliable on volume-mounted Secrets
/// (kubelet uses symlink swaps that don't always trigger MODIFY events).
async fn run_cert_watcher(state: Arc<AppState>) {
    let mut interval = time::interval(Duration::from_secs(30));
    let mut last_mtime: Option<(SystemTime, SystemTime)> = None;

    // Seed with initial mtimes.
    if let (Ok(cert_meta), Ok(key_meta)) = (
        fs::metadata(&state.cert_path),
        fs::metadata(&state.key_path),
    ) {
        last_mtime = Some((
            cert_meta.modified().unwrap_or(UNIX_EPOCH),
            key_meta.modified().unwrap_or(UNIX_EPOCH),
        ));
    }

    info!("TLS cert watcher started (polling every 30s)");

    loop {
        interval.tick().await;

        let (cert_meta, key_meta) = match (
            fs::metadata(&state.cert_path),
            fs::metadata(&state.key_path),
        ) {
            (Ok(c), Ok(k)) => (c, k),
            _ => continue,
        };

        let current_mtime = (
            cert_meta.modified().unwrap_or(UNIX_EPOCH),
            key_meta.modified().unwrap_or(UNIX_EPOCH),
        );

        if last_mtime.as_ref() == Some(&current_mtime) {
            continue;
        }

        // Debounce: wait for both files to stabilize.
        time::sleep(Duration::from_secs(1)).await;

        match load_tls_config_from_paths(&state.cert_path, &state.key_path) {
            Ok(new_config) => {
                state.tls_config.store(new_config);
                last_mtime = Some(current_mtime);
                info!("TLS certificate reloaded successfully");
            }
            Err(e) => {
                warn!("TLS certificate reload failed (keeping old config): {e}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    // Install ring as the default crypto provider before any TLS operations.
    // Required because kube's rustls-tls feature also enables aws-lc-rs,
    // so rustls can't auto-detect which provider to use.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let knock_password = env::var("KCD_KNOCK_PASSWORD")
        .expect("KCD_KNOCK_PASSWORD must be set")
        .into_bytes();
    let access_password = env::var("KCD_ACCESS_PASSWORD")
        .expect("KCD_ACCESS_PASSWORD must be set")
        .into_bytes();
    if knock_password.is_empty() {
        panic!("KCD_KNOCK_PASSWORD must not be empty");
    }
    if access_password.is_empty() {
        panic!("KCD_ACCESS_PASSWORD must not be empty");
    }

    let ip_ttl_hours: u64 = env::var("KCD_IP_TTL_HOURS")
        .unwrap_or_else(|_| "24".into())
        .parse()
        .expect("KCD_IP_TTL_HOURS must be a non-negative integer");
    if ip_ttl_hours > 24 * 365 {
        warn!(
            "KCD_IP_TTL_HOURS is set to {}h (over 1 year); verify this is intentional",
            ip_ttl_hours
        );
    }

    let cert_path = PathBuf::from(
        env::var("KCD_TLS_CERT_PATH").unwrap_or_else(|_| "/mnt/secrets-store/kcd-tls-cert".into()),
    );
    let key_path = PathBuf::from(
        env::var("KCD_TLS_KEY_PATH").unwrap_or_else(|_| "/mnt/secrets-store/kcd-tls-key".into()),
    );

    let auth_netpol_namespace = env::var("KCD_NAMESPACE")
        .expect("KCD_NAMESPACE must be set");
    let auth_netpol_name = env::var("KCD_AUTH_NETPOL_NAME")
        .expect("KCD_AUTH_NETPOL_NAME must be set");

    info!(
        "Klingon Cloaking Device starting: CRD-driven target discovery, IP TTL = {ip_ttl_hours}h"
    );

    let tls_config = load_tls_config_from_paths(&cert_path, &key_path)
        .unwrap_or_else(|e| panic!("Failed to load initial TLS config: {e}"));

    let state = Arc::new(AppState {
        knock_password,
        access_password,
        target_services: RwLock::new(Vec::new()),
        ip_ttl_hours,
        tls_config: ArcSwap::from(tls_config),
        cert_path,
        key_path,
        auth_netpol_name,
        auth_netpol_namespace,
        knock_progress: RwLock::new(HashMap::new()),
        knocked_ips: RwLock::new(HashMap::new()),
        authorized_ips: RwLock::new(HashMap::new()),
    });

    // Do an initial list to populate targets before starting listeners.
    match rebuild_targets_from_list(&state).await {
        Ok(count) => {
            info!("Initial target discovery: {count} CloakingDevice CR(s) found");
            let targets = state.target_services.read().await;
            for (ns, name) in targets.iter() {
                info!("  Target: {ns}/{name}");
            }
        }
        Err(e) => {
            warn!("Initial CRD list failed (will retry via watcher): {e}");
        }
    }

    // Seed authorized IPs from existing Service state.
    seed_authorized_ips(&state).await;

    // Clean stale auth NetworkPolicy entries from previous crashes.
    clean_auth_networkpolicy(&state).await;

    // Launch all tasks concurrently.
    tokio::join!(
        run_knock_listener(state.clone()),
        run_auth_listener(state.clone()),
        sweep_knock_state(state.clone()),
        sweep_authorized_ips(state.clone()),
        watch_cloaking_devices(state.clone()),
        run_cert_watcher(state.clone()),
    );
}

#[cfg(test)]
mod tests {
    use super::crd::CloakingDeviceSpec;
    use super::load_tls_config_from_paths;
    use std::io::Write;

    #[test]
    fn crd_spec_deserializes() {
        let json = serde_json::json!({
            "serviceName": "my-svc",
            "ttlHours": 12
        });
        let spec: CloakingDeviceSpec = serde_json::from_value(json).unwrap();
        assert_eq!(spec.service_name, "my-svc");
        assert_eq!(spec.ttl_hours, Some(12));
    }

    #[test]
    fn crd_spec_default_ttl() {
        let json = serde_json::json!({
            "serviceName": "my-svc"
        });
        let spec: CloakingDeviceSpec = serde_json::from_value(json).unwrap();
        assert_eq!(spec.service_name, "my-svc");
        assert_eq!(spec.ttl_hours, Some(24));
    }

    #[test]
    fn load_tls_config_with_valid_pem() {
        // Install ring provider for test context.
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Generate a self-signed cert+key using rcgen.
        let subject_alt_names = vec!["localhost".to_string()];
        let cert = rcgen::generate_simple_self_signed(subject_alt_names).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("tls.crt");
        let key_path = dir.path().join("tls.key");
        std::fs::File::create(&cert_path)
            .unwrap()
            .write_all(cert_pem.as_bytes())
            .unwrap();
        std::fs::File::create(&key_path)
            .unwrap()
            .write_all(key_pem.as_bytes())
            .unwrap();

        let config = load_tls_config_from_paths(&cert_path, &key_path);
        assert!(config.is_ok(), "Expected valid TLS config, got: {:?}", config.err());
    }

    #[test]
    fn load_tls_config_with_invalid_pem_returns_error() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("tls.crt");
        let key_path = dir.path().join("tls.key");
        std::fs::write(&cert_path, b"not a cert").unwrap();
        std::fs::write(&key_path, b"not a key").unwrap();

        let config = load_tls_config_from_paths(&cert_path, &key_path);
        assert!(config.is_err());
    }

    #[test]
    fn load_tls_config_with_missing_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("nonexistent.crt");
        let key_path = dir.path().join("nonexistent.key");

        let config = load_tls_config_from_paths(&cert_path, &key_path);
        assert!(config.is_err());
    }
}
