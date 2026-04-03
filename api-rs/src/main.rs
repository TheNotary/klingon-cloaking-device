use arc_swap::ArcSwap;
use std::{
    collections::HashMap,
    env,
    net::IpAddr,
    path::PathBuf,
    sync::Arc,
    time::Instant,
};
use tokio::sync::RwLock;
use tracing::{info, warn};
use rustls::ServerConfig;

mod listeners;
mod crd;
mod netpol;
mod services;
mod sweeper;
mod tls;
mod cloak_watcher;

use listeners::{auth_listener, knock_listener};
use netpol::clean_auth_networkpolicy;
use sweeper::seed_authorized_ips;
use tls::load_tls_config_from_paths;
use cloak_watcher::rebuild_targets_from_list;

/// Maximum number of in-flight knock sequences tracked at once.
pub(crate) const MAX_KNOCK_PROGRESS_ENTRIES: usize = 10_000;

/// Tracks progress of an in-flight knock sequence from a single IP.
pub(crate) struct KnockProgress {
    pub(crate) received: Vec<bool>,
    pub(crate) payloads: Vec<Vec<u8>>,
    pub(crate) created: Instant,
}

/// An IP that has been authorized and added to loadBalancerSourceRanges.
pub(crate) struct AuthorizedIp {
    pub(crate) authorized_at: Instant,
}

pub(crate) struct AppState {
    /// knock_password read from env/secret.
    pub(crate) knock_password: Vec<u8>,
    /// access_password read from env/secret.
    pub(crate) access_password: Vec<u8>,
    /// Target services to patch (namespace, name) pairs, updated by CRD watcher.
    pub(crate) target_services: RwLock<Vec<(String, String)>>,
    /// IP TTL in hours (0 = no expiry).
    pub(crate) ip_ttl_hours: u64,
    /// Hot-swappable TLS configuration, reloaded when cert files change.
    pub(crate) tls_config: ArcSwap<ServerConfig>,
    /// Path to the TLS certificate file.
    pub(crate) cert_path: PathBuf,
    /// Path to the TLS private key file.
    pub(crate) key_path: PathBuf,

    /// Name of the auth NetworkPolicy managed by this operator.
    pub(crate) auth_netpol_name: String,
    /// Namespace where the auth NetworkPolicy lives.
    pub(crate) auth_netpol_namespace: String,
    /// CIDRs that should always be allowed in the auth NetworkPolicy
    /// (e.g. Azure LB health-probe IP, node subnet for kubelet probes).
    pub(crate) health_probe_cidrs: Vec<String>,

    /// In-flight knock sequences: (src_ip, timestamp) → progress.
    pub(crate) knock_progress: RwLock<HashMap<(IpAddr, u64), KnockProgress>>,
    /// IPs that completed the knock and may connect via TCP (30s TTL).
    pub(crate) knocked_ips: RwLock<HashMap<IpAddr, Instant>>,
    /// IPs that have been authorized (patched into Services).
    pub(crate) authorized_ips: RwLock<HashMap<IpAddr, AuthorizedIp>>,
}

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
        env::var("KCD_TLS_CERT_PATH").unwrap_or_else(|_| "/certs/tls.crt".into()),
    );
    let key_path = PathBuf::from(
        env::var("KCD_TLS_KEY_PATH").unwrap_or_else(|_| "/certs/tls.key".into()),
    );

    let auth_netpol_namespace = env::var("KCD_NAMESPACE")
        .expect("KCD_NAMESPACE must be set");
    let auth_netpol_name = env::var("KCD_AUTH_NETPOL_NAME")
        .expect("KCD_AUTH_NETPOL_NAME must be set");

    let health_probe_cidrs: Vec<String> = env::var("KCD_ALWAYS_ALLOWED_CIDRS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if !health_probe_cidrs.is_empty() {
        info!("Health-probe CIDRs configured: {:?} (permanent auth-netpol allow rules)", health_probe_cidrs);
    }

    info!(
        "Klingon Cloaking Device starting: CRD-driven target discovery, IP TTL = {ip_ttl_hours}h"
    );
    info!("TLS cert path: {}", cert_path.display());
    info!("TLS key path: {}", key_path.display());

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
        health_probe_cidrs,
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
        knock_listener::run_knock_listener(state.clone()),
        auth_listener::run_auth_listener(state.clone()),
        sweeper::sweep_knock_state(state.clone()),
        sweeper::sweep_authorized_ips(state.clone()),
        cloak_watcher::watch_cloaking_devices(state.clone()),
        tls::run_cert_watcher(state.clone()),
    );
}
