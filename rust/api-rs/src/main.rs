use arc_swap::ArcSwap;
use std::{
    collections::HashMap,
    env,
    path::PathBuf,
    sync::Arc,
};
use tokio::sync::RwLock;
use tracing::{info, warn};

use kcd_server::{
    AppState,
    listeners::{auth_listener, health_listener, knock_listener},
    netpol::clean_auth_networkpolicy,
    sweeper::{self, seed_authorized_ips},
    tls::{self, load_tls_config_from_paths},
    cloak_watcher::{self, rebuild_targets_from_list},
};

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

    let kube_client = kube::Client::try_default()
        .await
        .expect("Failed to create Kubernetes client");

    let state = Arc::new(AppState {
        kube_client,
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
        knock_bind_addr: format!("0.0.0.0:{}", env::var("KCD_KNOCK_PORT").unwrap_or_else(|_| "9000".into())),
        auth_bind_addr: format!("0.0.0.0:{}", env::var("KCD_AUTH_PORT").unwrap_or_else(|_| "9001".into())),
        health_bind_addr: format!("0.0.0.0:{}", env::var("KCD_HEALTH_PORT").unwrap_or_else(|_| "9002".into())),
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
        knock_listener::run_knock_listener(state.clone(), None),
        auth_listener::run_auth_listener(state.clone(), None),
        health_listener::run_health_listener(state.clone()),
        sweeper::sweep_knock_state(state.clone()),
        sweeper::sweep_authorized_ips(state.clone()),
        cloak_watcher::watch_cloaking_devices(state.clone()),
        tls::run_cert_watcher(state.clone()),
    );
}
