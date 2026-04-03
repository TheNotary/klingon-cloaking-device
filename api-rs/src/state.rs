use arc_swap::ArcSwap;
use rustls::ServerConfig;
use std::{
    collections::HashMap,
    net::IpAddr,
    path::PathBuf,
    time::Instant,
};
use tokio::sync::RwLock;

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
