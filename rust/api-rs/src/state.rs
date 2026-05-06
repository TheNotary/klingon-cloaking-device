use arc_swap::ArcSwap;
use std::{
    collections::HashMap,
    net::IpAddr,
    path::PathBuf,
    time::Instant,
};
use tokio::sync::RwLock;
use rustls::ServerConfig;

/// Maximum number of in-flight knock sequences tracked at once.
pub const MAX_KNOCK_PROGRESS_ENTRIES: usize = 10_000;

/// Tracks progress of an in-flight knock sequence from a single IP.
pub struct KnockProgress {
    pub received: Vec<bool>,
    pub payloads: Vec<Vec<u8>>,
    pub created: Instant,
}

/// An IP that has been authorized and added to loadBalancerSourceRanges.
pub struct AuthorizedIp {
    pub authorized_at: Instant,
}

pub struct AppState {
    /// Shared Kubernetes API client, injected once at startup.
    pub kube_client: kube::Client,
    /// knock_password read from env/secret.
    pub knock_password: Vec<u8>,
    /// access_password read from env/secret.
    pub access_password: Vec<u8>,
    /// Target services to patch (namespace, name) pairs, updated by CRD watcher.
    pub target_services: RwLock<Vec<(String, String)>>,
    /// IP TTL in hours (0 = no expiry).
    pub ip_ttl_hours: u64,
    /// Hot-swappable TLS configuration, reloaded when cert files change.
    pub tls_config: ArcSwap<ServerConfig>,
    /// Path to the TLS certificate file.
    pub cert_path: PathBuf,
    /// Path to the TLS private key file.
    pub key_path: PathBuf,

    /// Name of the auth NetworkPolicy managed by this operator.
    pub auth_netpol_name: String,
    /// Namespace where the auth NetworkPolicy lives.
    pub auth_netpol_namespace: String,
    /// CIDRs that should always be allowed in the auth NetworkPolicy
    /// (e.g. Azure LB health-probe IP, node subnet for kubelet probes).
    pub health_probe_cidrs: Vec<String>,

    /// In-flight knock sequences: (src_ip, timestamp) → progress.
    pub knock_progress: RwLock<HashMap<(IpAddr, u64), KnockProgress>>,
    /// IPs that completed the knock and may connect via TCP (30s TTL).
    pub knocked_ips: RwLock<HashMap<IpAddr, Instant>>,
    /// IPs that have been authorized (patched into Services).
    pub authorized_ips: RwLock<HashMap<IpAddr, AuthorizedIp>>,

    /// Bind address for the UDP knock listener (e.g. "0.0.0.0:9000").
    pub knock_bind_addr: String,
    /// Bind address for the TCP/TLS auth listener (e.g. "0.0.0.0:9001").
    pub auth_bind_addr: String,
    /// Bind address for the internal health probe listener (e.g. "0.0.0.0:9002").
    pub health_bind_addr: String,
}
