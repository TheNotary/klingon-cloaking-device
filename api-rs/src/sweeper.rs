use crate::netpol::close_auth_port;
use crate::services::{remove_ip_from_services, CLOAK_SENTINEL_CIDR};
use crate::{AppState, AuthorizedIp};
use k8s_openapi::api::core::v1::Service;
use kcd_proto::{KNOCK_WINDOW_SECS, TCP_ACCEPT_WINDOW_SECS};
use kube::Api;
use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::time;
use tracing::{info, warn};

/// Sweep stale knock progress and expired knocked IPs.
pub(crate) async fn sweep_knock_state(state: Arc<AppState>) {
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
pub(crate) async fn sweep_authorized_ips(state: Arc<AppState>) {
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
            remove_ip_from_services(&client, &targets, *ip, &state.health_probe_cidrs).await;
            drop(targets);
            state.authorized_ips.write().await.remove(ip);
        }
    }
}

/// On startup, read existing loadBalancerSourceRanges from target services
/// and seed the authorized_ips map so TTL tracking works across restarts.
pub(crate) async fn seed_authorized_ips(state: &AppState) {
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
                        // Skip baseline CIDRs — they are not real authorized
                        // IPs and should not be subject to TTL expiry.
                        if cidr == CLOAK_SENTINEL_CIDR
                            || state.health_probe_cidrs.contains(cidr)
                        {
                            continue;
                        }
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
