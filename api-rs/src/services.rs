use crate::{AppState, AuthorizedIp};
use k8s_openapi::api::core::v1::Service;
use kube::{
    api::{Patch, PatchParams},
    Api,
};
use serde_json::json;
use std::{net::IpAddr, time::Instant};
use tracing::{info, warn};

/// Sentinel CIDR used to block all traffic through a LoadBalancer while still
/// keeping the `loadBalancerSourceRanges` field populated. No real client will
/// have this source IP, so the allowlist effectively denies everything.
pub const CLOAK_SENTINEL_CIDR: &str = "255.255.255.255/32";

pub async fn patch_services(state: &AppState, ip: IpAddr) -> Result<(), kube::Error> {
    let client = state.kube_client.clone();
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

pub async fn remove_ip_from_services(
    client: &kube::Client,
    targets: &[(String, String)],
    ip: IpAddr,
    health_probe_cidrs: &[String],
) {
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
            // Last authorized IP removed — restore cloaked baseline so the
            // service stays protected while the CR still exists.
            let mut baseline = vec![CLOAK_SENTINEL_CIDR.to_string()];
            baseline.extend(health_probe_cidrs.iter().cloned());
            json!({ "spec": { "loadBalancerSourceRanges": baseline } })
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

/// Set a Service's `loadBalancerSourceRanges` to the cloaked baseline:
/// the deny-all sentinel plus any always-allowed CIDRs (health probes, etc.).
pub async fn cloak_service(
    client: &kube::Client,
    ns: &str,
    svc_name: &str,
    health_probe_cidrs: &[String],
) {
    let mut baseline = vec![CLOAK_SENTINEL_CIDR.to_string()];
    baseline.extend(health_probe_cidrs.iter().cloned());

    let api: Api<Service> = Api::namespaced(client.clone(), ns);
    let patch = json!({
        "spec": {
            "loadBalancerSourceRanges": baseline
        }
    });

    match api
        .patch(svc_name, &PatchParams::default(), &Patch::Merge(patch))
        .await
    {
        Ok(_) => info!("Cloaked {ns}/{svc_name}: set loadBalancerSourceRanges to baseline"),
        Err(e) => warn!("Failed to cloak {ns}/{svc_name}: {e}"),
    }
}

/// Remove `loadBalancerSourceRanges` from a Service entirely, restoring open
/// connectivity. Used when a CloakingDevice CR is deleted.
pub async fn uncloak_service(client: &kube::Client, ns: &str, svc_name: &str) {
    let api: Api<Service> = Api::namespaced(client.clone(), ns);
    let patch = json!({ "spec": { "loadBalancerSourceRanges": null } });

    match api
        .patch(svc_name, &PatchParams::default(), &Patch::Merge(patch))
        .await
    {
        Ok(_) => info!("Uncloaked {ns}/{svc_name}: removed loadBalancerSourceRanges"),
        Err(e) => warn!("Failed to uncloak {ns}/{svc_name}: {e}"),
    }
}
