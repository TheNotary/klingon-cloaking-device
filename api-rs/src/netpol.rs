use crate::state::AppState;
use k8s_openapi::api::networking::v1::NetworkPolicy;
use kube::{
    api::{Patch, PatchParams},
    Api,
};
use serde_json::json;
use std::net::IpAddr;
use tracing::{info, warn};

/// Open TCP 9001 in the auth NetworkPolicy for the given IP.
pub(crate) async fn open_auth_port(state: &AppState, ip: IpAddr) {
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
pub(crate) async fn close_auth_port(state: &AppState, ip: IpAddr) {
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
        // No client IPs left — restore baseline with health-probe CIDRs if configured.
        if state.health_probe_cidrs.is_empty() {
            json!({ "spec": { "ingress": [] } })
        } else {
            let probe_blocks: Vec<serde_json::Value> = state.health_probe_cidrs.iter()
                .map(|c| json!({ "ipBlock": { "cidr": c } }))
                .collect();
            json!({
                "spec": {
                    "ingress": [{
                        "from": probe_blocks,
                        "ports": [{ "port": 9001, "protocol": "TCP" }]
                    }]
                }
            })
        }
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
pub(crate) async fn clean_auth_networkpolicy(state: &AppState) {
    let client = match kube::Client::try_default().await {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to create K8s client for auth NP cleanup: {e}");
            return;
        }
    };

    let api: Api<NetworkPolicy> = Api::namespaced(client, &state.auth_netpol_namespace);
    let patch = if state.health_probe_cidrs.is_empty() {
        json!({ "spec": { "ingress": [] } })
    } else {
        let probe_blocks: Vec<serde_json::Value> = state.health_probe_cidrs.iter()
            .map(|c| json!({ "ipBlock": { "cidr": c } }))
            .collect();
        json!({
            "spec": {
                "ingress": [{
                    "from": probe_blocks,
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
        Ok(_) => info!("Auth NetworkPolicy cleaned on startup (empty ingress)"),
        Err(e) => warn!("Failed to clean auth NetworkPolicy on startup: {e}"),
    }
}
