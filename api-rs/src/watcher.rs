use crate::crd::CloakingDevice;
use crate::services::{cloak_service, uncloak_service};
use crate::state::AppState;
use futures::StreamExt;
use kube::{runtime::watcher, Api};
use std::{sync::Arc, time::Duration};
use tokio::time;
use tracing::{info, warn};

/// Watch all CloakingDevice CRs cluster-wide and keep the target_services
/// list up to date. Uses kube::runtime::watcher for real-time updates.
/// Handles Apply (cloak), Delete (uncloak), and Init (full-sync) events.
pub(crate) async fn watch_cloaking_devices(state: Arc<AppState>) {
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

        let api: Api<CloakingDevice> = Api::all(client.clone());
        let watcher_config = watcher::Config::default();
        let mut stream = watcher(api, watcher_config).boxed();

        // Buffer used during Init → InitApply* → InitDone sequences.
        let mut init_buffer: Vec<(String, String)> = Vec::new();

        while let Some(result) = futures::StreamExt::next(&mut stream).await {
            match result {
                Ok(watcher::Event::Apply(cr)) => {
                    let ns = cr.metadata.namespace.unwrap_or_default();
                    let svc_name = cr.spec.service_name.clone();
                    let entry = (ns.clone(), svc_name.clone());

                    let mut targets = state.target_services.write().await;
                    if !targets.contains(&entry) {
                        targets.push(entry);
                        info!(
                            "CRD watcher: added target {ns}/{svc_name} ({} total)",
                            targets.len()
                        );
                        drop(targets);
                        cloak_service(&client, &ns, &svc_name, &state.health_probe_cidrs).await;
                    }
                }
                Ok(watcher::Event::Delete(cr)) => {
                    let ns = cr.metadata.namespace.unwrap_or_default();
                    let svc_name = cr.spec.service_name.clone();
                    let entry = (ns.clone(), svc_name.clone());

                    let mut targets = state.target_services.write().await;
                    targets.retain(|t| t != &entry);
                    info!(
                        "CRD watcher: removed target {ns}/{svc_name} ({} remaining)",
                        targets.len()
                    );
                    drop(targets);
                    uncloak_service(&client, &ns, &svc_name).await;
                }
                Ok(watcher::Event::Init) => {
                    init_buffer.clear();
                }
                Ok(watcher::Event::InitApply(cr)) => {
                    let ns = cr.metadata.namespace.unwrap_or_default();
                    let svc_name = cr.spec.service_name.clone();
                    init_buffer.push((ns, svc_name));
                }
                Ok(watcher::Event::InitDone) => {
                    let old_targets = state.target_services.read().await.clone();

                    // Cloak any targets that appeared.
                    for (ns, svc_name) in &init_buffer {
                        if !old_targets.contains(&(ns.clone(), svc_name.clone())) {
                            cloak_service(&client, ns, svc_name, &state.health_probe_cidrs).await;
                        }
                    }
                    // Uncloak any targets that disappeared.
                    for (ns, svc_name) in &old_targets {
                        if !init_buffer.contains(&(ns.clone(), svc_name.clone())) {
                            uncloak_service(&client, ns, svc_name).await;
                        }
                    }

                    let count = init_buffer.len();
                    *state.target_services.write().await = init_buffer.drain(..).collect();
                    info!("CRD watcher: init sync complete ({count} targets)");
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

/// Do a full list of CloakingDevice CRs and replace the target_services vec,
/// cloaking any newly-discovered targets and uncloaking any that disappeared.
pub(crate) async fn rebuild_targets_from_list(state: &AppState) -> Result<usize, kube::Error> {
    let client = kube::Client::try_default().await?;
    let api: Api<CloakingDevice> = Api::all(client.clone());
    let list = api.list(&Default::default()).await?;

    let mut new_targets = Vec::new();
    for ps in &list.items {
        let ns = ps.metadata.namespace.clone().unwrap_or_default();
        let svc_name = ps.spec.service_name.clone();
        new_targets.push((ns, svc_name));
    }

    let old_targets = state.target_services.read().await.clone();

    // Cloak any targets that appeared.
    for (ns, svc_name) in &new_targets {
        if !old_targets.contains(&(ns.clone(), svc_name.clone())) {
            cloak_service(&client, ns, svc_name, &state.health_probe_cidrs).await;
        }
    }
    // Uncloak any targets that disappeared.
    for (ns, svc_name) in &old_targets {
        if !new_targets.contains(&(ns.clone(), svc_name.clone())) {
            uncloak_service(&client, ns, svc_name).await;
        }
    }

    let count = new_targets.len();
    let mut targets = state.target_services.write().await;
    *targets = new_targets;
    Ok(count)
}
