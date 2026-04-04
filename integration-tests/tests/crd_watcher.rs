// Integration tests for CRD watcher (create/delete CR → cloak/uncloak Service).
// Implementation: issue #75

mod helpers;

use helpers::mock_k8s::{
    MockK8sState, cloaking_device_list_with, default_service, patches_matching,
};
use helpers::state::TestStateBuilder;

fn install_crypto() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
}

#[tokio::test]
async fn cr_created_cloaks_service() {
    install_crypto();

    // Mock K8s has one CloakingDevice CR pointing to test/my-svc.
    let mock_state = MockK8sState {
        service: default_service("test", "my-svc"),
        cloaking_device_list: cloaking_device_list_with("test", "my-svc"),
        ..Default::default()
    };

    let ctx = TestStateBuilder::new()
        .target_services(vec![]) // start empty — rebuild should discover targets
        .mock_k8s_state(mock_state)
        .build();

    // Call rebuild_targets_from_list — this should discover the CR and cloak the service.
    let count = kcd_server::cloak_watcher::rebuild_targets_from_list(&ctx.state)
        .await
        .expect("rebuild_targets_from_list should succeed");

    assert_eq!(count, 1, "Should discover 1 CloakingDevice CR");

    // Verify target_services was updated.
    let targets = ctx.state.target_services.read().await;
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0], ("test".to_string(), "my-svc".to_string()));
    drop(targets);

    // Verify a PATCH was sent to cloak the service.
    let svc_patches = patches_matching(&ctx.request_log, "/services/");
    assert!(
        !svc_patches.is_empty(),
        "Expected at least 1 Service PATCH to cloak, got 0"
    );

    let patch_body = svc_patches[0].body.as_ref().expect("PATCH should have body");
    let ranges = patch_body["spec"]["loadBalancerSourceRanges"]
        .as_array()
        .expect("Should have loadBalancerSourceRanges");
    let has_sentinel = ranges.iter().any(|r| r.as_str() == Some("255.255.255.255/32"));
    assert!(has_sentinel, "Cloak patch should include sentinel CIDR, got: {ranges:?}");
}

#[tokio::test]
async fn cr_deleted_uncloaks_service() {
    install_crypto();

    // Start with target_services populated (existing CR), but mock K8s returns empty list (CR deleted).
    let ctx = TestStateBuilder::new()
        .target_services(vec![("test".to_string(), "my-svc".to_string())])
        .build();

    // Call rebuild — should see no CRs and uncloak the service.
    let count = kcd_server::cloak_watcher::rebuild_targets_from_list(&ctx.state)
        .await
        .expect("rebuild_targets_from_list should succeed");

    assert_eq!(count, 0, "Should discover 0 CloakingDevice CRs");

    // Verify target_services is now empty.
    let targets = ctx.state.target_services.read().await;
    assert!(targets.is_empty(), "target_services should be empty after CR deletion");
    drop(targets);

    // Verify a PATCH was sent to uncloak (loadBalancerSourceRanges: null).
    let svc_patches = patches_matching(&ctx.request_log, "/services/");
    assert!(
        !svc_patches.is_empty(),
        "Expected at least 1 Service PATCH to uncloak, got 0"
    );

    let patch_body = svc_patches[0].body.as_ref().expect("PATCH should have body");
    let ranges = &patch_body["spec"]["loadBalancerSourceRanges"];
    assert!(
        ranges.is_null(),
        "Uncloak patch should set loadBalancerSourceRanges to null, got: {ranges}"
    );
}
