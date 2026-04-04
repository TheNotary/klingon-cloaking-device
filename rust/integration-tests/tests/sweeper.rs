// Integration tests for the IP TTL sweeper (expiry → IP removal from Services).

mod helpers;

use helpers::mock_k8s::{MockK8sState, patches_matching};
use helpers::state::TestStateBuilder;
use kcd_server::AuthorizedIp;
use std::net::IpAddr;
use std::time::{Duration, Instant};

fn install_crypto() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
}

#[tokio::test]
async fn expired_ip_removed() {
    install_crypto();

    // Service has the sentinel + an authorized IP.
    let mock_state = MockK8sState {
        service: serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "my-svc", "namespace": "default" },
            "spec": {
                "type": "LoadBalancer",
                "loadBalancerSourceRanges": ["255.255.255.255/32", "1.2.3.4/32"]
            }
        }),
        ..Default::default()
    };

    let ctx = TestStateBuilder::new()
        .ip_ttl_hours(1) // 1 hour TTL
        .mock_k8s_state(mock_state)
        .build();

    // Pre-populate authorized_ips with an IP that's already expired (authorized 2 hours ago).
    let ip: IpAddr = "1.2.3.4".parse().unwrap();
    ctx.state.authorized_ips.write().await.insert(
        ip,
        AuthorizedIp {
            authorized_at: Instant::now() - Duration::from_secs(7200), // 2 hours ago
        },
    );

    // Run one sweep iteration.
    kcd_server::sweeper::sweep_authorized_ips_once(&ctx.state).await;

    // Verify the IP was removed from authorized_ips.
    let authorized = ctx.state.authorized_ips.read().await;
    assert!(
        !authorized.contains_key(&ip),
        "1.2.3.4 should have been removed from authorized_ips"
    );
    drop(authorized);

    // Verify a PATCH was sent to remove the IP from the Service.
    let svc_patches = patches_matching(&ctx.request_log, "/services/");
    assert!(
        !svc_patches.is_empty(),
        "Expected at least 1 Service PATCH to remove expired IP"
    );

    let patch_body = svc_patches[0].body.as_ref().expect("PATCH should have body");
    let ranges = patch_body["spec"]["loadBalancerSourceRanges"]
        .as_array()
        .expect("Should have loadBalancerSourceRanges");

    // Should still have the sentinel but NOT 1.2.3.4/32.
    let has_sentinel = ranges.iter().any(|r| r.as_str() == Some("255.255.255.255/32"));
    let has_expired = ranges.iter().any(|r| r.as_str() == Some("1.2.3.4/32"));
    assert!(has_sentinel, "Should keep sentinel CIDR, got: {ranges:?}");
    assert!(!has_expired, "Should have removed 1.2.3.4/32, got: {ranges:?}");
}

#[tokio::test]
async fn unexpired_ip_not_removed() {
    install_crypto();

    let ctx = TestStateBuilder::new()
        .ip_ttl_hours(24) // 24 hour TTL
        .build();

    // Pre-populate with an IP that was just authorized.
    let ip: IpAddr = "5.6.7.8".parse().unwrap();
    ctx.state.authorized_ips.write().await.insert(
        ip,
        AuthorizedIp {
            authorized_at: Instant::now(), // just now
        },
    );

    // Run sweep — should NOT remove anything.
    kcd_server::sweeper::sweep_authorized_ips_once(&ctx.state).await;

    // IP should still be there.
    let authorized = ctx.state.authorized_ips.read().await;
    assert!(
        authorized.contains_key(&ip),
        "5.6.7.8 should still be in authorized_ips (not expired)"
    );

    // No Service patches should have been made.
    let svc_patches = patches_matching(&ctx.request_log, "/services/");
    assert!(
        svc_patches.is_empty(),
        "Expected zero Service patches for unexpired IP, got {}",
        svc_patches.len()
    );
}
