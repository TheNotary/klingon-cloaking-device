// Integration tests for the authorize flow (knock + TLS auth → K8s patches).

mod helpers;

use helpers::mock_k8s::patches_matching;
use helpers::state::TestStateBuilder;
use kcd_proto::{split_knock, KnockPacket, PROTOCOL_VERSION};
use rustls::pki_types::ServerName;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::UdpSocket;
use tokio::time::sleep;

fn install_crypto() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
}

fn build_insecure_tls_config() -> Arc<rustls::ClientConfig> {
    #[derive(Debug)]
    struct InsecureVerifier;
    impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
        .with_no_client_auth();
    Arc::new(config)
}

/// Send the knock sequence via UDP and return the timestamp used.
async fn send_knock(
    server_addr: std::net::SocketAddr,
    password: &[u8],
    chunks: u8,
) -> u64 {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let parts = split_knock(password, chunks);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    for (i, chunk) in parts.iter().enumerate() {
        let pkt = KnockPacket {
            version: PROTOCOL_VERSION,
            seq: i as u8,
            total: chunks,
            timestamp,
            payload: chunk.clone(),
        };
        sock.send_to(&pkt.to_bytes(), server_addr).await.unwrap();
        if i + 1 < parts.len() {
            sleep(Duration::from_millis(50)).await;
        }
    }
    timestamp
}

/// Connect via TLS and send the access password. Returns the server's response line.
async fn tls_auth(
    server_addr: std::net::SocketAddr,
    access_password: &str,
) -> String {
    let tls_config = build_insecure_tls_config();
    let connector = tokio_rustls::TlsConnector::from(tls_config);
    let server_name = ServerName::try_from("127.0.0.1".to_string()).unwrap();

    let tcp = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let tls = connector.connect(server_name, tcp).await.unwrap();

    let (reader, mut writer) = tokio::io::split(tls);
    let mut reader = TokioBufReader::new(reader);

    // Read "Ready\n"
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert_eq!(line.trim(), "Ready");

    // Send access password
    writer
        .write_all(format!("{access_password}\n").as_bytes())
        .await
        .unwrap();

    // Read result
    let mut result = String::new();
    reader.read_line(&mut result).await.unwrap();
    result.trim().to_string()
}

/// Start the knock and auth listeners on ephemeral ports and return their bound addresses.
async fn start_listeners(
    state: Arc<kcd_server::AppState>,
) -> (std::net::SocketAddr, std::net::SocketAddr) {
    let (knock_tx, knock_rx) = tokio::sync::oneshot::channel();
    let (auth_tx, auth_rx) = tokio::sync::oneshot::channel();

    let s1 = state.clone();
    tokio::spawn(async move {
        kcd_server::listeners::knock_listener::run_knock_listener(s1, Some(knock_tx)).await;
    });

    let s2 = state.clone();
    tokio::spawn(async move {
        kcd_server::listeners::auth_listener::run_auth_listener(s2, Some(auth_tx)).await;
    });

    let knock_addr = knock_rx.await.unwrap();
    let auth_addr = auth_rx.await.unwrap();
    (knock_addr, auth_addr)
}

#[tokio::test]
async fn happy_path() {
    install_crypto();

    let ctx = TestStateBuilder::new().build();
    let (knock_addr, auth_addr) = start_listeners(ctx.state.clone()).await;

    // Phase 1: Send correct knock sequence.
    send_knock(knock_addr, b"test-knock-secret", 4).await;

    // Wait for the knock to be processed and NetworkPolicy to be patched.
    sleep(Duration::from_millis(500)).await;

    // Phase 2: TLS auth with correct password.
    let result = tls_auth(auth_addr, "test-access-secret").await;
    assert_eq!(result, "AUTHORIZED");

    // Wait for async K8s operations to complete.
    sleep(Duration::from_millis(500)).await;

    // Verify K8s API calls.
    let netpol_patches = patches_matching(&ctx.request_log, "/networkpolicies/");
    let svc_patches = patches_matching(&ctx.request_log, "/services/");

    // Should have at least 1 netpol patch (open) and 1 service patch, and 1 netpol patch (close).
    assert!(
        netpol_patches.len() >= 2,
        "Expected at least 2 NetworkPolicy patches (open + close), got {}",
        netpol_patches.len()
    );
    assert!(
        !svc_patches.is_empty(),
        "Expected at least 1 Service patch, got 0"
    );

    // Verify the Service patch added the IP.
    let svc_patch_body = svc_patches[0].body.as_ref().expect("Service patch should have body");
    let ranges = svc_patch_body["spec"]["loadBalancerSourceRanges"]
        .as_array()
        .expect("Should have loadBalancerSourceRanges array");
    let has_loopback = ranges.iter().any(|r| r.as_str() == Some("127.0.0.1/32"));
    assert!(has_loopback, "Service patch should include 127.0.0.1/32, got: {ranges:?}");

    // Verify the IP was tracked in authorized_ips.
    let authorized = ctx.state.authorized_ips.read().await;
    let loopback: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    assert!(
        authorized.contains_key(&loopback),
        "127.0.0.1 should be in authorized_ips"
    );
}

#[tokio::test]
async fn bad_knock_password() {
    install_crypto();

    let ctx = TestStateBuilder::new().build();
    let (knock_addr, _auth_addr) = start_listeners(ctx.state.clone()).await;

    // Send wrong knock password.
    send_knock(knock_addr, b"wrong-password", 4).await;

    // Wait for processing.
    sleep(Duration::from_millis(500)).await;

    // No K8s patches should have been made.
    let all_patches = helpers::mock_k8s::patches(&ctx.request_log);
    assert!(
        all_patches.is_empty(),
        "Expected zero K8s PATCH calls after bad knock, got {}",
        all_patches.len()
    );

    // The knocked_ips should be empty.
    let knocked = ctx.state.knocked_ips.read().await;
    assert!(knocked.is_empty(), "No IPs should be in knocked_ips after bad knock");
}

#[tokio::test]
async fn bad_access_password() {
    install_crypto();

    let ctx = TestStateBuilder::new().build();
    let (knock_addr, auth_addr) = start_listeners(ctx.state.clone()).await;

    // Phase 1: Send correct knock.
    send_knock(knock_addr, b"test-knock-secret", 4).await;
    sleep(Duration::from_millis(500)).await;

    // Phase 2: TLS auth with wrong password.
    let result = tls_auth(auth_addr, "wrong-access-password").await;
    assert_eq!(result, "DENIED");

    // Wait for async operations.
    sleep(Duration::from_millis(500)).await;

    // Should have NetworkPolicy patches (open + close) but NO Service patches.
    let netpol_patches = patches_matching(&ctx.request_log, "/networkpolicies/");
    let svc_patches = patches_matching(&ctx.request_log, "/services/");

    assert!(
        netpol_patches.len() >= 2,
        "Expected at least 2 NetworkPolicy patches (open + close), got {}",
        netpol_patches.len()
    );
    assert!(
        svc_patches.is_empty(),
        "Expected zero Service patches after bad access password, got {}",
        svc_patches.len()
    );

    // No IP should be authorized.
    let authorized = ctx.state.authorized_ips.read().await;
    assert!(authorized.is_empty(), "No IPs should be authorized after bad password");
}
