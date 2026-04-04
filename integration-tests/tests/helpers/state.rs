use arc_swap::ArcSwap;
use kcd_server::{AppState, tls::load_tls_config_from_paths};
use std::{
    collections::HashMap,
    sync::Arc,
};
use tokio::sync::RwLock;

use super::mock_k8s::{MockK8sService, MockK8sState, RequestLog, default_handler};
use super::tls::{TestTlsCerts, generate_test_certs};

/// Builder for constructing an `AppState` suitable for integration tests.
pub struct TestStateBuilder {
    knock_password: Vec<u8>,
    access_password: Vec<u8>,
    target_services: Vec<(String, String)>,
    ip_ttl_hours: u64,
    auth_netpol_name: String,
    auth_netpol_namespace: String,
    health_probe_cidrs: Vec<String>,
    mock_state: Arc<std::sync::Mutex<MockK8sState>>,
}

/// The assembled test context returned by the builder.
pub struct TestContext {
    pub state: Arc<AppState>,
    pub request_log: RequestLog,
    pub tls_certs: TestTlsCerts,
    pub mock_k8s_state: Arc<std::sync::Mutex<MockK8sState>>,
}

impl Default for TestStateBuilder {
    fn default() -> Self {
        Self {
            knock_password: b"test-knock-secret".to_vec(),
            access_password: b"test-access-secret".to_vec(),
            target_services: vec![("default".to_string(), "my-svc".to_string())],
            ip_ttl_hours: 24,
            auth_netpol_name: "kcd-auth".to_string(),
            auth_netpol_namespace: "default".to_string(),
            health_probe_cidrs: Vec::new(),
            mock_state: Arc::new(std::sync::Mutex::new(MockK8sState::default())),
        }
    }
}

impl TestStateBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn knock_password(mut self, pw: &[u8]) -> Self {
        self.knock_password = pw.to_vec();
        self
    }

    pub fn access_password(mut self, pw: &[u8]) -> Self {
        self.access_password = pw.to_vec();
        self
    }

    pub fn target_services(mut self, targets: Vec<(String, String)>) -> Self {
        self.target_services = targets;
        self
    }

    pub fn ip_ttl_hours(mut self, hours: u64) -> Self {
        self.ip_ttl_hours = hours;
        self
    }

    pub fn health_probe_cidrs(mut self, cidrs: Vec<String>) -> Self {
        self.health_probe_cidrs = cidrs;
        self
    }

    pub fn mock_k8s_state(mut self, state: MockK8sState) -> Self {
        self.mock_state = Arc::new(std::sync::Mutex::new(state));
        self
    }

    /// Build the test context with an `AppState` using a mock K8s client.
    pub fn build(self) -> TestContext {
        let tls_certs = generate_test_certs();

        let tls_config = load_tls_config_from_paths(
            tls_certs.cert_file.path(),
            tls_certs.key_file.path(),
        )
        .expect("Failed to load test TLS config");

        let mock_svc = MockK8sService::new(default_handler(self.mock_state.clone()));
        let (kube_client, request_log) = mock_svc.into_client();

        let state = Arc::new(AppState {
            kube_client,
            knock_password: self.knock_password,
            access_password: self.access_password,
            target_services: RwLock::new(self.target_services),
            ip_ttl_hours: self.ip_ttl_hours,
            tls_config: ArcSwap::from(tls_config),
            cert_path: tls_certs.cert_file.path().to_path_buf(),
            key_path: tls_certs.key_file.path().to_path_buf(),
            auth_netpol_name: self.auth_netpol_name,
            auth_netpol_namespace: self.auth_netpol_namespace,
            health_probe_cidrs: self.health_probe_cidrs,
            knock_progress: RwLock::new(HashMap::new()),
            knocked_ips: RwLock::new(HashMap::new()),
            authorized_ips: RwLock::new(HashMap::new()),
            knock_bind_addr: "127.0.0.1:0".to_string(),
            auth_bind_addr: "127.0.0.1:0".to_string(),
        });

        TestContext {
            state,
            request_log,
            tls_certs,
            mock_k8s_state: self.mock_state,
        }
    }
}
