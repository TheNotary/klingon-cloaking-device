#![allow(dead_code)]

use http::{Request, Response};
use http_body_util::Full;
use hyper::body::Bytes;
use kube::client::Body;
use serde_json::{json, Value};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tower::Service;

/// A recorded HTTP request made by the kube::Client to the mock K8s API.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub body: Option<Value>,
}

/// Shared request log for assertions.
pub type RequestLog = Arc<Mutex<Vec<RecordedRequest>>>;

/// Handler function type: takes (method, path, body_bytes) and returns (status, json_body).
type HandlerFn = Arc<
    dyn Fn(&str, &str, &[u8]) -> (u16, Value) + Send + Sync,
>;

/// A tower::Service mock that intercepts HTTP requests destined for a K8s API
/// server, records them, and returns configurable responses.
#[derive(Clone)]
pub struct MockK8sService {
    pub requests: RequestLog,
    handler: HandlerFn,
}

impl MockK8sService {
    /// Build a mock from a handler closure.
    ///
    /// The handler receives (method, path, body_bytes) and returns (status_code, json_body).
    /// Use the builder helpers below for common scenarios.
    pub fn new<F>(handler: F) -> Self
    where
        F: Fn(&str, &str, &[u8]) -> (u16, Value) + Send + Sync + 'static,
    {
        Self {
            requests: Arc::new(Mutex::new(Vec::new())),
            handler: Arc::new(handler),
        }
    }

    /// Build a `kube::Client` backed by this mock service.
    pub fn into_client(self) -> (kube::Client, RequestLog) {
        let log = self.requests.clone();
        let client = kube::Client::new(self, "default");
        (client, log)
    }
}

impl Service<Request<Body>> for MockK8sService {
    type Response = Response<Full<Bytes>>;
    type Error = std::convert::Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let method = req.method().to_string();
        let path = req.uri().path_and_query().map(|pq| pq.to_string()).unwrap_or_default();
        let handler = self.handler.clone();
        let requests = self.requests.clone();

        Box::pin(async move {
            // Collect the request body.
            let body_bytes = {
                use http_body_util::BodyExt;
                let collected = req.into_body().collect().await.unwrap();
                collected.to_bytes().to_vec()
            };

            // Parse body as JSON if non-empty.
            let body_json = if body_bytes.is_empty() {
                None
            } else {
                serde_json::from_slice(&body_bytes).ok()
            };

            // Record the request.
            requests.lock().unwrap().push(RecordedRequest {
                method: method.clone(),
                path: path.clone(),
                body: body_json,
            });

            // Call the handler to get the response.
            let (status, response_body) = handler(&method, &path, &body_bytes);

            let response = Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(serde_json::to_vec(&response_body).unwrap())))
                .unwrap();

            Ok(response)
        })
    }
}

/// Create a handler for common integration test scenarios.
///
/// Handles:
/// - GET/PATCH NetworkPolicy
/// - GET/PATCH Service
/// - GET CloakingDevice list
///
/// The `state` parameter holds mutable JSON state for services and network policies.
pub fn default_handler(mock_state: Arc<Mutex<MockK8sState>>) -> impl Fn(&str, &str, &[u8]) -> (u16, Value) + Send + Sync + 'static {
    move |method, path, body| {
        let mut state = mock_state.lock().unwrap();

        // NetworkPolicy GET
        if method == "GET" && path.contains("/networkpolicies/") {
            return (200, state.network_policy.clone());
        }

        // NetworkPolicy PATCH
        if method == "PATCH" && path.contains("/networkpolicies/") {
            if let Ok(patch) = serde_json::from_slice::<Value>(body) {
                merge_json(&mut state.network_policy, &patch);
            }
            return (200, state.network_policy.clone());
        }

        // Service GET
        if method == "GET" && path.contains("/services/") && !path.contains("?") {
            return (200, state.service.clone());
        }

        // Service PATCH
        if method == "PATCH" && path.contains("/services/") {
            if let Ok(patch) = serde_json::from_slice::<Value>(body) {
                merge_json(&mut state.service, &patch);
            }
            return (200, state.service.clone());
        }

        // CloakingDevice list
        if method == "GET" && path.contains("/cloakingdevices") {
            return (200, state.cloaking_device_list.clone());
        }

        // Fallback 404
        (404, json!({"kind": "Status", "apiVersion": "v1", "status": "Failure", "message": format!("not found: {} {}", method, path), "code": 404}))
    }
}

/// Mutable K8s state that the mock handler reads/writes.
pub struct MockK8sState {
    pub network_policy: Value,
    pub service: Value,
    pub cloaking_device_list: Value,
}

impl Default for MockK8sState {
    fn default() -> Self {
        Self {
            network_policy: default_network_policy(),
            service: default_service("default", "my-svc"),
            cloaking_device_list: empty_cloaking_device_list(),
        }
    }
}

/// Empty NetworkPolicy with no ingress rules.
pub fn default_network_policy() -> Value {
    json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": "kcd-auth",
            "namespace": "default"
        },
        "spec": {
            "ingress": []
        }
    })
}

/// Service with the cloak sentinel in loadBalancerSourceRanges.
pub fn default_service(ns: &str, name: &str) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": name,
            "namespace": ns
        },
        "spec": {
            "type": "LoadBalancer",
            "loadBalancerSourceRanges": ["255.255.255.255/32"]
        }
    })
}

/// Empty CloakingDevice list.
pub fn empty_cloaking_device_list() -> Value {
    json!({
        "apiVersion": "klingon-cloaking-device.thenotary.github.io/v1alpha1",
        "kind": "CloakingDeviceList",
        "metadata": { "resourceVersion": "1" },
        "items": []
    })
}

/// CloakingDevice list with one entry.
pub fn cloaking_device_list_with(ns: &str, svc_name: &str) -> Value {
    json!({
        "apiVersion": "klingon-cloaking-device.thenotary.github.io/v1alpha1",
        "kind": "CloakingDeviceList",
        "metadata": { "resourceVersion": "1" },
        "items": [{
            "apiVersion": "klingon-cloaking-device.thenotary.github.io/v1alpha1",
            "kind": "CloakingDevice",
            "metadata": {
                "name": format!("{svc_name}-cd"),
                "namespace": ns,
                "resourceVersion": "1"
            },
            "spec": {
                "serviceName": svc_name
            }
        }]
    })
}

/// Simple JSON merge (RFC 7386-style): recursively merge patch into target.
fn merge_json(target: &mut Value, patch: &Value) {
    match (target, patch) {
        (Value::Object(t), Value::Object(p)) => {
            for (k, v) in p {
                if v.is_null() {
                    t.remove(k);
                } else {
                    let entry = t.entry(k.clone()).or_insert(Value::Null);
                    merge_json(entry, v);
                }
            }
        }
        (target, patch) => {
            *target = patch.clone();
        }
    }
}

/// Helper to extract PATCH requests from the log.
pub fn patches(log: &RequestLog) -> Vec<RecordedRequest> {
    log.lock()
        .unwrap()
        .iter()
        .filter(|r| r.method == "PATCH")
        .cloned()
        .collect()
}

/// Helper to extract PATCH requests to a specific path pattern.
pub fn patches_matching(log: &RequestLog, pattern: &str) -> Vec<RecordedRequest> {
    log.lock()
        .unwrap()
        .iter()
        .filter(|r| r.method == "PATCH" && r.path.contains(pattern))
        .cloned()
        .collect()
}
