use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Spec for a CloakingDevice custom resource.
///
/// The CR's namespace determines which namespace the target Service lives in.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "klingon-cloaking-device.thenotary.github.io",
    version = "v1alpha1",
    kind = "CloakingDevice",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct CloakingDeviceSpec {
    /// Name of the Kubernetes Service to protect.
    pub service_name: String,
    /// Hours before an authorized IP is removed. 0 disables expiry.
    #[serde(default = "default_ttl_hours")]
    pub ttl_hours: Option<u32>,
}

fn default_ttl_hours() -> Option<u32> {
    Some(24)
}

#[cfg(test)]
mod tests {
    use super::CloakingDeviceSpec;

    #[test]
    fn crd_spec_deserializes() {
        let json = serde_json::json!({
            "serviceName": "my-svc",
            "ttlHours": 12
        });
        let spec: CloakingDeviceSpec = serde_json::from_value(json).unwrap();
        assert_eq!(spec.service_name, "my-svc");
        assert_eq!(spec.ttl_hours, Some(12));
    }

    #[test]
    fn crd_spec_default_ttl() {
        let json = serde_json::json!({
            "serviceName": "my-svc"
        });
        let spec: CloakingDeviceSpec = serde_json::from_value(json).unwrap();
        assert_eq!(spec.service_name, "my-svc");
        assert_eq!(spec.ttl_hours, Some(24));
    }
}
