# Plain Kubernetes Manifests

## Install

```bash
# Download all manifests
curl -sL https://github.com/thenotary/klingon-cloaking-device/archive/refs/heads/main.tar.gz \
  | tar xz --strip-components=2 '*/klingon-cloaking-device/plain_k8s_manifests'

# Edit secrets
vi plain_k8s_manifests/secrets.yaml

# Apply
kubectl apply -f plain_k8s_manifests/
```

## Files

| File | Description |
|------|-------------|
| `namespace.yaml` | Creates the `klingon-cloaking-device` namespace |
| `crd.yaml` | CloakingDevice custom resource definition |
| `serviceaccount.yaml` | Service account (update workload identity annotation) |
| `clusterrole.yaml` | RBAC for patching services and watching CRDs |
| `clusterrolebinding.yaml` | Binds the ClusterRole to the ServiceAccount |
| `deployment.yaml` | Server deployment (update image reference) |
| `service.yaml` | LoadBalancer service (UDP 9000 + TCP 9001) |
| `networkpolicy.yaml` | Restricts ingress/egress traffic |
| `secrets.yaml` | Knock and access passwords (edit before applying) |
