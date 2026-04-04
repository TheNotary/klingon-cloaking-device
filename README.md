# Klingon Cloaking Device (KCD)

With Klingon Cloaking Device, you can hide k8s services deployed behind an external load balancer from scanners. The cloaking device restricts access via `loadBalancerSourceRanges` on target services — only IPs that complete a port-knock sequence and TLS authentication are whitelisted.

## Quick Start — Hide an SSH Service

### 1. Install the Klingon Cloaking Device Helm chart into your Cluster

Generate a self-signed TLS certificate for the Quick Start (production deployments should use cert-manager or a real certificate — see [TLS Configuration](#tls-configuration)):

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout tls.key -out tls.crt -days 365 -nodes -subj "/CN=klingon-cloaking-device"
```

Install with inline TLS:

```bash
helm install kcd oci://ghcr.io/thenotary/charts/klingon-cloaking-device \
  --set secrets.knockPassword="my-knock-secret" \
  --set secrets.accessPassword="my-access-secret" \
  --set tls.mode=inline \
  --set tls.inline.crt="$(base64 -w0 < tls.crt)" \
  --set tls.inline.key="$(base64 -w0 < tls.key)"
```

### 2. Deploy the test SSH service

```bash
kubectl apply -f integration_test/ssh-server.yaml
```

### 3. Apply the CloakingDevice CR

```bash
kubectl apply -f integration_test/cloakingdevice.yaml
```

### 4. Verify the SSH banner is no longer reachable

```bash
SSH_IP=$(kubectl get svc ssh-server -n kcd-integration-test \
  -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

# This should time out — the service is cloaked
ssh-keyscan -p 22 -T 5 "$SSH_IP"
```

### 5. Install the CLI

Download the latest binary from [GitHub Releases](https://github.com/thenotary/klingon-cloaking-device/releases):

```bash
# Linux (amd64)
curl -Lo kcd https://github.com/thenotary/klingon-cloaking-device/releases/latest/download/kcd-linux-amd64
chmod +x kcd
sudo mv kcd /usr/local/bin/
```

Or build from source: `cd rust/cli-rs && cargo build --release`

### 6. Authorize your IP

```bash
KCD_IP=$(kubectl get svc klingon-cloaking-device -n klingon-cloaking-device \
  -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

KNOCK_PW=$(kubectl get secret klingon-cloaking-device-credentials \
  -n klingon-cloaking-device -o jsonpath='{.data.kcd-knock-password}' | base64 -d)

ACCESS_PW=$(kubectl get secret klingon-cloaking-device-credentials \
  -n klingon-cloaking-device -o jsonpath='{.data.kcd-access-password}' | base64 -d)

kcd authorize \
  --server "$KCD_IP" \
  --knock-password "$KNOCK_PW" \
  --access-password "$ACCESS_PW" \
  --insecure
```

### 7. Verify the SSH banner is reachable again

```bash
# This should now return the SSH banner
ssh-keyscan -p 22 -T 5 "$SSH_IP"
```

---

## Docker

```bash
# Build the container image
docker build -t klingon-cloaking-device-server -f Dockerfile .

# Run locally (for testing — needs K8s API access)
docker run --rm \
  -e KCD_KNOCK_PASSWORD=my-knock-secret \
  -e KCD_ACCESS_PASSWORD=my-access-secret \
  -e KCD_TLS_CERT_PATH=/certs/tls.crt \
  -e KCD_TLS_KEY_PATH=/certs/tls.key \
  -v /path/to/certs:/certs:ro \
  -p 9000:9000/udp -p 9001:9001 \
  klingon-cloaking-device-server
```

## Build & Test

This is a Cargo workspace with four crates (under `rust/`):

| Crate | Description |
|---|---|
| `api-rs` | K8s operator server (binary + `kcd_server` library) |
| `cli-rs` | CLI client binary |
| `kcd-proto` | Shared knock protocol types |
| `integration-tests` | Integration tests with mock K8s API |

```bash
# Build all crates
cd rust
cargo build --workspace

# Run all tests (unit + integration)
cargo test --workspace

# Run only integration tests
cargo test -p integration-tests
```

## Release

```bash
git tag v0.1.0
git push origin v0.1.0
```

Pushing a semver tag triggers the GitHub Actions workflow which builds and publishes the container image and Helm chart to GHCR.

- Chart: `oci://ghcr.io/TheNotary/charts`
- Container: `ghcr.io/TheNotary/klingon-cloaking-device-server:<version>`

## TLS Configuration

The server requires a TLS certificate and private key. The Helm chart supports three modes via `tls.mode`.

### Option A: cert-manager (recommended)

If [cert-manager](https://cert-manager.io) is installed in your cluster, set `tls.mode=certManager` and the chart will create a `Certificate` CR. cert-manager provisions the cert and stores it in a Kubernetes Secret automatically.

```bash
helm install kcd oci://ghcr.io/thenotary/charts/klingon-cloaking-device \
  --set secrets.knockPassword="my-knock-secret" \
  --set secrets.accessPassword="my-access-secret" \
  --set tls.mode=certManager \
  --set tls.certManager.issuerName=letsencrypt-prod \
  --set tls.certManager.issuerKind=ClusterIssuer
```

### Option B: Existing Kubernetes TLS Secret

Reference a pre-existing `kubernetes.io/tls` Secret:

```bash
helm install kcd oci://ghcr.io/thenotary/charts/klingon-cloaking-device \
  --set secrets.knockPassword="my-knock-secret" \
  --set secrets.accessPassword="my-access-secret" \
  --set tls.mode=secret \
  --set tls.secret.name=my-existing-tls-secret
```

### Option C: Inline certificate

Provide base64-encoded PEM certificate chain and private key directly:

```bash
helm install kcd oci://ghcr.io/thenotary/charts/klingon-cloaking-device \
  --set secrets.knockPassword="my-knock-secret" \
  --set secrets.accessPassword="my-access-secret" \
  --set tls.mode=inline \
  --set tls.inline.crt="$(base64 -w0 < tls.crt)" \
  --set tls.inline.key="$(base64 -w0 < tls.key)"
```

### Certificate Hot-Reload

The server automatically detects when certificate files change on disk (e.g. after cert-manager renewal or Secret rotation) and reloads the TLS configuration without a pod restart. File changes are detected via polling every 30 seconds.

---

## Components

| Directory | Description |
|-----------|-------------|
| [helm_chart/](helm_chart/README.md) | Helm chart for deploying into a Kubernetes cluster |
| [plain_k8s_manifests/](plain_k8s_manifests/README.md) | YAML manifests for manual deployment |
| [rust/api-rs/](rust/api-rs/README.md)     | Server binary (`klingon-cloaking-device-server`) |
| [rust/cli-rs/](rust/cli-rs/README.md)     | CLI binary (`klingon-cloaking-device`) |
| [integration_test/](integration_test/README.md) | SSH service and CloakingDevice CR for testing |
