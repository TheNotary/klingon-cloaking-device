# Klingon Cloaking Device (KCD)

With Klingon Cloaking Device, you can hide k8s services deployed behind an external load balancer from scanners. The cloaking device restricts access via `loadBalancerSourceRanges` on target services — only IPs that complete a port-knock sequence and TLS authentication are whitelisted.

## Usage Summary

Create a cloakingdevice.yaml CR to cloak a service in your k8s cluster.

(`cloakingdevice.yaml`)
```yaml
apiVersion: klingon-cloaking-device.thenotary.github.io/v1alpha1
kind: CloakingDevice
metadata:
  name: ssh-server
  namespace: kcd-integration-test
spec:
  serviceName: ssh-server # name of service to cloak
  ttlHours: 0 # how long to whitelist an IP (0 = no expiration)
```

Run `kubectl explain cloakingdevice` for more details.

## Directory Structure

```bash
├── Dockerfile              # Builds the server container image
│
├── docs/                   # Architecture diagrams and design docs
│
├── helm_chart/             # Helm chart for deploying into a Kubernetes cluster
│
├── integration_test/       # Testing resources to support README's quick start
│
├── plain_k8s_manifests/    # Plain (untested) YAML if Helm is a bad fit
│
└── rust/
    ├── api-rs/             # Server binary
    ├── cli-rs/             # CLI binary
    ├── integration-tests/  # Integration tests with mock K8s API
    └── kcd-proto/          # Shared protocol types
```

---

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

The recommended way to install is via [cargo-binstall](https://github.com/cargo-bins/cargo-binstall) — it downloads a prebuilt binary for your platform:

```bash
cargo binstall klingon-cloaking-device
```

<details>
<summary>Alternative: manual download</summary>

Download the latest binary from [GitHub Releases](https://github.com/thenotary/klingon-cloaking-device/releases):

```bash
# Linux (amd64)
curl -Lo kcd https://github.com/thenotary/klingon-cloaking-device/releases/latest/download/kcd-linux-amd64
chmod +x kcd
sudo mv kcd /usr/local/bin/
```

</details>

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

## Helm Chart

See [helm_chart/README.md](helm_chart/README.md) for installation and configuration instructions.

## CLI

See [rust/cli-rs/README.md](rust/cli-rs/README.md) for installation and usage instructions once your Helm chart has been successfully deployed.

## Container Build & Run

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

## Rust Build & Test

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
- See GitHub Releases for binaries

