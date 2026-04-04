# Helm Chart

## Install

```bash
helm install kcd oci://ghcr.io/thenotary/charts/klingon-cloaking-device \
  --namespace klingon-cloaking-device \
  --create-namespace \
  --set secrets.knockPassword="<YOUR_KNOCK_PASSWORD>" \
  --set secrets.accessPassword="<YOUR_ACCESS_PASSWORD>"
```

## Upgrade

```bash
helm upgrade kcd oci://ghcr.io/thenotary/charts/klingon-cloaking-device \
  --namespace klingon-cloaking-device \
  --set image.tag="0.2.0"
```

## Configuration

See [values.yaml](values.yaml) for all configurable values.

### TLS Values

| Key | Type | Default | Description |
|-----       |------|---------|-------------|
| `tls.mode` | string | `""` | TLS mode: `certManager`, `secret`, `inline`, or empty (disabled) |
| `tls.certManager.issuerName` | string | `""` | cert-manager Issuer or ClusterIssuer name |
| `tls.certManager.issuerKind` | string | `"ClusterIssuer"` | `Issuer` or `ClusterIssuer` |
| `tls.certManager.dnsNames` | list | `[]` | SANs for the certificate |
| `tls.secret.name`          | string | `""` | Name of an existing `kubernetes.io/tls` Secret |
| `tls.inline.crt`           | string | `""` | Base64-encoded PEM certificate chain |
| `tls.inline.key`           | string | `""` | Base64-encoded PEM private key |

### Azure Workload Identity

To use [Azure Workload Identity](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview), supply your managed identity client ID:

```bash
helm install kcd oci://ghcr.io/thenotary/charts/klingon-cloaking-device \
  --set secrets.knockPassword="<YOUR_KNOCK_PASSWORD>" \
  --set secrets.accessPassword="<YOUR_ACCESS_PASSWORD>" \
  --set azureWorkloadIdentity.clientId="<CLIENT_ID>" \
  --set tls.mode=secret \
  --set tls.secret.name=my-tls-secret
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `azureWorkloadIdentity.clientId` | string | `""` | Azure managed identity client ID. When non-empty, adds the pod label and ServiceAccount annotation for Workload Identity |

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
