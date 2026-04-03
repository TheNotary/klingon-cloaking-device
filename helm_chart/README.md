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
|-----|------|---------|-------------|
| `tls.mode` | string | `""` | TLS mode: `certManager`, `secret`, `inline`, or empty (disabled) |
| `tls.certManager.issuerName` | string | `""` | cert-manager Issuer or ClusterIssuer name |
| `tls.certManager.issuerKind` | string | `"ClusterIssuer"` | `Issuer` or `ClusterIssuer` |
| `tls.certManager.dnsNames` | list | `[]` | SANs for the certificate |
| `tls.secret.name` | string | `""` | Name of an existing `kubernetes.io/tls` Secret |
| `tls.inline.crt` | string | `""` | Base64-encoded PEM certificate chain |
| `tls.inline.key` | string | `""` | Base64-encoded PEM private key |

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

## Release

Helm chart are released per the documentation in the root README.md.
