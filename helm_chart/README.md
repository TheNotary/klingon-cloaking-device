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

## Azure Key Vault Integration

```bash
helm install kcd oci://ghcr.io/thenotary/charts/klingon-cloaking-device \
  --set secretProvider.enabled=true \
  --set secretProvider.clientID="<WORKLOAD_IDENTITY_CLIENT_ID>" \
  --set secretProvider.keyvaultName="<KEYVAULT_NAME>" \
  --set secretProvider.tenantID="<TENANT_ID>" \
  --set serviceAccount.annotations."azure\.workload\.identity/client-id"="<CLIENT_ID>"
```

## Configuration

See [values.yaml](values.yaml) for all configurable values.

### Namespace

By default, all resources are deployed into the Helm release namespace (the
`--namespace` flag). To deploy into a different namespace, set
`namespaceOverride`:

```bash
helm install kcd oci://ghcr.io/thenotary/charts/klingon-cloaking-device \
  --namespace klingon-cloaking-device \
  --create-namespace \
  --set namespaceOverride=my-custom-ns \
  --set secrets.knockPassword="<YOUR_KNOCK_PASSWORD>" \
  --set secrets.accessPassword="<YOUR_ACCESS_PASSWORD>"
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `namespaceOverride` | string | `""` | Override the release namespace for all resources |
| `createNamespace` | bool | `true` | Create a Namespace resource with chart labels |

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

## Release

Helm chart are released per the documentation in the root README.md.
