# api-rs

The server binary: `klingon-cloaking-device-server`. Listens for UDP knock sequences and TLS authentication, then patches `loadBalancerSourceRanges` on target Kubernetes services.

## Build

```bash
cargo build --release
```

## Test

```bash
cargo test
```

## Run

```bash
KCD_KNOCK_PASSWORD=my-knock-secret \
KCD_ACCESS_PASSWORD=my-access-secret \
KCD_TLS_CERT_PATH=./tls.crt \
KCD_TLS_KEY_PATH=./tls.key \
cargo run --release
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KCD_KNOCK_PASSWORD` | *required* | Password split into UDP knock chunks |
| `KCD_ACCESS_PASSWORD` | *required* | Password sent over TLS for final auth |
| `KCD_IP_TTL_HOURS` | `24` | Hours before authorized IPs expire (0 = never) |
| `KCD_TLS_CERT_PATH` | `/mnt/secrets-store/kcd-tls-cert` | TLS certificate path |
| `KCD_TLS_KEY_PATH` | `/mnt/secrets-store/kcd-tls-key` | TLS private key path |

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 9000 | UDP | Knock sequence listener |
| 9001 | TCP | TLS authentication listener |
