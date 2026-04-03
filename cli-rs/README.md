# cli-rs

The CLI binary: `klingon-cloaking-device`. Sends a knock sequence and authenticates over TLS to whitelist your IP on cloaked services.

## Install

Download the latest binary from [GitHub Releases](https://github.com/thenotary/klingon-cloaking-device/releases):

| Platform | Binary |
|----------|--------|
| Linux (amd64) | `kcd-linux-amd64` |
| Linux (arm64) | `kcd-linux-arm64` |
| macOS (amd64) | `kcd-darwin-amd64` |
| macOS (arm64) | `kcd-darwin-arm64` |
| Windows (amd64) | `kcd-windows-amd64.exe` |

```bash
# Example: Linux amd64
curl -Lo kcd https://github.com/thenotary/klingon-cloaking-device/releases/latest/download/kcd-linux-amd64
chmod +x kcd
sudo mv kcd /usr/local/bin/
```

## Build from Source

```bash
cargo build --release
```

## Test

```bash
cargo test
```

## Run

```bash
# Create an alias
alias kcd=./target/release/klingon-cloaking-device

# With environment variables
export KCD_KNOCK_PASSWORD=my-knock-secret
export KCD_ACCESS_PASSWORD=my-access-secret
# TODO: pull server from k8s service
kcd authorize --server 1.2.3.4

# Authorize your IP
kcd authorize \
  --server 1.2.3.4 \
  --knock-password "my-knock-secret" \
  --access-password "my-access-secret" \
  --insecure

# With a CA certificate
kcd authorize \
  --server 1.2.3.4 \
  --knock-password "my-knock-secret" \
  --access-password "my-access-secret" \
  --ca-cert ./ca.pem
```

## Options

```
klingon-cloaking-device authorize [OPTIONS]

    --server <IP>              Server IP or hostname
    --knock-port <PORT>        UDP knock port [default: 9000]
    --auth-port <PORT>         TCP auth port [default: 9001]
    --knock-password <SECRET>  Knock password (or KCD_KNOCK_PASSWORD env)
    --access-password <SECRET> Access password (or KCD_ACCESS_PASSWORD env)
    --ca-cert <PATH>           PEM CA certificate for server verification
    --insecure                 Skip TLS certificate verification
    --knock-chunks <N>         Number of knock chunks [default: 4]
```
