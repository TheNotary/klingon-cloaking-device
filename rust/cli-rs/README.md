# cli-rs

The CLI binary: `klingon-cloaking-device`. Sends a knock sequence and authenticates over TLS to whitelist your IP on cloaked services.

## Install

The recommended way to install is via [cargo-binstall](https://github.com/cargo-bins/cargo-binstall) — it downloads a prebuilt binary for your platform:

```bash
cargo binstall klingon-cloaking-device
```

### Manual download

Alternatively, download a binary from [GitHub Releases](https://github.com/thenotary/klingon-cloaking-device/releases):

| Platform        | Binary             |
|----------       |--------            |
| Linux (amd64)   | `kcd-linux-amd64`  |
| Linux (arm64)   | `kcd-linux-arm64`  |
| macOS (amd64)   | `kcd-darwin-amd64` |
| macOS (arm64)   | `kcd-darwin-arm64` |
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

# With explicit TLS hostname (when --server is an IP)
kcd authorize \
  --server 1.2.3.4 \
  --hostname my-kcd.example.com \
  --knock-password "my-knock-secret" \
  --access-password "my-access-secret"

# Using ~/.kcd/config (authorize all configured servers)
kcd authorize
```

## Config File

After a successful authorization with explicit arguments, the CLI will prompt you to save the server to `~/.kcd/config`. Once saved, you can run `kcd authorize` with no arguments to authorize against all configured servers.

```yaml
servers:
  - name: my-kcd
    address: 1.2.3.4
    hostname: my-kcd.example.com
    knock_password: my-knock-secret
    access_password: my-access-secret
    insecure_skip_tls_verify: false
```

## Options

```
klingon-cloaking-device authorize [OPTIONS]

    --server <IP>              Server IP or hostname (optional if ~/.kcd/config exists)
    --knock-port <PORT>        UDP knock port [default: 9000]
    --auth-port <PORT>         TCP auth port [default: 9001]
    --knock-password <SECRET>  Knock password (or KCD_KNOCK_PASSWORD env)
    --access-password <SECRET> Access password (or KCD_ACCESS_PASSWORD env)
    --hostname <HOST>          TLS server name for cert verification (overrides --server)
    --ca-cert <PATH>           PEM CA certificate for server verification
    --insecure                 Skip TLS certificate verification
    --knock-chunks <N>         Number of knock chunks [default: 4]
```
