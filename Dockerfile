# ---------------------------------------------------------------------------
# Stage 1 — Build a fully static binary with musl
# ---------------------------------------------------------------------------
FROM --platform=linux/amd64 rust:1.88-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build
COPY kcd-proto/ kcd-proto/
COPY api-rs/ api-rs/
COPY cli-rs/ cli-rs/

RUN cd api-rs && cargo build --release --target x86_64-unknown-linux-musl

# ---------------------------------------------------------------------------
# Stage 2 — Minimal runtime
# ---------------------------------------------------------------------------
FROM alpine:3.21

# CA certificates so the binary can reach the K8s API server
RUN apk add --no-cache ca-certificates

COPY --from=builder /build/api-rs/target/x86_64-unknown-linux-musl/release/klingon-cloaking-device-server /klingon-cloaking-device-server
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 9000/udp 9001

ENTRYPOINT ["/entrypoint.sh"]
