# ---------------------------------------------------------------------------
# Stage 1 — Build a fully static musl binary for the target platform
# ---------------------------------------------------------------------------
FROM rust:1.88-alpine AS builder

ARG TARGETARCH

RUN apk add --no-cache musl-dev

WORKDIR /build

COPY rust/ ./

RUN case "$TARGETARCH" in \
      amd64) RUST_TARGET="x86_64-unknown-linux-musl" ;; \
      arm64) RUST_TARGET="aarch64-unknown-linux-musl" ;; \
      *)     echo "Unsupported architecture: $TARGETARCH" && exit 1 ;; \
    esac && \
    cargo build --release --manifest-path api-rs/Cargo.toml --target "$RUST_TARGET" && \
    cp "target/$RUST_TARGET/release/klingon-cloaking-device-server" /klingon-cloaking-device-server

# ---------------------------------------------------------------------------
# Stage 2 — Minimal runtime
# ---------------------------------------------------------------------------
FROM alpine:3.21

RUN apk add --no-cache ca-certificates

COPY --from=builder /klingon-cloaking-device-server /klingon-cloaking-device-server

EXPOSE 9000/udp 9001 9002

ENTRYPOINT ["/klingon-cloaking-device-server"]
