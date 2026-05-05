# ---------------------------------------------------------------------------
# Stage 1 — Build a fully static aarch64 musl binary
# ---------------------------------------------------------------------------
FROM rust:1.88-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build

COPY rust/ ./

RUN cargo build --release --manifest-path api-rs/Cargo.toml --target aarch64-unknown-linux-musl

# ---------------------------------------------------------------------------
# Stage 2 — Minimal runtime
# ---------------------------------------------------------------------------
FROM alpine:3.21

RUN apk add --no-cache ca-certificates

COPY --from=builder /build/target/aarch64-unknown-linux-musl/release/klingon-cloaking-device-server /klingon-cloaking-device-server

EXPOSE 9000/udp 9001

ENTRYPOINT ["/klingon-cloaking-device-server"]
