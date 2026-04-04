# ---------------------------------------------------------------------------
# Stage 1 — Build a fully static binary with musl
# ---------------------------------------------------------------------------
FROM --platform=linux/amd64 rust:1.88-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build

# --- Dependency caching layer ---
# Copy only manifests and lock files first so Docker can cache compiled
# dependencies separately from our source code.
COPY kcd-proto/Cargo.toml kcd-proto/Cargo.toml
COPY kcd-proto/src/ kcd-proto/src/
COPY api-rs/Cargo.toml api-rs/Cargo.lock api-rs/
COPY cli-rs/Cargo.toml cli-rs/Cargo.lock cli-rs/

# Dummy source files to let cargo resolve and compile all dependencies.
RUN mkdir -p api-rs/src cli-rs/src \
    && echo "fn main() {}" > api-rs/src/main.rs \
    && echo "" > api-rs/src/lib.rs \
    && echo "fn main() {}" > cli-rs/src/main.rs

RUN cd api-rs && cargo build --release --target x86_64-unknown-linux-musl

# Remove dummy sources and build fingerprints so cargo rebuilds our code.
RUN rm -rf api-rs/src cli-rs/src \
    && rm -f api-rs/target/x86_64-unknown-linux-musl/release/deps/klingon_cloaking_device_server* \
    && rm -f api-rs/target/x86_64-unknown-linux-musl/release/deps/libkcd_server* \
    && rm -f api-rs/target/x86_64-unknown-linux-musl/release/deps/kcd_proto* \
    && rm -f api-rs/target/x86_64-unknown-linux-musl/release/klingon-cloaking-device-server*

# --- Full source build ---
COPY api-rs/src/ api-rs/src/
COPY cli-rs/src/ cli-rs/src/

RUN cd api-rs && cargo build --release --target x86_64-unknown-linux-musl

# ---------------------------------------------------------------------------
# Stage 2 — Minimal runtime
# ---------------------------------------------------------------------------
FROM alpine:3.21

# CA certificates so the binary can reach the K8s API server
RUN apk add --no-cache ca-certificates

COPY --from=builder /build/api-rs/target/x86_64-unknown-linux-musl/release/klingon-cloaking-device-server /klingon-cloaking-device-server

EXPOSE 9000/udp 9001

ENTRYPOINT ["/klingon-cloaking-device-server"]
