# OpenSASE Core - Multi-stage Docker Build
# Optimized for production deployment on Harvester HCI

FROM rust:1.75-bookworm AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY benches ./benches
COPY bpf ./bpf

# Build release binary
RUN cargo build --release --workspace

# Runtime stage - minimal image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    iproute2 \
    iptables \
    wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false opensase

WORKDIR /app

# Copy built binaries
COPY --from=builder /build/target/release/sase-gateway /usr/local/bin/
COPY --from=builder /build/target/release/sase-dataplane /usr/local/bin/ 2>/dev/null || true

# Set ownership
RUN chown -R opensase:opensase /app

USER opensase

EXPOSE 8080 443 51820/udp

ENV RUST_LOG=info

CMD ["sase-gateway"]
