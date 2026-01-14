FROM rust:1.75-slim as builder

WORKDIR /app
COPY Cargo.toml ./
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    iproute2 \
    iptables \
    wireguard-tools \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/opensase-edge /usr/local/bin/
COPY docker/entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

EXPOSE 8080 51820/udp

ENTRYPOINT ["/entrypoint.sh"]
CMD ["opensase-edge"]
