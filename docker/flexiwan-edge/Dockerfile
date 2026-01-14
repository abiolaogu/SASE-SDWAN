# FlexiWAN Edge with VPP
# High-performance SD-WAN edge device

FROM ubuntu:22.04

LABEL maintainer="OpenSASE Team"
LABEL description="FlexiWAN Edge with VPP data plane"

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    gnupg2 \
    lsb-release \
    iproute2 \
    iptables \
    wireguard-tools \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install VPP
RUN curl -s https://packagecloud.io/install/repositories/fdio/release/script.deb.sh | bash && \
    apt-get update && apt-get install -y \
    vpp \
    vpp-plugin-core \
    vpp-plugin-dpdk \
    && rm -rf /var/lib/apt/lists/*

# Install FlexiWAN Agent
RUN curl -sL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs && \
    npm install -g flexiwan-agent

# Create directories
RUN mkdir -p /etc/flexiwan /var/log/flexiwan

# Copy configuration templates
COPY edge-config/ /etc/flexiwan/

# Copy startup script
COPY scripts/start-edge.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/start-edge.sh

# Expose ports
# WireGuard
EXPOSE 51820/udp
# FlexiWAN Agent
EXPOSE 4789/udp
# VPP API
EXPOSE 5002

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:4789/health || exit 1

# Start edge
CMD ["/usr/local/bin/start-edge.sh"]
