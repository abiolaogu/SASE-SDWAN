# Security PoP Dockerfile - Enhanced
# Alpine-based security gateway with Suricata IPS, Unbound DNS, Squid Proxy
# Substitute for OPNsense (which doesn't run well in containers)

FROM alpine:3.19

LABEL maintainer="OpenSASE Lab"
LABEL description="Security PoP Gateway with Suricata IPS, Unbound DNS, Squid Proxy"

# Install packages
RUN apk add --no-cache \
    # Core utilities
    bash curl wget jq ca-certificates supervisor \
    # Suricata IPS
    suricata \
    # DNS
    unbound \
    # Firewall
    nftables iptables ip6tables \
    # Squid Proxy (SWG-lite)
    squid \
    # Prometheus metrics export
    node_exporter \
    # Python for management API
    python3 py3-pip py3-flask py3-requests \
    # Networking tools
    bind-tools iputils tcpdump iproute2 conntrack-tools \
    # File beat for log shipping
    && rm -rf /var/cache/apk/*

# Create directories
RUN mkdir -p /var/log/suricata \
    /var/log/unbound \
    /var/log/squid \
    /var/lib/suricata/rules \
    /var/lib/suricata/update \
    /etc/suricata/rules \
    /run/suricata

# Copy configurations
COPY supervisord.conf /etc/supervisord.conf
COPY nftables.conf /etc/nftables.conf
COPY suricata/ /etc/suricata/
COPY unbound/ /etc/unbound/
COPY squid/ /etc/squid/
COPY api/ /opt/api/

# Download ET Open rules for Suricata
RUN suricata-update --no-check-certificate \
    || echo "Rule update failed, will use bundled rules"

# Create safe demo rules directory
COPY suricata/rules/ /var/lib/suricata/rules/

# Set permissions
RUN chown -R suricata:suricata /var/log/suricata /var/lib/suricata /run/suricata \
    && chown -R unbound:unbound /var/log/unbound \
    && chown -R squid:squid /var/log/squid /var/cache/squid

# Initialize Squid cache
RUN squid -z 2>/dev/null || true

# Expose ports
# 8080 - Management API
# 3128 - Squid HTTP Proxy
# 53 - DNS (UDP/TCP)
# 9100 - Prometheus Node Exporter
EXPOSE 8080 3128 53/udp 53/tcp 9100

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -sf http://localhost:8080/api/health || exit 1

# Enable IP forwarding on container start
ENTRYPOINT ["/bin/sh", "-c", "sysctl -w net.ipv4.ip_forward=1 && exec /usr/bin/supervisord -c /etc/supervisord.conf"]
