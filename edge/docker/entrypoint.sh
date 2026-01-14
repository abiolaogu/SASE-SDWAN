#!/bin/bash
set -e

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Load WireGuard module if available
modprobe wireguard 2>/dev/null || true

exec "$@"
