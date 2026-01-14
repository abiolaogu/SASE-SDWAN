# OpenSASE Tuning Guide

Performance tuning for 40Gbps+ throughput.

## 1. Hugepages

```bash
# Reserve 2GB hugepages at boot
echo 'GRUB_CMDLINE_LINUX="hugepages=1024"' >> /etc/default/grub
update-grub

# Or at runtime
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# Mount
mkdir -p /dev/hugepages
mount -t hugetlbfs nodev /dev/hugepages
```

## 2. CPU Pinning

```bash
# Isolate cores 2-5 for FPE
echo 'GRUB_CMDLINE_LINUX="isolcpus=2-5 nohz_full=2-5 rcu_nocbs=2-5"' >> /etc/default/grub

# Check isolation
cat /sys/devices/system/cpu/isolated
```

## 3. NUMA Optimization

```bash
# Check NUMA topology
numactl --hardware

# Pin to local socket
numactl --cpubind=0 --membind=0 ./opensase-fpe

# Verify
numastat -p $(pgrep opensase)
```

## 4. Network Interface

```bash
# Disable irqbalance
systemctl stop irqbalance

# Pin NIC IRQs to specific cores
echo 2 > /proc/irq/$(cat /proc/interrupts | grep eth0-rx-0 | awk '{print $1}' | tr -d ':')/smp_affinity_list

# Increase ring buffers
ethtool -G eth0 rx 4096 tx 4096

# Enable multi-queue
ethtool -L eth0 combined 4
```

## 5. Kernel Parameters

```bash
cat >> /etc/sysctl.conf << EOF
# Networking
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.netdev_max_backlog = 250000
net.core.optmem_max = 4194304

# Disable conntrack (FPE handles it)
net.netfilter.nf_conntrack_max = 0

# Disable iptables (security handled in userspace)
net.bridge.bridge-nf-call-iptables = 0
EOF

sysctl -p
```

## 6. AF_XDP Setup

```bash
# Load XDP program
ip link set dev eth0 xdp obj xdp_steering.o sec xdp

# Create AF_XDP socket
# (handled by FPE internally)

# Verify
ip link show eth0 | grep xdp
```

## 7. Benchmark Commands

```bash
cd opensase-core

# Run all benchmarks
cargo bench

# Flow table only
cargo bench --bench flow_table

# With flamegraph
cargo flamegraph --bench flow_table

# Profile with perf
perf record -g cargo bench
perf report
```

## 8. Monitoring

```bash
# Real-time stats
curl localhost:9090/metrics | grep opensase

# Key metrics
opensase_rx_packets_total
opensase_tx_packets_total
opensase_flow_table_size
opensase_latency_p99_us
```

## Performance Checklist

- [ ] Hugepages allocated (2GB+)
- [ ] CPUs isolated for FPE
- [ ] NUMA-aware memory allocation
- [ ] IRQs pinned to non-FPE cores
- [ ] Ring buffers maximized
- [ ] Kernel conntrack disabled
- [ ] XDP program loaded
- [ ] AF_XDP sockets bound
