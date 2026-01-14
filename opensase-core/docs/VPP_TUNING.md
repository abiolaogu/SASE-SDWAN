# OpenSASE VPP Performance Tuning Guide

## Overview

This guide covers performance tuning for achieving **100+ Gbps** throughput and **<5μs** latency on dedicated servers.

## Hardware Requirements

### Minimum Configuration

| Component | Specification |
|-----------|---------------|
| CPU | 16 cores, 2.5 GHz+ |
| RAM | 64 GB DDR4 |
| NIC | 2x 100GbE (ConnectX-6/E810) |
| Storage | NVMe SSD (logs) |

### Recommended Configuration

| Component | Specification |
|-----------|---------------|
| CPU | 32+ cores, 3.0 GHz (EPYC 7003 / Xeon 4th Gen) |
| RAM | 128 GB DDR4-3200 |
| NIC | 2x 100GbE + 2x 25GbE (mgmt) |
| Storage | 2x NVMe RAID-1 |
| NUMA | 2 sockets, NICs on separate NUMA |

## BIOS Settings

```
Performance Mode:         Enabled
Turbo Boost:              Enabled
C-States:                 Disabled (or C1 only)
P-States:                 Disabled (or max frequency)
Hyperthreading:           Disabled (for consistent latency)
NUMA:                     Enabled
Memory Interleaving:      Disabled
PCIe ASPM:                Disabled
SR-IOV:                   Enabled
```

## Kernel Configuration

### GRUB Command Line

```
GRUB_CMDLINE_LINUX="default_hugepagesz=1G hugepagesz=1G hugepages=64 \
    isolcpus=4-31 nohz_full=4-31 rcu_nocbs=4-31 \
    intel_pstate=disable processor.max_cstate=1 intel_idle.max_cstate=0 \
    iommu=pt intel_iommu=on"
```

### Sysctl Settings

```bash
# /etc/sysctl.d/80-vpp-perf.conf

# Hugepages
vm.nr_hugepages = 16384

# Shared memory
kernel.shmmax = 68719476736
kernel.shmall = 16777216

# Network buffers
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.netdev_max_backlog = 250000
net.core.netdev_budget = 50000

# Reduce swap
vm.swappiness = 1
```

## CPU Tuning

### Core Isolation

Reserve cores for VPP workers:

```bash
# isolcpus=4-31 in GRUB

# Verify isolation
cat /sys/devices/system/cpu/isolated
```

### CPU Governor

```bash
# Set to performance
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    echo "performance" > $cpu
done
```

### Disable irqbalance

```bash
systemctl stop irqbalance
systemctl disable irqbalance
```

### IRQ Affinity

Pin NIC interrupts to non-VPP cores:

```bash
# For NIC on NUMA 0, use cores 0-3
echo 1 > /proc/irq/<IRQ>/smp_affinity_list
```

## Memory Tuning

### Hugepage Allocation

#### 1GB Hugepages (Recommended)

```bash
# At boot via GRUB
hugepages=64  # 64GB of 1GB pages

# Verify
cat /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages
```

#### 2MB Hugepages (Fallback)

```bash
# Runtime allocation
echo 16384 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# NUMA-aware
echo 8192 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
echo 8192 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages
```

### NUMA Binding

```bash
# VPP startup.conf
dpdk {
    socket-mem 8192,8192  # Per NUMA node
}
```

## NIC Tuning

### Driver Selection

| NIC | Driver | Binding |
|-----|--------|---------|
| Mellanox ConnectX-6 | mlx5 | Native DPDK |
| Intel E810 | ice | VFIO-PCI |
| Intel X710 | i40e | VFIO-PCI |

### VFIO-PCI Binding

```bash
# Load modules
modprobe vfio-pci

# Unbind from kernel
echo "0000:41:00.0" > /sys/bus/pci/devices/0000:41:00.0/driver/unbind

# Bind to VFIO
echo "vfio-pci" > /sys/bus/pci/devices/0000:41:00.0/driver_override
echo "0000:41:00.0" > /sys/bus/pci/drivers/vfio-pci/bind
```

### Queue Configuration

```
# VPP dpdk configuration
dev 0000:41:00.0 {
    num-rx-queues 8
    num-tx-queues 8
    num-rx-desc 4096
    num-tx-desc 4096
    rss-fn ipv4-tcp ipv4-udp
}
```

## VPP Tuning

### Buffer Configuration

```
buffers {
    buffers-per-numa 524288      # 512K buffers
    default data-size 2048       # 2KB per buffer
    preallocated-per-numa 262144 # Pre-allocate 256K
}
```

### CPU Configuration

```
cpu {
    main-core 0
    corelist-workers 4-19       # 16 workers
    # scheduler-policy fifo     # Optional: real-time
    # scheduler-priority 50
}
```

### Poll Mode

```
unix {
    poll-sleep-usec 0  # Zero sleep for minimum latency
}
```

### Session Layer

```
session {
    preallocated-sessions 1000000
    v4-session-table-buckets 512000
}
```

## Performance Validation

### Expected Results

| Metric | Target | Notes |
|--------|--------|-------|
| Throughput (64B) | 100 Mpps | Stress packet rate |
| Throughput (1518B) | 100 Gbps | Stress bandwidth |
| Throughput (IMIX) | 80 Gbps | Realistic traffic |
| Latency P50 | <5 μs | Typical latency |
| Latency P99 | <20 μs | Tail latency |
| Concurrent flows | 10M+ | Flow table capacity |
| New flows/sec | 1M+ | Session creation |
| WireGuard | 80 Gbps | Encrypted throughput |
| CPU utilization | <80% | Headroom |

### Benchmark Commands

```bash
# Run full benchmark suite
sudo ./vpp/tests/run-benchmark.sh all 60

# TRex automated testing
python3 ./vpp/tests/benchmark_vpp.py --test all --duration 60
```

### Monitoring During Tests

```bash
# Real-time interface stats
watch -n1 'vppctl show interface'

# Node performance (clocks per packet)
vppctl show runtime max

# CPU utilization
vppctl show threads
```

## Troubleshooting

### Low Throughput

1. Check hugepages: `cat /proc/meminfo | grep Huge`
2. Verify CPU isolation: `cat /sys/devices/system/cpu/isolated`
3. Check NUMA binding: `numactl --hardware`
4. Verify NIC queues: `vppctl show dpdk interface`

### High Latency

1. Disable C-states in BIOS
2. Set CPU governor to performance
3. Check for IRQ interference
4. Reduce poll-sleep-usec to 0

### Packet Loss

1. Increase buffer pool size
2. Check rx/tx descriptor counts
3. Verify NUMA alignment
4. Monitor error counters: `vppctl show errors`

### Memory Issues

1. Increase hugepage allocation
2. Check for memory leaks: `vppctl show memory`
3. Verify socket-mem in dpdk config

## Quick Reference

```bash
# Status checks
vppctl show version
vppctl show interface
vppctl show runtime
vppctl show memory
vppctl show opensase stats

# Performance metrics
vppctl show threads
vppctl show dpdk physmem
vppctl show buffers

# Debug
vppctl trace add dpdk-input 100
vppctl show trace
```
