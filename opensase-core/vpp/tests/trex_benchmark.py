#!/usr/bin/env python3
"""
OpenSASE VPP - TRex Benchmark Script

Automated traffic generation for VPP performance validation.
Requires TRex v3.00+ installed and running on the test server.

Usage:
    python3 trex_benchmark.py --test <test_name> --duration <seconds>
"""

import argparse
import sys
import time
import json
from datetime import datetime

try:
    from trex.stl.api import *
except ImportError:
    print("ERROR: TRex STL API not found")
    print("Install: pip install trex-stl-lib")
    sys.exit(1)


class OpenSASEBenchmark:
    """TRex-based benchmark for OpenSASE VPP engine."""
    
    # Benchmark targets
    TARGET_THROUGHPUT_GBPS = 100
    TARGET_LATENCY_US = 5
    TARGET_64B_PPS = 148_000_000
    
    def __init__(self, server="localhost", ports=[0, 1]):
        self.server = server
        self.ports = ports
        self.client = STLClient(server=server)
        self.results = {}
    
    def connect(self):
        """Connect to TRex server."""
        print(f"Connecting to TRex at {self.server}...")
        self.client.connect()
        self.client.reset(ports=self.ports)
        self.client.clear_stats(ports=self.ports)
        print("Connected!")
    
    def disconnect(self):
        """Disconnect from TRex server."""
        self.client.disconnect()
        print("Disconnected from TRex")
    
    def create_udp_stream(self, size=64, pps=None, src_ip="10.0.0.1", 
                          dst_ip="10.0.0.2", src_port=1024, dst_port=80):
        """Create a UDP stream with specified parameters."""
        
        # Calculate payload size
        # Ethernet(14) + IP(20) + UDP(8) + FCS(4) = 46 overhead
        payload_size = max(size - 46, 18)
        
        pkt = Ether() / IP(src=src_ip, dst=dst_ip) / \
              UDP(sport=src_port, dport=dst_port) / \
              Raw(b'\x00' * payload_size)
        
        if pps:
            mode = STLTXCont(pps=pps)
        else:
            mode = STLTXCont(percentage=100)  # Line rate
        
        return STLStream(
            packet=STLPktBuilder(pkt=pkt),
            mode=mode
        )
    
    def create_imix_streams(self):
        """Create IMIX (Internet Mix) traffic streams."""
        streams = []
        
        # IMIX composition: 7x64, 4x570, 1x1518
        # Normalized to percentages
        configs = [
            (64, 58.33),    # Small packets
            (570, 33.33),   # Medium packets
            (1518, 8.33),   # Large packets
        ]
        
        for size, percentage in configs:
            pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / \
                  UDP(sport=1024, dport=80) / \
                  Raw(b'\x00' * max(size - 46, 18))
            
            stream = STLStream(
                packet=STLPktBuilder(pkt=pkt),
                mode=STLTXCont(percentage=percentage)
            )
            streams.append(stream)
        
        return streams
    
    def create_session_storm_streams(self, sessions_per_sec=1_000_000):
        """Create streams for session creation stress test."""
        
        # Use variable source IPs and ports to create unique flows
        vm = STLScVmRaw([
            STLVmFlowVar(name="src_ip", min_value="10.0.0.1", 
                        max_value="10.255.255.254", size=4, op="random"),
            STLVmFlowVar(name="src_port", min_value=1024, 
                        max_value=65535, size=2, op="random"),
            STLVmWrFlowVar(fv_name="src_ip", pkt_offset="IP.src"),
            STLVmWrFlowVar(fv_name="src_port", pkt_offset="UDP.sport"),
            STLVmFixIpv4(offset="IP")
        ])
        
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / \
              UDP(sport=1024, dport=80) / Raw(b'\x00' * 18)
        
        return STLStream(
            packet=STLPktBuilder(pkt=pkt, vm=vm),
            mode=STLTXCont(pps=sessions_per_sec)
        )
    
    def run_baseline_test(self, duration=60):
        """Test baseline forwarding throughput."""
        print("\n=== Baseline Throughput Test ===")
        
        stream = self.create_udp_stream(size=64)
        self.client.add_streams(stream, ports=[0])
        
        self.client.start(ports=[0], mult="100%", duration=duration)
        self.client.wait_on_traffic()
        
        stats = self.client.get_stats()
        self._record_results("baseline", stats, duration)
    
    def run_sase_pipeline_test(self, duration=60):
        """Test full SASE pipeline at line rate."""
        print("\n=== Full SASE Pipeline Test ===")
        
        # Bidirectional traffic
        stream0 = self.create_udp_stream(size=256, src_ip="10.0.0.1", dst_ip="10.0.0.2")
        stream1 = self.create_udp_stream(size=256, src_ip="10.0.0.2", dst_ip="10.0.0.1")
        
        self.client.add_streams(stream0, ports=[0])
        self.client.add_streams(stream1, ports=[1])
        
        # Start with latency measurement
        self.client.start(ports=self.ports, mult="100%", duration=duration)
        
        # Collect stats periodically
        stats_samples = []
        for _ in range(duration):
            time.sleep(1)
            stats_samples.append(self.client.get_stats())
        
        self.client.wait_on_traffic()
        
        final_stats = self.client.get_stats()
        self._record_results("sase_pipeline", final_stats, duration)
    
    def run_imix_test(self, duration=60):
        """Test with IMIX traffic profile."""
        print("\n=== IMIX Traffic Test ===")
        
        streams = self.create_imix_streams()
        self.client.add_streams(streams, ports=[0])
        
        self.client.start(ports=[0], mult="100%", duration=duration)
        self.client.wait_on_traffic()
        
        stats = self.client.get_stats()
        self._record_results("imix", stats, duration)
    
    def run_session_storm_test(self, duration=60, sps=1_000_000):
        """Test session creation under load."""
        print(f"\n=== Session Storm Test ({sps/1e6:.1f}M sessions/sec) ===")
        
        stream = self.create_session_storm_streams(sps)
        self.client.add_streams(stream, ports=[0])
        
        self.client.start(ports=[0], duration=duration)
        self.client.wait_on_traffic()
        
        stats = self.client.get_stats()
        self._record_results("session_storm", stats, duration)
    
    def run_latency_test(self, duration=60):
        """Measure latency distribution."""
        print("\n=== Latency Measurement Test ===")
        
        # Low rate for accurate latency measurement
        stream = self.create_udp_stream(size=64, pps=100_000)
        
        # Enable latency measurement
        stream = STLStream(
            packet=STLPktBuilder(pkt=Ether()/IP(src="10.0.0.1",dst="10.0.0.2")/UDP()/Raw(b'\x00'*18)),
            mode=STLTXCont(pps=100_000),
            flow_stats=STLFlowLatencyStats(pg_id=0)
        )
        
        self.client.add_streams(stream, ports=[0])
        self.client.start(ports=[0], duration=duration)
        
        # Sample latency during test
        latencies = []
        for _ in range(duration):
            time.sleep(1)
            stats = self.client.get_stats()
            if 'latency' in stats and 0 in stats['latency']:
                lat = stats['latency'][0]
                if 'latency' in lat:
                    latencies.append({
                        'average': lat['latency'].get('average', 0),
                        'total_max': lat['latency'].get('total_max', 0),
                        'jitter': lat['latency'].get('jitter', 0),
                    })
        
        self.client.wait_on_traffic()
        
        if latencies:
            avg_lat = sum(l['average'] for l in latencies) / len(latencies)
            max_lat = max(l['total_max'] for l in latencies)
            avg_jitter = sum(l['jitter'] for l in latencies) / len(latencies)
            
            self.results['latency'] = {
                'average_us': avg_lat,
                'max_us': max_lat,
                'jitter_us': avg_jitter,
                'samples': len(latencies)
            }
            
            print(f"  Average latency: {avg_lat:.2f} μs")
            print(f"  Max latency:     {max_lat:.2f} μs")
            print(f"  Jitter:          {avg_jitter:.2f} μs")
            
            if avg_lat <= self.TARGET_LATENCY_US:
                print(f"  ✓ PASS: Latency within target (<{self.TARGET_LATENCY_US} μs)")
            else:
                print(f"  ✗ FAIL: Latency exceeds target")
    
    def _record_results(self, test_name, stats, duration):
        """Record and print test results."""
        
        port0 = stats.get(0, {})
        port1 = stats.get(1, {})
        
        tx_pkts = port0.get('opackets', 0) + port1.get('opackets', 0)
        rx_pkts = port0.get('ipackets', 0) + port1.get('ipackets', 0)
        tx_bytes = port0.get('obytes', 0) + port1.get('obytes', 0)
        rx_bytes = port0.get('ibytes', 0) + port1.get('ibytes', 0)
        
        # Calculate rates
        tx_pps = tx_pkts / duration
        rx_pps = rx_pkts / duration
        tx_gbps = (tx_bytes * 8) / (duration * 1e9)
        rx_gbps = (rx_bytes * 8) / (duration * 1e9)
        
        # Calculate loss
        loss = tx_pkts - rx_pkts if tx_pkts > rx_pkts else 0
        loss_pct = (loss / tx_pkts * 100) if tx_pkts > 0 else 0
        
        result = {
            'test_name': test_name,
            'duration': duration,
            'tx_packets': tx_pkts,
            'rx_packets': rx_pkts,
            'tx_bytes': tx_bytes,
            'rx_bytes': rx_bytes,
            'tx_pps': tx_pps,
            'rx_pps': rx_pps,
            'tx_gbps': tx_gbps,
            'rx_gbps': rx_gbps,
            'packet_loss': loss,
            'loss_percentage': loss_pct,
            'timestamp': datetime.now().isoformat()
        }
        
        self.results[test_name] = result
        
        # Print results
        print(f"\n  Results for {test_name}:")
        print(f"  TX: {tx_pps/1e6:.2f} Mpps ({tx_gbps:.2f} Gbps)")
        print(f"  RX: {rx_pps/1e6:.2f} Mpps ({rx_gbps:.2f} Gbps)")
        print(f"  Loss: {loss:,} packets ({loss_pct:.4f}%)")
        
        # Evaluate against targets
        if tx_gbps >= self.TARGET_THROUGHPUT_GBPS:
            print(f"  ✓ PASS: Throughput meets target (≥{self.TARGET_THROUGHPUT_GBPS} Gbps)")
        else:
            print(f"  ✗ FAIL: Throughput below target ({tx_gbps:.1f} < {self.TARGET_THROUGHPUT_GBPS} Gbps)")
        
        if loss_pct <= 0.001:
            print(f"  ✓ PASS: Packet loss acceptable (≤0.001%)")
        else:
            print(f"  ✗ FAIL: Packet loss too high ({loss_pct:.4f}% > 0.001%)")
    
    def save_results(self, filename="benchmark_results.json"):
        """Save results to JSON file."""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\nResults saved to {filename}")
    
    def print_summary(self):
        """Print summary of all tests."""
        print("\n" + "="*60)
        print("BENCHMARK SUMMARY")
        print("="*60)
        
        for name, result in self.results.items():
            if isinstance(result, dict) and 'tx_gbps' in result:
                status = "✓" if result['tx_gbps'] >= self.TARGET_THROUGHPUT_GBPS else "✗"
                print(f"  {status} {name}: {result['tx_gbps']:.2f} Gbps, "
                      f"{result['loss_percentage']:.4f}% loss")
            elif name == 'latency':
                status = "✓" if result['average_us'] <= self.TARGET_LATENCY_US else "✗"
                print(f"  {status} latency: {result['average_us']:.2f} μs avg")


def main():
    parser = argparse.ArgumentParser(description="OpenSASE VPP Benchmark")
    parser.add_argument("--server", default="localhost", help="TRex server address")
    parser.add_argument("--test", default="all", 
                       choices=["baseline", "sase", "imix", "sessions", "latency", "all"],
                       help="Test to run")
    parser.add_argument("--duration", type=int, default=60, help="Test duration in seconds")
    parser.add_argument("--output", default="benchmark_results.json", help="Output file")
    
    args = parser.parse_args()
    
    benchmark = OpenSASEBenchmark(server=args.server)
    
    try:
        benchmark.connect()
        
        if args.test in ["baseline", "all"]:
            benchmark.run_baseline_test(args.duration)
            benchmark.client.reset(ports=benchmark.ports)
        
        if args.test in ["sase", "all"]:
            benchmark.run_sase_pipeline_test(args.duration)
            benchmark.client.reset(ports=benchmark.ports)
        
        if args.test in ["imix", "all"]:
            benchmark.run_imix_test(args.duration)
            benchmark.client.reset(ports=benchmark.ports)
        
        if args.test in ["sessions", "all"]:
            benchmark.run_session_storm_test(args.duration)
            benchmark.client.reset(ports=benchmark.ports)
        
        if args.test in ["latency", "all"]:
            benchmark.run_latency_test(args.duration)
        
        benchmark.print_summary()
        benchmark.save_results(args.output)
        
    finally:
        benchmark.disconnect()


if __name__ == "__main__":
    main()
