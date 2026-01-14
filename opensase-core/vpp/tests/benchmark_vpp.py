#!/usr/bin/env python3
"""
OpenSASE VPP - Comprehensive Performance Benchmark Suite

Full benchmark implementation for validating VPP at 100 Gbps.
Includes throughput, latency, flow scaling, and stability tests.

Usage:
    python3 benchmark_vpp.py --test <test_name> --duration <seconds>
    python3 benchmark_vpp.py --test all --duration 60

Requirements:
    - TRex v3.00+ installed and running
    - VPP configured and running
    - 2x 100GbE NICs connected back-to-back
"""

import argparse
import sys
import time
import json
import os
from datetime import datetime
from typing import Dict, List, Optional

try:
    from trex_stl_lib.api import *
except ImportError:
    print("ERROR: TRex STL API not found")
    print("Install: pip install trex-stl-lib")
    sys.exit(1)


class VPPBenchmark:
    """Comprehensive VPP benchmarking suite using TRex."""
    
    # Performance targets
    TARGETS = {
        'throughput_64b_mpps': 100,
        'throughput_1518b_gbps': 100,
        'throughput_imix_gbps': 80,
        'latency_p50_us': 5,
        'latency_p99_us': 20,
        'concurrent_flows': 10_000_000,
        'new_flows_per_sec': 1_000_000,
        'wireguard_gbps': 80,
        'cpu_utilization_percent': 80,
    }
    
    def __init__(self, server: str = '127.0.0.1', ports: List[int] = [0, 1]):
        self.server = server
        self.ports = ports
        self.client = STLClient(server=server)
        self.results: Dict = {}
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
    def connect(self):
        """Connect to TRex server."""
        print(f"\n{'='*60}")
        print(f"OpenSASE VPP Performance Benchmark")
        print(f"TRex Server: {self.server}")
        print(f"Timestamp: {self.timestamp}")
        print(f"{'='*60}\n")
        
        self.client.connect()
        self.client.reset(ports=self.ports)
        self.client.clear_stats(ports=self.ports)
        print("✓ Connected to TRex\n")
        
    def disconnect(self):
        """Disconnect from TRex."""
        self.client.disconnect()
        print("\n✓ Disconnected from TRex")
        
    def run_throughput_test(self, packet_size: int = 1518, 
                            duration: int = 60) -> Dict:
        """
        Run throughput test and return results.
        
        Args:
            packet_size: Packet size in bytes (64-9000)
            duration: Test duration in seconds
            
        Returns:
            Dictionary with test results
        """
        test_name = f"throughput_{packet_size}b"
        print(f"\n{'='*60}")
        print(f"THROUGHPUT TEST: {packet_size}B packets for {duration}s")
        print(f"{'='*60}")
        
        self.client.reset(ports=self.ports)
        
        # Calculate payload size (Ethernet=14, IP=20, UDP=8)
        payload_size = max(packet_size - 42, 18)
        
        # Create packet
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.1.1") / \
              UDP(sport=1024, dport=80) / Raw(b'x' * payload_size)
        
        # For 64B packets, use PPS mode
        if packet_size <= 64:
            # 100 Mpps target
            stream = STLStream(
                packet=STLPktBuilder(pkt=pkt),
                mode=STLTXCont(pps=100_000_000)
            )
        else:
            # Use line rate for larger packets
            stream = STLStream(
                packet=STLPktBuilder(pkt=pkt),
                mode=STLTXCont(percentage=100)
            )
        
        self.client.add_streams(stream, ports=[0])
        
        print(f"Starting traffic generation...")
        self.client.start(ports=[0], duration=duration)
        
        # Monitor progress
        for i in range(duration):
            time.sleep(1)
            if (i + 1) % 10 == 0:
                stats = self.client.get_stats()
                curr_gbps = stats[0].get('tx_bps', 0) / 1e9
                curr_mpps = stats[0].get('tx_pps', 0) / 1e6
                print(f"  [{i+1:3d}s] TX: {curr_gbps:.2f} Gbps, {curr_mpps:.2f} Mpps")
        
        self.client.wait_on_traffic()
        
        # Get final stats
        stats = self.client.get_stats()
        
        tx_pkts = stats[0].get('opackets', 0)
        rx_pkts = stats[1].get('ipackets', 0)
        tx_bytes = stats[0].get('obytes', 0)
        rx_bytes = stats[1].get('ibytes', 0)
        
        # Calculate rates
        tx_pps = tx_pkts / duration
        rx_pps = rx_pkts / duration
        tx_gbps = (tx_bytes * 8) / (duration * 1e9)
        rx_gbps = (rx_bytes * 8) / (duration * 1e9)
        
        # Calculate loss
        loss = tx_pkts - rx_pkts if tx_pkts > rx_pkts else 0
        loss_pct = (loss / tx_pkts * 100) if tx_pkts > 0 else 0
        
        results = {
            'test_name': test_name,
            'packet_size': packet_size,
            'duration': duration,
            'tx_packets': tx_pkts,
            'rx_packets': rx_pkts,
            'tx_bytes': tx_bytes,
            'rx_bytes': rx_bytes,
            'tx_pps': tx_pps,
            'rx_pps': rx_pps,
            'tx_mpps': tx_pps / 1e6,
            'rx_mpps': rx_pps / 1e6,
            'tx_gbps': tx_gbps,
            'rx_gbps': rx_gbps,
            'packet_loss': loss,
            'loss_percent': loss_pct,
        }
        
        self.results[test_name] = results
        self._print_throughput_results(results)
        
        return results
    
    def run_latency_test(self, duration: int = 60) -> Dict:
        """
        Run latency test with hardware timestamping.
        
        Uses low rate traffic to accurately measure latency distribution.
        """
        test_name = "latency"
        print(f"\n{'='*60}")
        print(f"LATENCY TEST: {duration}s duration")
        print(f"{'='*60}")
        
        self.client.reset(ports=self.ports)
        
        # Small packets at low rate for accurate latency
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.1.1") / \
              UDP(sport=1024, dport=80) / Raw(b'x' * 18)
        
        # Enable latency measurement
        stream = STLStream(
            packet=STLPktBuilder(pkt=pkt),
            mode=STLTXCont(pps=100_000),  # 100K pps for latency test
            flow_stats=STLFlowLatencyStats(pg_id=0)
        )
        
        self.client.add_streams(stream, ports=[0])
        
        print("Starting latency measurement...")
        self.client.start(ports=[0], duration=duration)
        
        # Collect latency samples
        latency_samples = []
        for i in range(duration):
            time.sleep(1)
            stats = self.client.get_stats()
            if 'latency' in stats and 0 in stats['latency']:
                lat = stats['latency'][0].get('latency', {})
                if lat:
                    sample = {
                        'average': lat.get('average', 0),
                        'total_min': lat.get('total_min', 0),
                        'total_max': lat.get('total_max', 0),
                        'jitter': lat.get('jitter', 0),
                    }
                    latency_samples.append(sample)
                    
                    if (i + 1) % 10 == 0:
                        print(f"  [{i+1:3d}s] avg={sample['average']:.1f}μs, "
                              f"max={sample['total_max']:.1f}μs, "
                              f"jitter={sample['jitter']:.1f}μs")
        
        self.client.wait_on_traffic()
        
        # Calculate statistics
        if latency_samples:
            avg_latency = sum(s['average'] for s in latency_samples) / len(latency_samples)
            max_latency = max(s['total_max'] for s in latency_samples)
            min_latency = min(s['total_min'] for s in latency_samples if s['total_min'] > 0)
            avg_jitter = sum(s['jitter'] for s in latency_samples) / len(latency_samples)
            
            # Approximate p50 and p99 (sorted averages)
            sorted_avg = sorted([s['average'] for s in latency_samples])
            p50 = sorted_avg[len(sorted_avg) // 2]
            p99 = sorted_avg[int(len(sorted_avg) * 0.99)]
        else:
            avg_latency = max_latency = min_latency = avg_jitter = p50 = p99 = 0
        
        results = {
            'test_name': test_name,
            'duration': duration,
            'samples': len(latency_samples),
            'average_us': avg_latency,
            'min_us': min_latency,
            'max_us': max_latency,
            'p50_us': p50,
            'p99_us': p99,
            'jitter_us': avg_jitter,
        }
        
        self.results[test_name] = results
        self._print_latency_results(results)
        
        return results
    
    def run_flow_scaling_test(self, max_flows: int = 1_000_000,
                               duration: int = 60) -> Dict:
        """
        Test flow table scaling with unique 5-tuples.
        
        Args:
            max_flows: Maximum number of unique flows to generate
            duration: Test duration in seconds
        """
        test_name = "flow_scaling"
        print(f"\n{'='*60}")
        print(f"FLOW SCALING TEST: {max_flows/1e6:.1f}M flows for {duration}s")
        print(f"{'='*60}")
        
        self.client.reset(ports=self.ports)
        
        # Variable source IP and port to create unique flows
        vm = STLScVmRaw([
            STLVmFlowVar(name="src_ip", min_value="10.0.0.1",
                        max_value="10.255.255.254", size=4, op="random"),
            STLVmFlowVar(name="src_port", min_value=1024,
                        max_value=65535, size=2, op="random"),
            STLVmWrFlowVar(fv_name="src_ip", pkt_offset="IP.src"),
            STLVmWrFlowVar(fv_name="src_port", pkt_offset="UDP.sport"),
            STLVmFixIpv4(offset="IP")
        ])
        
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.1.1") / \
              UDP(sport=1024, dport=80) / Raw(b'x' * 18)
        
        # Generate flows at target rate
        flows_per_sec = min(max_flows // duration, self.TARGETS['new_flows_per_sec'])
        
        stream = STLStream(
            packet=STLPktBuilder(pkt=pkt, vm=vm),
            mode=STLTXCont(pps=flows_per_sec)
        )
        
        self.client.add_streams(stream, ports=[0])
        
        print(f"Generating {flows_per_sec/1e6:.2f}M new flows/sec...")
        self.client.start(ports=[0], duration=duration)
        
        for i in range(duration):
            time.sleep(1)
            if (i + 1) % 10 == 0:
                stats = self.client.get_stats()
                tx = stats[0].get('opackets', 0)
                rx = stats[1].get('ipackets', 0)
                loss = ((tx - rx) / tx * 100) if tx > 0 else 0
                print(f"  [{i+1:3d}s] TX: {tx/1e6:.2f}M, RX: {rx/1e6:.2f}M, Loss: {loss:.4f}%")
        
        self.client.wait_on_traffic()
        
        stats = self.client.get_stats()
        tx_pkts = stats[0].get('opackets', 0)
        rx_pkts = stats[1].get('ipackets', 0)
        loss_pct = ((tx_pkts - rx_pkts) / tx_pkts * 100) if tx_pkts > 0 else 0
        
        results = {
            'test_name': test_name,
            'duration': duration,
            'target_flows': max_flows,
            'flows_per_sec': flows_per_sec,
            'tx_packets': tx_pkts,
            'rx_packets': rx_pkts,
            'loss_percent': loss_pct,
            'unique_flows_estimated': min(tx_pkts, max_flows),
        }
        
        self.results[test_name] = results
        self._print_flow_results(results)
        
        return results
    
    def run_imix_test(self, duration: int = 60) -> Dict:
        """
        Run IMIX (Internet Mix) traffic test.
        
        IMIX distribution:
        - 7x 64 bytes (58.33%)
        - 4x 570 bytes (33.33%)
        - 1x 1518 bytes (8.33%)
        """
        test_name = "imix"
        print(f"\n{'='*60}")
        print(f"IMIX TEST: {duration}s duration")
        print(f"{'='*60}")
        
        self.client.reset(ports=self.ports)
        
        streams = []
        imix_config = [
            (64, 58.33),
            (570, 33.33),
            (1518, 8.33),
        ]
        
        for size, percentage in imix_config:
            payload = max(size - 42, 18)
            pkt = Ether() / IP(src="10.0.0.1", dst="10.0.1.1") / \
                  UDP(sport=1024, dport=80) / Raw(b'x' * payload)
            
            stream = STLStream(
                packet=STLPktBuilder(pkt=pkt),
                mode=STLTXCont(percentage=percentage)
            )
            streams.append(stream)
        
        self.client.add_streams(streams, ports=[0])
        
        print("Starting IMIX traffic...")
        self.client.start(ports=[0], duration=duration)
        
        for i in range(duration):
            time.sleep(1)
            if (i + 1) % 10 == 0:
                stats = self.client.get_stats()
                gbps = stats[0].get('tx_bps', 0) / 1e9
                mpps = stats[0].get('tx_pps', 0) / 1e6
                print(f"  [{i+1:3d}s] TX: {gbps:.2f} Gbps, {mpps:.2f} Mpps")
        
        self.client.wait_on_traffic()
        
        stats = self.client.get_stats()
        tx_bytes = stats[0].get('obytes', 0)
        rx_bytes = stats[1].get('ibytes', 0)
        tx_gbps = (tx_bytes * 8) / (duration * 1e9)
        rx_gbps = (rx_bytes * 8) / (duration * 1e9)
        
        results = {
            'test_name': test_name,
            'duration': duration,
            'tx_gbps': tx_gbps,
            'rx_gbps': rx_gbps,
            'loss_percent': ((tx_bytes - rx_bytes) / tx_bytes * 100) if tx_bytes > 0 else 0,
        }
        
        self.results[test_name] = results
        
        # Evaluate
        passed = rx_gbps >= self.TARGETS['throughput_imix_gbps']
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"\n{status}: IMIX throughput {rx_gbps:.2f} Gbps "
              f"(target: ≥{self.TARGETS['throughput_imix_gbps']} Gbps)")
        
        return results
    
    def run_all_tests(self, duration: int = 60):
        """Run all benchmark tests."""
        print("\n" + "="*60)
        print("RUNNING COMPLETE BENCHMARK SUITE")
        print("="*60 + "\n")
        
        # Throughput tests
        for pkt_size in [64, 128, 256, 512, 1024, 1518]:
            self.run_throughput_test(packet_size=pkt_size, duration=duration)
            time.sleep(5)  # Cool-down between tests
        
        # IMIX test
        self.run_imix_test(duration=duration)
        time.sleep(5)
        
        # Latency test
        self.run_latency_test(duration=duration)
        time.sleep(5)
        
        # Flow scaling test
        self.run_flow_scaling_test(max_flows=1_000_000, duration=duration)
    
    def _print_throughput_results(self, results: Dict):
        """Print throughput test results."""
        print(f"\nResults:")
        print(f"  TX: {results['tx_mpps']:.2f} Mpps ({results['tx_gbps']:.2f} Gbps)")
        print(f"  RX: {results['rx_mpps']:.2f} Mpps ({results['rx_gbps']:.2f} Gbps)")
        print(f"  Loss: {results['loss_percent']:.4f}%")
        
        # Evaluate against targets
        if results['packet_size'] <= 64:
            target = self.TARGETS['throughput_64b_mpps']
            actual = results['rx_mpps']
            unit = "Mpps"
        else:
            target = self.TARGETS['throughput_1518b_gbps']
            actual = results['rx_gbps']
            unit = "Gbps"
        
        passed = actual >= target
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"\n{status}: {actual:.2f} {unit} (target: ≥{target} {unit})")
    
    def _print_latency_results(self, results: Dict):
        """Print latency test results."""
        print(f"\nResults:")
        print(f"  Average: {results['average_us']:.2f} μs")
        print(f"  Min:     {results['min_us']:.2f} μs")
        print(f"  Max:     {results['max_us']:.2f} μs")
        print(f"  P50:     {results['p50_us']:.2f} μs")
        print(f"  P99:     {results['p99_us']:.2f} μs")
        print(f"  Jitter:  {results['jitter_us']:.2f} μs")
        
        p50_pass = results['p50_us'] <= self.TARGETS['latency_p50_us']
        p99_pass = results['p99_us'] <= self.TARGETS['latency_p99_us']
        
        print(f"\n{'✓ PASS' if p50_pass else '✗ FAIL'}: P50 latency "
              f"{results['p50_us']:.2f} μs (target: ≤{self.TARGETS['latency_p50_us']} μs)")
        print(f"{'✓ PASS' if p99_pass else '✗ FAIL'}: P99 latency "
              f"{results['p99_us']:.2f} μs (target: ≤{self.TARGETS['latency_p99_us']} μs)")
    
    def _print_flow_results(self, results: Dict):
        """Print flow scaling test results."""
        print(f"\nResults:")
        print(f"  Flows/sec: {results['flows_per_sec']/1e6:.2f}M")
        print(f"  Total flows: ~{results['unique_flows_estimated']/1e6:.2f}M")
        print(f"  Loss: {results['loss_percent']:.4f}%")
        
        passed = results['flows_per_sec'] >= self.TARGETS['new_flows_per_sec']
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"\n{status}: {results['flows_per_sec']/1e6:.2f}M flows/sec "
              f"(target: ≥{self.TARGETS['new_flows_per_sec']/1e6:.0f}M)")
    
    def print_summary(self):
        """Print summary of all test results."""
        print("\n" + "="*60)
        print("BENCHMARK SUMMARY")
        print("="*60 + "\n")
        
        all_passed = True
        
        for name, result in self.results.items():
            if 'throughput' in name:
                if result.get('packet_size', 0) <= 64:
                    target = self.TARGETS['throughput_64b_mpps']
                    actual = result.get('rx_mpps', 0)
                    passed = actual >= target
                    print(f"  {'✓' if passed else '✗'} {name}: "
                          f"{actual:.2f} Mpps (target: ≥{target})")
                else:
                    target = self.TARGETS['throughput_1518b_gbps']
                    actual = result.get('rx_gbps', 0)
                    passed = actual >= target
                    print(f"  {'✓' if passed else '✗'} {name}: "
                          f"{actual:.2f} Gbps (target: ≥{target})")
            elif name == 'latency':
                p50 = result.get('p50_us', 0)
                p99 = result.get('p99_us', 0)
                p50_pass = p50 <= self.TARGETS['latency_p50_us']
                p99_pass = p99 <= self.TARGETS['latency_p99_us']
                passed = p50_pass and p99_pass
                print(f"  {'✓' if passed else '✗'} {name}: "
                      f"P50={p50:.1f}μs, P99={p99:.1f}μs")
            elif name == 'imix':
                actual = result.get('rx_gbps', 0)
                target = self.TARGETS['throughput_imix_gbps']
                passed = actual >= target
                print(f"  {'✓' if passed else '✗'} {name}: "
                      f"{actual:.2f} Gbps (target: ≥{target})")
            elif name == 'flow_scaling':
                actual = result.get('flows_per_sec', 0)
                target = self.TARGETS['new_flows_per_sec']
                passed = actual >= target
                print(f"  {'✓' if passed else '✗'} {name}: "
                      f"{actual/1e6:.2f}M flows/sec")
            
            if not passed:
                all_passed = False
        
        print(f"\n{'='*60}")
        final = "ALL TESTS PASSED ✓" if all_passed else "SOME TESTS FAILED ✗"
        print(f"  {final}")
        print(f"{'='*60}\n")
    
    def save_results(self, filename: Optional[str] = None):
        """Save results to JSON file."""
        if not filename:
            filename = f"benchmark_results_{self.timestamp}.json"
        
        output = {
            'timestamp': self.timestamp,
            'targets': self.TARGETS,
            'results': self.results,
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"Results saved to: {filename}")


def main():
    parser = argparse.ArgumentParser(
        description="OpenSASE VPP Performance Benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Test options:
  throughput  - Run throughput tests (all packet sizes)
  latency     - Run latency measurement test
  flows       - Run flow scaling test
  imix        - Run IMIX traffic test
  all         - Run complete benchmark suite
        """
    )
    parser.add_argument("--server", default="127.0.0.1",
                       help="TRex server address")
    parser.add_argument("--test", default="all",
                       choices=["throughput", "latency", "flows", "imix", "all"],
                       help="Test to run")
    parser.add_argument("--duration", type=int, default=60,
                       help="Test duration in seconds")
    parser.add_argument("--output", help="Output file for results")
    
    args = parser.parse_args()
    
    benchmark = VPPBenchmark(server=args.server)
    
    try:
        benchmark.connect()
        
        if args.test == "throughput":
            for size in [64, 128, 256, 512, 1024, 1518]:
                benchmark.run_throughput_test(packet_size=size, duration=args.duration)
        elif args.test == "latency":
            benchmark.run_latency_test(duration=args.duration)
        elif args.test == "flows":
            benchmark.run_flow_scaling_test(duration=args.duration)
        elif args.test == "imix":
            benchmark.run_imix_test(duration=args.duration)
        elif args.test == "all":
            benchmark.run_all_tests(duration=args.duration)
        
        benchmark.print_summary()
        benchmark.save_results(args.output)
        
    except STLError as e:
        print(f"TRex error: {e}")
        sys.exit(1)
    finally:
        benchmark.disconnect()


if __name__ == "__main__":
    main()
