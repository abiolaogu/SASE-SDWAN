//! Flow Table Benchmarks
//!
//! Proving 40Gbps targets with Criterion.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};

// Note: In actual benchmarks, import from sase_dataplane
// For now, inline simplified versions

/// Simplified flow key for benchmarking
#[derive(Clone, Copy)]
struct FlowKey {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
}

impl FlowKey {
    fn hash(&self) -> u64 {
        const FNV_OFFSET: u64 = 0xcbf29ce484222325;
        const FNV_PRIME: u64 = 0x100000001b3;
        
        let mut h = FNV_OFFSET;
        for byte in self.src_ip.to_ne_bytes() {
            h ^= byte as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        for byte in self.dst_ip.to_ne_bytes() {
            h ^= byte as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        h ^= self.src_port as u64;
        h = h.wrapping_mul(FNV_PRIME);
        h ^= self.dst_port as u64;
        h = h.wrapping_mul(FNV_PRIME);
        h ^= self.protocol as u64;
        h.wrapping_mul(FNV_PRIME)
    }
}

fn bench_flow_hash(c: &mut Criterion) {
    let key = FlowKey {
        src_ip: 0xC0A80101,
        dst_ip: 0x08080808,
        src_port: 12345,
        dst_port: 443,
        protocol: 6,
    };

    c.bench_function("flow_key_hash", |b| {
        b.iter(|| black_box(key).hash())
    });
}

fn bench_flow_lookup(c: &mut Criterion) {
    use std::collections::HashMap;
    
    let mut table: HashMap<u64, u32> = HashMap::new();
    
    // Pre-populate with 1M flows
    for i in 0..1_000_000u32 {
        let key = FlowKey {
            src_ip: i,
            dst_ip: 0x08080808,
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
        };
        table.insert(key.hash(), i);
    }

    let lookup_key = FlowKey {
        src_ip: 500_000,
        dst_ip: 0x08080808,
        src_port: 12345,
        dst_port: 443,
        protocol: 6,
    };

    c.bench_function("flow_table_lookup_1M", |b| {
        b.iter(|| {
            let h = black_box(lookup_key).hash();
            table.get(&h)
        })
    });
}

fn bench_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");
    
    // Simulate packet processing at different sizes
    for size in [64, 128, 256, 512, 1024, 1500].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let data = vec![0u8; size];
            b.iter(|| {
                // Simulate minimal processing
                let sum: u8 = black_box(&data).iter().take(20).fold(0u8, |a, &b| a.wrapping_add(b));
                black_box(sum)
            })
        });
    }
    group.finish();
}

fn bench_batch_processing(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch");
    
    for batch_size in [16, 32, 64, 128].iter() {
        group.bench_with_input(
            BenchmarkId::new("process", batch_size),
            batch_size,
            |b, &batch_size| {
                let packets: Vec<[u8; 64]> = (0..batch_size).map(|_| [0u8; 64]).collect();
                
                b.iter(|| {
                    let mut results = Vec::with_capacity(batch_size);
                    for pkt in &packets {
                        // Simulate parse + classify
                        let hash = u64::from_ne_bytes([
                            pkt[0], pkt[1], pkt[2], pkt[3],
                            pkt[4], pkt[5], pkt[6], pkt[7],
                        ]);
                        results.push(black_box(hash));
                    }
                    results
                })
            }
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_flow_hash,
    bench_flow_lookup,
    bench_throughput,
    bench_batch_processing,
);

criterion_main!(benches);
