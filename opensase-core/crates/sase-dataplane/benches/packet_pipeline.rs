//! Packet Pipeline Benchmarks

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

fn bench_parse_ipv4(c: &mut Criterion) {
    // Minimal IPv4 packet (Ethernet + IP + TCP)
    let packet: [u8; 54] = [
        // Ethernet (14 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // dst mac
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // src mac
        0x08, 0x00,  // IPv4
        // IPv4 (20 bytes)
        0x45, 0x00, 0x00, 0x28,  // ver, ihl, tos, len
        0x00, 0x00, 0x40, 0x00,  // id, flags, frag
        0x40, 0x06, 0x00, 0x00,  // ttl, proto (TCP), checksum
        0xC0, 0xA8, 0x01, 0x01,  // src ip: 192.168.1.1
        0x0A, 0x00, 0x00, 0x01,  // dst ip: 10.0.0.1
        // TCP (20 bytes)
        0x30, 0x39, 0x01, 0xBB,  // src port: 12345, dst port: 443
        0x00, 0x00, 0x00, 0x00,  // seq
        0x00, 0x00, 0x00, 0x00,  // ack
        0x50, 0x02, 0x00, 0x00,  // offset, flags
        0x00, 0x00, 0x00, 0x00,  // checksum, urgent
    ];

    c.bench_function("parse_ipv4_packet", |b| {
        b.iter(|| {
            let data = black_box(&packet);
            // Parse Ethernet
            let ethertype = u16::from_be_bytes([data[12], data[13]]);
            // Parse IPv4
            let src_ip = u32::from_be_bytes([data[26], data[27], data[28], data[29]]);
            let dst_ip = u32::from_be_bytes([data[30], data[31], data[32], data[33]]);
            let protocol = data[23];
            // Parse TCP
            let src_port = u16::from_be_bytes([data[34], data[35]]);
            let dst_port = u16::from_be_bytes([data[36], data[37]]);
            
            black_box((ethertype, src_ip, dst_ip, protocol, src_port, dst_port))
        })
    });
}

fn bench_dscp_mark(c: &mut Criterion) {
    let mut packet = [0u8; 54];
    packet[12] = 0x08; packet[13] = 0x00;  // IPv4
    packet[14] = 0x45;  // IP header

    c.bench_function("dscp_mark", |b| {
        b.iter(|| {
            let pkt = black_box(&mut packet.clone());
            let dscp = 46u8;  // EF
            let ecn = pkt[15] & 0x03;
            pkt[15] = (dscp << 2) | ecn;
            black_box(pkt)
        })
    });
}

fn bench_nat_rewrite(c: &mut Criterion) {
    let mut packet = [0u8; 54];
    packet[26..30].copy_from_slice(&[192, 168, 1, 1]);  // Original src

    let new_ip: [u8; 4] = [10, 0, 0, 1];

    c.bench_function("nat_ip_rewrite", |b| {
        b.iter(|| {
            let pkt = black_box(&mut packet.clone());
            pkt[26..30].copy_from_slice(&new_ip);
            black_box(pkt)
        })
    });
}

fn bench_pipeline_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("pipeline_throughput");
    
    group.throughput(Throughput::Bytes(1500 * 64));  // 64 packets of 1500 bytes
    
    group.bench_function("64_packets", |b| {
        let packets: Vec<[u8; 64]> = (0..64).map(|i| {
            let mut p = [0u8; 64];
            p[12] = 0x08; p[13] = 0x00;
            p[14] = 0x45;
            p[23] = 6;
            p[26..30].copy_from_slice(&(i as u32).to_be_bytes());
            p
        }).collect();
        
        b.iter(|| {
            let mut results = 0u64;
            for pkt in &packets {
                // Simulate full pipeline
                let src_ip = u32::from_be_bytes([pkt[26], pkt[27], pkt[28], pkt[29]]);
                results += src_ip as u64;
            }
            black_box(results)
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_parse_ipv4,
    bench_dscp_mark,
    bench_nat_rewrite,
    bench_pipeline_throughput,
);

criterion_main!(benches);
