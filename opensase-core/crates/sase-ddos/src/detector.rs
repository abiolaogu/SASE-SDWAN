//! Attack Detection Engine
//!
//! <100μs detection latency with multi-stage analysis.

use crate::{
    Attack, AttackMetrics, AttackSource, AttackStatus, AttackTarget, AttackType,
    DetectionConfig, Protocol, TrafficBaseline, TrafficSample,
};
use dashmap::DashMap;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Attack detector with line-rate analysis
pub struct AttackDetector {
    config: DetectionConfig,
    /// Per-destination traffic counters
    destination_stats: DashMap<IpAddr, DestinationStats>,
    /// Per-source tracking for source profiling
    source_stats: DashMap<IpAddr, SourceStats>,
    /// Recent attack fingerprints for dedup
    recent_attacks: DashMap<String, Instant>,
    /// Global counters
    total_samples: AtomicU64,
    total_attacks: AtomicU64,
}

#[derive(Default)]
struct DestinationStats {
    pps: AtomicU64,
    bps: AtomicU64,
    syn_count: AtomicU64,
    ack_count: AtomicU64,
    udp_count: AtomicU64,
    icmp_count: AtomicU64,
    unique_sources: AtomicU64,
    last_window_start: parking_lot::Mutex<Instant>,
    source_ips: parking_lot::Mutex<Vec<IpAddr>>,
}

#[derive(Default)]
struct SourceStats {
    pps: AtomicU64,
    bps: AtomicU64,
    first_seen: parking_lot::Mutex<Option<Instant>>,
    packet_sizes: parking_lot::Mutex<Vec<u32>>,
}

impl AttackDetector {
    pub fn new(config: DetectionConfig) -> Self {
        Self {
            config,
            destination_stats: DashMap::new(),
            source_stats: DashMap::new(),
            recent_attacks: DashMap::new(),
            total_samples: AtomicU64::new(0),
            total_attacks: AtomicU64::new(0),
        }
    }
    
    /// Analyze traffic sample for attacks
    pub async fn analyze(
        &self,
        sample: &TrafficSample,
        baseline: Option<&TrafficBaseline>,
    ) -> Option<Attack> {
        self.total_samples.fetch_add(1, Ordering::Relaxed);
        
        // Update counters
        self.update_stats(sample);
        
        // Get or create destination stats
        let dest_stats = self.destination_stats
            .entry(sample.destination)
            .or_default();
        
        // Check detection window
        let window_ms = self.config.detection_window_ms;
        let now = Instant::now();
        
        {
            let mut last_start = dest_stats.last_window_start.lock();
            if now.duration_since(*last_start).as_millis() as u64 >= window_ms {
                // New window - check for attacks
                let attack = self.detect_in_window(&dest_stats, sample, baseline);
                
                // Reset window
                *last_start = now;
                self.reset_window_stats(&dest_stats);
                
                if attack.is_some() {
                    self.total_attacks.fetch_add(1, Ordering::Relaxed);
                }
                
                return attack;
            }
        }
        
        None
    }
    
    fn update_stats(&self, sample: &TrafficSample) {
        // Update destination stats
        let dest = self.destination_stats
            .entry(sample.destination)
            .or_default();
        
        dest.pps.fetch_add(sample.pps, Ordering::Relaxed);
        dest.bps.fetch_add(sample.bps, Ordering::Relaxed);
        
        // Track protocol
        match sample.protocol {
            Protocol::Tcp => {
                if let Some(flags) = sample.tcp_flags {
                    if flags & 0x02 != 0 { // SYN
                        dest.syn_count.fetch_add(1, Ordering::Relaxed);
                    }
                    if flags & 0x10 != 0 { // ACK
                        dest.ack_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            Protocol::Udp => {
                dest.udp_count.fetch_add(sample.pps, Ordering::Relaxed);
            }
            Protocol::Icmp => {
                dest.icmp_count.fetch_add(sample.pps, Ordering::Relaxed);
            }
            _ => {}
        }
        
        // Track unique sources
        {
            let mut sources = dest.source_ips.lock();
            if !sources.contains(&sample.source) && sources.len() < 100000 {
                sources.push(sample.source);
                dest.unique_sources.fetch_add(1, Ordering::Relaxed);
            }
        }
        
        // Update source stats
        let src = self.source_stats
            .entry(sample.source)
            .or_default();
        
        src.pps.fetch_add(sample.pps, Ordering::Relaxed);
        src.bps.fetch_add(sample.bps, Ordering::Relaxed);
        
        {
            let mut sizes = src.packet_sizes.lock();
            if sizes.len() < 1000 {
                sizes.push(sample.packet_size);
            }
        }
    }
    
    fn detect_in_window(
        &self,
        stats: &DestinationStats,
        sample: &TrafficSample,
        baseline: Option<&TrafficBaseline>,
    ) -> Option<Attack> {
        let pps = stats.pps.load(Ordering::Relaxed);
        let bps = stats.bps.load(Ordering::Relaxed);
        
        // Check minimum thresholds
        if pps < self.config.min_pps_threshold {
            return None;
        }
        
        // Check against baseline
        if let Some(bl) = baseline {
            if !bl.is_anomaly(pps, bps, self.config.anomaly_threshold) {
                return None;
            }
        }
        
        // Determine attack type
        let attack_type = self.classify_attack(stats, sample);
        
        // Check cooldown
        let fingerprint = format!("{}-{:?}", sample.destination, attack_type);
        if let Some(last_seen) = self.recent_attacks.get(&fingerprint) {
            if last_seen.elapsed().as_secs() < self.config.cooldown_seconds {
                return None;
            }
        }
        self.recent_attacks.insert(fingerprint, Instant::now());
        
        // Build attack info
        let sources = self.get_top_sources(sample.destination, 10);
        
        Some(Attack {
            id: uuid::Uuid::new_v4().to_string(),
            attack_type,
            target: AttackTarget {
                ip: sample.destination,
                port: Some(sample.dst_port),
                protocol: sample.protocol,
                customer_id: None,
            },
            sources,
            metrics: AttackMetrics {
                total_pps: pps,
                total_bps: bps,
                peak_pps: pps,
                peak_bps: bps,
                unique_sources: stats.unique_sources.load(Ordering::Relaxed),
                avg_packet_size: if pps > 0 { (bps / pps / 8) as u32 } else { 0 },
                protocol_distribution: HashMap::new(),
            },
            started_at: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
            status: AttackStatus::Detected,
            mitigation: None,
        })
    }
    
    fn classify_attack(&self, stats: &DestinationStats, sample: &TrafficSample) -> AttackType {
        let syn_count = stats.syn_count.load(Ordering::Relaxed);
        let ack_count = stats.ack_count.load(Ordering::Relaxed);
        let udp_count = stats.udp_count.load(Ordering::Relaxed);
        let icmp_count = stats.icmp_count.load(Ordering::Relaxed);
        let pps = stats.pps.load(Ordering::Relaxed);
        
        // SYN flood: high SYN ratio
        if pps > 0 {
            let syn_ratio = syn_count as f64 / pps as f64;
            if syn_ratio > self.config.syn_ratio_threshold {
                return AttackType::SynFlood;
            }
        }
        
        // UDP-based attacks
        if udp_count > pps / 2 {
            return match sample.dst_port {
                53 => AttackType::DnsAmplification,
                123 => AttackType::NtpAmplification,
                1900 => AttackType::SsdpAmplification,
                11211 => AttackType::MemcachedAmplification,
                _ => AttackType::UdpFlood,
            };
        }
        
        // ICMP flood
        if icmp_count > pps / 2 {
            return AttackType::IcmpFlood;
        }
        
        // ACK flood
        if ack_count > syn_count * 10 {
            return AttackType::AckFlood;
        }
        
        AttackType::Unknown
    }
    
    fn get_top_sources(&self, _destination: IpAddr, limit: usize) -> Vec<AttackSource> {
        let mut sources: Vec<_> = self.source_stats.iter()
            .map(|entry| {
                let ip = *entry.key();
                let stats = entry.value();
                AttackSource {
                    ip,
                    network: None,
                    asn: None,
                    country: None,
                    pps: stats.pps.load(Ordering::Relaxed),
                    bps: stats.bps.load(Ordering::Relaxed),
                    is_spoofed: false,
                }
            })
            .collect();
        
        sources.sort_by(|a, b| b.pps.cmp(&a.pps));
        sources.truncate(limit);
        sources
    }
    
    fn reset_window_stats(&self, stats: &DestinationStats) {
        stats.pps.store(0, Ordering::Relaxed);
        stats.bps.store(0, Ordering::Relaxed);
        stats.syn_count.store(0, Ordering::Relaxed);
        stats.ack_count.store(0, Ordering::Relaxed);
        stats.udp_count.store(0, Ordering::Relaxed);
        stats.icmp_count.store(0, Ordering::Relaxed);
        stats.unique_sources.store(0, Ordering::Relaxed);
        stats.source_ips.lock().clear();
    }
    
    /// Calculate entropy of source IP distribution
    pub fn calculate_source_entropy(&self, destination: IpAddr) -> f64 {
        if let Some(stats) = self.destination_stats.get(&destination) {
            let sources = stats.source_ips.lock();
            let total = sources.len() as f64;
            if total == 0.0 {
                return 0.0;
            }
            
            // Count occurrences
            let mut counts: HashMap<IpAddr, usize> = HashMap::new();
            for ip in sources.iter() {
                *counts.entry(*ip).or_default() += 1;
            }
            
            // Calculate Shannon entropy
            let entropy: f64 = counts.values()
                .map(|&count| {
                    let p = count as f64 / total;
                    if p > 0.0 { -p * p.log2() } else { 0.0 }
                })
                .sum();
            
            entropy
        } else {
            0.0
        }
    }
}
