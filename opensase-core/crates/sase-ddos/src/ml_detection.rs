//! ML-Powered Attack Detection
//!
//! Baseline learning and anomaly detection for <100μs detection.

use crate::{Attack, AttackType, AttackMetrics, AttackTarget, AttackSource, AttackStatus, Protocol};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use dashmap::DashMap;
use parking_lot::RwLock;

/// ML-powered attack detector
pub struct MlDetector {
    /// Baseline model trained on normal traffic
    baseline: Arc<RwLock<BaselineModel>>,
    /// Feature extractor
    feature_extractor: FeatureExtractor,
    /// Attack classifier
    classifier: AttackClassifier,
    /// Per-destination metrics buffer
    metrics_buffer: DashMap<IpAddr, MetricsBuffer>,
    /// Global metrics
    global_metrics: Arc<RwLock<GlobalMetrics>>,
    /// Detection config
    config: MlDetectionConfig,
}

#[derive(Debug, Clone)]
pub struct MlDetectionConfig {
    /// Anomaly threshold (0-1)
    pub anomaly_threshold: f64,
    /// Minimum samples for detection
    pub min_samples: u64,
    /// Detection window in ms
    pub window_ms: u64,
    /// Baseline learning rate
    pub learning_rate: f64,
}

impl Default for MlDetectionConfig {
    fn default() -> Self {
        Self {
            anomaly_threshold: 0.8,
            min_samples: 100,
            window_ms: 100,
            learning_rate: 0.01,
        }
    }
}

/// Traffic features for ML analysis
#[derive(Debug, Clone, Default)]
pub struct TrafficFeatures {
    // Rate metrics
    pub pps: f64,
    pub bps: f64,
    pub new_flows_per_sec: f64,
    
    // Protocol distribution
    pub tcp_ratio: f64,
    pub udp_ratio: f64,
    pub icmp_ratio: f64,
    
    // TCP flags distribution
    pub syn_ratio: f64,
    pub ack_ratio: f64,
    pub rst_ratio: f64,
    pub fin_ratio: f64,
    
    // Packet size distribution
    pub avg_packet_size: f64,
    pub packet_size_stddev: f64,
    pub small_packet_ratio: f64,
    
    // Source diversity
    pub unique_sources: u64,
    pub source_entropy: f64,
    pub top_source_ratio: f64,
    
    // Destination diversity
    pub unique_destinations: u64,
    pub unique_dest_ports: u64,
    
    // Temporal patterns
    pub inter_arrival_mean: f64,
    pub inter_arrival_stddev: f64,
}

impl TrafficFeatures {
    /// Convert to feature vector for ML
    pub fn to_vector(&self) -> Vec<f64> {
        vec![
            self.pps,
            self.bps,
            self.new_flows_per_sec,
            self.tcp_ratio,
            self.udp_ratio,
            self.icmp_ratio,
            self.syn_ratio,
            self.ack_ratio,
            self.rst_ratio,
            self.fin_ratio,
            self.avg_packet_size,
            self.packet_size_stddev,
            self.small_packet_ratio,
            self.unique_sources as f64,
            self.source_entropy,
            self.top_source_ratio,
            self.unique_destinations as f64,
            self.unique_dest_ports as f64,
            self.inter_arrival_mean,
            self.inter_arrival_stddev,
        ]
    }
}

/// Baseline model trained on normal traffic
#[derive(Debug, Clone)]
pub struct BaselineModel {
    /// Mean of each feature
    pub mean: Vec<f64>,
    /// Standard deviation of each feature
    pub std: Vec<f64>,
    /// Time-of-day profiles
    pub hourly_profiles: [TrafficFeatures; 24],
    /// Day-of-week profiles
    pub daily_profiles: [TrafficFeatures; 7],
    /// Sample count
    pub sample_count: u64,
}

impl Default for BaselineModel {
    fn default() -> Self {
        Self {
            mean: vec![0.0; 20],
            std: vec![1.0; 20],
            hourly_profiles: Default::default(),
            daily_profiles: Default::default(),
            sample_count: 0,
        }
    }
}

impl BaselineModel {
    /// Update baseline with new sample
    pub fn update(&mut self, features: &TrafficFeatures, learning_rate: f64) {
        let vec = features.to_vector();
        
        for (i, (m, v)) in self.mean.iter_mut().zip(vec.iter()).enumerate() {
            let delta = v - *m;
            *m += learning_rate * delta;
            
            // Update variance estimate
            if self.sample_count > 0 {
                let variance = (v - *m).powi(2);
                let old_var = self.std[i].powi(2);
                self.std[i] = ((1.0 - learning_rate) * old_var + learning_rate * variance).sqrt();
            }
        }
        
        self.sample_count += 1;
    }
    
    /// Calculate anomaly score (0-1)
    pub fn anomaly_score(&self, features: &TrafficFeatures) -> f64 {
        let vec = features.to_vector();
        
        let z_scores: Vec<f64> = vec.iter()
            .zip(self.mean.iter())
            .zip(self.std.iter())
            .map(|((v, m), s)| {
                if *s > 0.0 { (v - m).abs() / s } else { 0.0 }
            })
            .collect();
        
        // Normalize to 0-1 using sigmoid-like function
        let max_z = z_scores.iter().cloned().fold(0.0, f64::max);
        let high_z_count = z_scores.iter().filter(|z| **z > 3.0).count();
        
        // Score based on number of anomalous features and max deviation
        let score = (high_z_count as f64 / 20.0 * 0.5) + (1.0 - 1.0 / (1.0 + max_z / 5.0)) * 0.5;
        
        score.min(1.0)
    }
}

/// Attack classifier using decision tree
pub struct AttackClassifier;

impl AttackClassifier {
    pub fn new() -> Self {
        Self
    }
    
    /// Classify attack type based on traffic features
    pub fn classify(&self, features: &TrafficFeatures) -> AttackType {
        // Decision tree based on traffic characteristics
        
        // UDP-based attacks
        if features.udp_ratio > 0.9 {
            if features.avg_packet_size > 1000.0 {
                // Large UDP packets - amplification
                return AttackType::DnsAmplification;
            }
            return AttackType::UdpFlood;
        }
        
        // TCP-based attacks
        if features.tcp_ratio > 0.8 {
            if features.syn_ratio > 0.9 {
                return AttackType::SynFlood;
            }
            if features.ack_ratio > 0.9 && features.syn_ratio < 0.1 {
                return AttackType::AckFlood;
            }
            if features.rst_ratio > 0.8 {
                return AttackType::RstFlood;
            }
            if features.small_packet_ratio > 0.95 && features.unique_sources > 1000 {
                return AttackType::HttpFlood;
            }
        }
        
        // ICMP flood
        if features.icmp_ratio > 0.7 {
            return AttackType::IcmpFlood;
        }
        
        // Multi-vector
        if features.tcp_ratio > 0.3 && features.udp_ratio > 0.3 {
            return AttackType::MultiVector;
        }
        
        AttackType::Unknown
    }
}

impl Default for AttackClassifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Feature extractor from raw traffic
pub struct FeatureExtractor {
    /// Packet size bins
    size_bins: [u64; 10],
    /// Protocol counters
    proto_counts: HashMap<Protocol, u64>,
}

impl FeatureExtractor {
    pub fn new() -> Self {
        Self {
            size_bins: [0; 10],
            proto_counts: HashMap::new(),
        }
    }
    
    /// Extract features from metrics buffer
    pub fn extract(&self, buffer: &MetricsBuffer) -> TrafficFeatures {
        let duration_sec = buffer.duration_seconds().max(0.001);
        
        let total_packets = buffer.total_packets;
        let total_bytes = buffer.total_bytes;
        
        TrafficFeatures {
            pps: total_packets as f64 / duration_sec,
            bps: total_bytes as f64 * 8.0 / duration_sec,
            new_flows_per_sec: buffer.new_flows as f64 / duration_sec,
            
            tcp_ratio: buffer.tcp_packets as f64 / total_packets.max(1) as f64,
            udp_ratio: buffer.udp_packets as f64 / total_packets.max(1) as f64,
            icmp_ratio: buffer.icmp_packets as f64 / total_packets.max(1) as f64,
            
            syn_ratio: buffer.syn_packets as f64 / buffer.tcp_packets.max(1) as f64,
            ack_ratio: buffer.ack_packets as f64 / buffer.tcp_packets.max(1) as f64,
            rst_ratio: buffer.rst_packets as f64 / buffer.tcp_packets.max(1) as f64,
            fin_ratio: buffer.fin_packets as f64 / buffer.tcp_packets.max(1) as f64,
            
            avg_packet_size: total_bytes as f64 / total_packets.max(1) as f64,
            packet_size_stddev: 0.0, // Would calculate from samples
            small_packet_ratio: buffer.small_packets as f64 / total_packets.max(1) as f64,
            
            unique_sources: buffer.unique_sources.len() as u64,
            source_entropy: calculate_entropy(&buffer.source_counts),
            top_source_ratio: buffer.top_source_packets as f64 / total_packets.max(1) as f64,
            
            unique_destinations: buffer.unique_dests.len() as u64,
            unique_dest_ports: buffer.unique_ports.len() as u64,
            
            inter_arrival_mean: 0.0,
            inter_arrival_stddev: 0.0,
        }
    }
}

impl Default for FeatureExtractor {
    fn default() -> Self {
        Self::new()
    }
}

/// Metrics buffer for a time window
#[derive(Debug, Clone, Default)]
pub struct MetricsBuffer {
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub tcp_packets: u64,
    pub udp_packets: u64,
    pub icmp_packets: u64,
    pub syn_packets: u64,
    pub ack_packets: u64,
    pub rst_packets: u64,
    pub fin_packets: u64,
    pub small_packets: u64,
    pub new_flows: u64,
    pub unique_sources: std::collections::HashSet<IpAddr>,
    pub unique_dests: std::collections::HashSet<IpAddr>,
    pub unique_ports: std::collections::HashSet<u16>,
    pub source_counts: HashMap<IpAddr, u64>,
    pub top_source_packets: u64,
}

impl MetricsBuffer {
    pub fn duration_seconds(&self) -> f64 {
        self.start_time
            .map(|s| (chrono::Utc::now() - s).num_milliseconds() as f64 / 1000.0)
            .unwrap_or(0.0)
    }
    
    pub fn reset(&mut self) {
        *self = Self::default();
        self.start_time = Some(chrono::Utc::now());
    }
}

/// Global metrics aggregator
#[derive(Debug, Default)]
pub struct GlobalMetrics {
    pub total_pps: f64,
    pub total_bps: f64,
    pub active_attacks: u64,
    pub mitigations_active: u64,
}

impl MlDetector {
    pub fn new(config: MlDetectionConfig) -> Self {
        Self {
            baseline: Arc::new(RwLock::new(BaselineModel::default())),
            feature_extractor: FeatureExtractor::new(),
            classifier: AttackClassifier::new(),
            metrics_buffer: DashMap::new(),
            global_metrics: Arc::new(RwLock::new(GlobalMetrics::default())),
            config,
        }
    }
    
    /// Analyze traffic and detect attacks
    pub async fn analyze(&self, destination: IpAddr) -> Option<Attack> {
        let buffer = self.metrics_buffer.get(&destination)?;
        
        if buffer.total_packets < self.config.min_samples {
            return None;
        }
        
        // Extract features
        let features = self.feature_extractor.extract(&buffer);
        
        // Calculate anomaly score
        let baseline = self.baseline.read();
        let score = baseline.anomaly_score(&features);
        
        if score < self.config.anomaly_threshold {
            // Update baseline with normal traffic
            drop(baseline);
            self.baseline.write().update(&features, self.config.learning_rate);
            return None;
        }
        
        // Classify attack
        let attack_type = self.classifier.classify(&features);
        
        // Build attack signature
        Some(Attack {
            id: uuid::Uuid::new_v4().to_string(),
            attack_type,
            target: AttackTarget {
                ip: destination,
                port: None,
                protocol: Protocol::Tcp,
                customer_id: None,
            },
            sources: self.get_top_sources(&buffer, 10),
            metrics: AttackMetrics {
                total_pps: features.pps as u64,
                total_bps: features.bps as u64,
                peak_pps: features.pps as u64,
                peak_bps: features.bps as u64,
                unique_sources: features.unique_sources,
                avg_packet_size: features.avg_packet_size as u32,
                protocol_distribution: HashMap::new(),
            },
            started_at: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
            status: AttackStatus::Detected,
            mitigation: None,
        })
    }
    
    fn get_top_sources(&self, buffer: &MetricsBuffer, limit: usize) -> Vec<AttackSource> {
        let mut sources: Vec<_> = buffer.source_counts.iter()
            .map(|(ip, count)| AttackSource {
                ip: *ip,
                network: None,
                asn: None,
                country: None,
                pps: *count,
                bps: 0,
                is_spoofed: false,
            })
            .collect();
        
        sources.sort_by(|a, b| b.pps.cmp(&a.pps));
        sources.truncate(limit);
        sources
    }
}

/// Calculate Shannon entropy
fn calculate_entropy(counts: &HashMap<IpAddr, u64>) -> f64 {
    let total: u64 = counts.values().sum();
    if total == 0 {
        return 0.0;
    }
    
    counts.values()
        .map(|&c| {
            let p = c as f64 / total as f64;
            if p > 0.0 { -p * p.log2() } else { 0.0 }
        })
        .sum()
}
