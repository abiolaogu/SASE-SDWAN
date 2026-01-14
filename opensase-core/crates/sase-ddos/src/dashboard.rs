//! Real-Time DDoS Dashboard
//!
//! WebSocket-based attack monitoring and alerting.

use crate::{Attack, AttackType, AttackStatus, MitigationStats};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::broadcast;

/// Real-time DDoS dashboard
pub struct Dashboard {
    /// Broadcast channel for attack events
    event_tx: broadcast::Sender<AttackEvent>,
    /// Active attacks
    active_attacks: dashmap::DashMap<String, AttackTracking>,
    /// Global statistics
    stats: DashboardStats,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AttackEvent {
    pub event_type: AttackEventType,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub attack_id: String,
    pub attack_type: String,
    pub target: String,
    pub metrics: EventMetrics,
    pub mitigation_status: String,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackEventType {
    Detected,
    Updated,
    Mitigating,
    Mitigated,
    Ended,
    Escalated,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct EventMetrics {
    pub current_pps: u64,
    pub current_bps: u64,
    pub peak_pps: u64,
    pub peak_bps: u64,
    pub unique_sources: u64,
    pub packets_dropped: u64,
    pub packets_passed: u64,
    pub mitigation_effectiveness: f64,
}

/// Tracking data for active attack
struct AttackTracking {
    attack: Attack,
    started_at: chrono::DateTime<chrono::Utc>,
    peak_pps: AtomicU64,
    peak_bps: AtomicU64,
    total_packets: AtomicU64,
    total_bytes: AtomicU64,
    packets_dropped: AtomicU64,
    packets_passed: AtomicU64,
}

#[derive(Debug, Default)]
struct DashboardStats {
    attacks_detected: AtomicU64,
    attacks_mitigated: AtomicU64,
    total_packets_dropped: AtomicU64,
    total_bytes_dropped: AtomicU64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DashboardSnapshot {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub active_attacks: usize,
    pub attacks_detected_total: u64,
    pub attacks_mitigated_total: u64,
    pub total_packets_dropped: u64,
    pub total_bytes_dropped: u64,
    pub attacks: Vec<AttackSummary>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AttackSummary {
    pub id: String,
    pub attack_type: String,
    pub target: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub duration_seconds: i64,
    pub current_pps: u64,
    pub peak_pps: u64,
    pub status: String,
    pub effectiveness: f64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AttackReport {
    pub attack_id: String,
    pub attack_type: String,
    pub target: String,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    pub duration_seconds: Option<i64>,
    pub peak_pps: u64,
    pub peak_bps: u64,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub unique_sources: u64,
    pub top_sources: Vec<SourceEntry>,
    pub mitigation_timeline: Vec<MitigationEvent>,
    pub effectiveness: f64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SourceEntry {
    pub ip: String,
    pub pps: u64,
    pub percent: f64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MitigationEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub action: String,
    pub details: String,
}

impl Dashboard {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1000);
        Self {
            event_tx: tx,
            active_attacks: dashmap::DashMap::new(),
            stats: DashboardStats::default(),
        }
    }
    
    /// Subscribe to attack events
    pub fn subscribe(&self) -> broadcast::Receiver<AttackEvent> {
        self.event_tx.subscribe()
    }
    
    /// Record new attack detected
    pub fn attack_detected(&self, attack: Attack) {
        let tracking = AttackTracking {
            attack: attack.clone(),
            started_at: chrono::Utc::now(),
            peak_pps: AtomicU64::new(attack.metrics.total_pps),
            peak_bps: AtomicU64::new(attack.metrics.total_bps),
            total_packets: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            packets_passed: AtomicU64::new(0),
        };
        
        self.active_attacks.insert(attack.id.clone(), tracking);
        self.stats.attacks_detected.fetch_add(1, Ordering::Relaxed);
        
        let event = AttackEvent {
            event_type: AttackEventType::Detected,
            timestamp: chrono::Utc::now(),
            attack_id: attack.id,
            attack_type: format!("{:?}", attack.attack_type),
            target: attack.target.ip.to_string(),
            metrics: EventMetrics {
                current_pps: attack.metrics.total_pps,
                current_bps: attack.metrics.total_bps,
                peak_pps: attack.metrics.total_pps,
                peak_bps: attack.metrics.total_bps,
                unique_sources: attack.metrics.unique_sources,
                packets_dropped: 0,
                packets_passed: 0,
                mitigation_effectiveness: 0.0,
            },
            mitigation_status: "detecting".to_string(),
        };
        
        let _ = self.event_tx.send(event);
    }
    
    /// Update attack metrics
    pub fn attack_updated(&self, attack_id: &str, pps: u64, bps: u64, dropped: u64, passed: u64) {
        if let Some(tracking) = self.active_attacks.get(attack_id) {
            // Update peak
            tracking.peak_pps.fetch_max(pps, Ordering::Relaxed);
            tracking.peak_bps.fetch_max(bps, Ordering::Relaxed);
            tracking.packets_dropped.fetch_add(dropped, Ordering::Relaxed);
            tracking.packets_passed.fetch_add(passed, Ordering::Relaxed);
            
            let total_dropped = tracking.packets_dropped.load(Ordering::Relaxed);
            let total_passed = tracking.packets_passed.load(Ordering::Relaxed);
            let effectiveness = if total_dropped + total_passed > 0 {
                total_dropped as f64 / (total_dropped + total_passed) as f64
            } else {
                0.0
            };
            
            let event = AttackEvent {
                event_type: AttackEventType::Updated,
                timestamp: chrono::Utc::now(),
                attack_id: attack_id.to_string(),
                attack_type: format!("{:?}", tracking.attack.attack_type),
                target: tracking.attack.target.ip.to_string(),
                metrics: EventMetrics {
                    current_pps: pps,
                    current_bps: bps,
                    peak_pps: tracking.peak_pps.load(Ordering::Relaxed),
                    peak_bps: tracking.peak_bps.load(Ordering::Relaxed),
                    unique_sources: tracking.attack.metrics.unique_sources,
                    packets_dropped: total_dropped,
                    packets_passed: total_passed,
                    mitigation_effectiveness: effectiveness,
                },
                mitigation_status: "mitigating".to_string(),
            };
            
            let _ = self.event_tx.send(event);
        }
    }
    
    /// Record attack ended
    pub fn attack_ended(&self, attack_id: &str) {
        if let Some((_, tracking)) = self.active_attacks.remove(attack_id) {
            self.stats.attacks_mitigated.fetch_add(1, Ordering::Relaxed);
            
            let total_dropped = tracking.packets_dropped.load(Ordering::Relaxed);
            self.stats.total_packets_dropped.fetch_add(total_dropped, Ordering::Relaxed);
            
            let event = AttackEvent {
                event_type: AttackEventType::Ended,
                timestamp: chrono::Utc::now(),
                attack_id: attack_id.to_string(),
                attack_type: format!("{:?}", tracking.attack.attack_type),
                target: tracking.attack.target.ip.to_string(),
                metrics: EventMetrics {
                    current_pps: 0,
                    current_bps: 0,
                    peak_pps: tracking.peak_pps.load(Ordering::Relaxed),
                    peak_bps: tracking.peak_bps.load(Ordering::Relaxed),
                    unique_sources: tracking.attack.metrics.unique_sources,
                    packets_dropped: total_dropped,
                    packets_passed: tracking.packets_passed.load(Ordering::Relaxed),
                    mitigation_effectiveness: 1.0,
                },
                mitigation_status: "ended".to_string(),
            };
            
            let _ = self.event_tx.send(event);
        }
    }
    
    /// Get dashboard snapshot
    pub fn get_snapshot(&self) -> DashboardSnapshot {
        let attacks: Vec<AttackSummary> = self.active_attacks.iter()
            .map(|entry| {
                let tracking = entry.value();
                let now = chrono::Utc::now();
                let duration = (now - tracking.started_at).num_seconds();
                let dropped = tracking.packets_dropped.load(Ordering::Relaxed);
                let passed = tracking.packets_passed.load(Ordering::Relaxed);
                let effectiveness = if dropped + passed > 0 {
                    dropped as f64 / (dropped + passed) as f64
                } else {
                    0.0
                };
                
                AttackSummary {
                    id: tracking.attack.id.clone(),
                    attack_type: format!("{:?}", tracking.attack.attack_type),
                    target: tracking.attack.target.ip.to_string(),
                    started_at: tracking.started_at,
                    duration_seconds: duration,
                    current_pps: tracking.attack.metrics.total_pps,
                    peak_pps: tracking.peak_pps.load(Ordering::Relaxed),
                    status: "mitigating".to_string(),
                    effectiveness,
                }
            })
            .collect();
        
        DashboardSnapshot {
            timestamp: chrono::Utc::now(),
            active_attacks: self.active_attacks.len(),
            attacks_detected_total: self.stats.attacks_detected.load(Ordering::Relaxed),
            attacks_mitigated_total: self.stats.attacks_mitigated.load(Ordering::Relaxed),
            total_packets_dropped: self.stats.total_packets_dropped.load(Ordering::Relaxed),
            total_bytes_dropped: self.stats.total_bytes_dropped.load(Ordering::Relaxed),
            attacks,
        }
    }
    
    /// Generate attack report
    pub fn generate_report(&self, attack_id: &str) -> Option<AttackReport> {
        self.active_attacks.get(attack_id).map(|tracking| {
            let t = tracking.value();
            let dropped = t.packets_dropped.load(Ordering::Relaxed);
            let passed = t.packets_passed.load(Ordering::Relaxed);
            
            AttackReport {
                attack_id: attack_id.to_string(),
                attack_type: format!("{:?}", t.attack.attack_type),
                target: t.attack.target.ip.to_string(),
                start_time: t.started_at,
                end_time: None,
                duration_seconds: Some((chrono::Utc::now() - t.started_at).num_seconds()),
                peak_pps: t.peak_pps.load(Ordering::Relaxed),
                peak_bps: t.peak_bps.load(Ordering::Relaxed),
                total_packets: t.total_packets.load(Ordering::Relaxed),
                total_bytes: t.total_bytes.load(Ordering::Relaxed),
                unique_sources: t.attack.metrics.unique_sources,
                top_sources: t.attack.sources.iter()
                    .take(10)
                    .map(|s| SourceEntry {
                        ip: s.ip.to_string(),
                        pps: s.pps,
                        percent: s.pps as f64 / t.attack.metrics.total_pps.max(1) as f64 * 100.0,
                    })
                    .collect(),
                mitigation_timeline: vec![
                    MitigationEvent {
                        timestamp: t.started_at,
                        action: "detected".to_string(),
                        details: "Attack detected via anomaly detection".to_string(),
                    }
                ],
                effectiveness: if dropped + passed > 0 {
                    dropped as f64 / (dropped + passed) as f64
                } else {
                    0.0
                },
            }
        })
    }
}

impl Default for Dashboard {
    fn default() -> Self {
        Self::new()
    }
}
