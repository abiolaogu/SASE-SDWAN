//! BGP Monitoring and Metrics
//!
//! Prometheus metrics for BGP session monitoring and alerting.

use crate::{PeeringSession, BgpSessionState, IxpPort};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// BGP session metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMetrics {
    pub session_id: String,
    pub peer_asn: u32,
    pub peer_name: String,
    pub state: BgpSessionState,
    pub prefixes_received: u32,
    pub prefixes_sent: u32,
    pub uptime_seconds: u64,
    pub messages_received: u64,
    pub messages_sent: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub last_update: i64,
}

/// IXP port metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMetrics {
    pub port_id: String,
    pub ixp_name: String,
    pub speed_mbps: u32,
    pub utilization_in_percent: f32,
    pub utilization_out_percent: f32,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub errors_in: u64,
    pub errors_out: u64,
}

/// Prometheus metrics exporter
pub struct MetricsExporter {
    sessions: HashMap<String, SessionMetrics>,
    ports: HashMap<String, PortMetrics>,
}

impl MetricsExporter {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            ports: HashMap::new(),
        }
    }

    /// Update session metrics
    pub fn update_session(&mut self, metrics: SessionMetrics) {
        self.sessions.insert(metrics.session_id.clone(), metrics);
    }

    /// Update port metrics
    pub fn update_port(&mut self, metrics: PortMetrics) {
        self.ports.insert(metrics.port_id.clone(), metrics);
    }

    /// Generate Prometheus metrics output
    pub fn export_prometheus(&self) -> String {
        let mut output = String::new();

        // Session metrics
        output.push_str("# HELP ospe_bgp_session_state BGP session state (1=established)\n");
        output.push_str("# TYPE ospe_bgp_session_state gauge\n");
        for (id, m) in &self.sessions {
            let state_value = if m.state == BgpSessionState::Established { 1 } else { 0 };
            output.push_str(&format!(
                "ospe_bgp_session_state{{session=\"{}\",peer_asn=\"{}\",peer_name=\"{}\"}} {}\n",
                id, m.peer_asn, m.peer_name, state_value
            ));
        }

        output.push_str("\n# HELP ospe_bgp_prefixes_received Number of prefixes received\n");
        output.push_str("# TYPE ospe_bgp_prefixes_received gauge\n");
        for (id, m) in &self.sessions {
            output.push_str(&format!(
                "ospe_bgp_prefixes_received{{session=\"{}\",peer_asn=\"{}\"}} {}\n",
                id, m.peer_asn, m.prefixes_received
            ));
        }

        output.push_str("\n# HELP ospe_bgp_prefixes_sent Number of prefixes sent\n");
        output.push_str("# TYPE ospe_bgp_prefixes_sent gauge\n");
        for (id, m) in &self.sessions {
            output.push_str(&format!(
                "ospe_bgp_prefixes_sent{{session=\"{}\",peer_asn=\"{}\"}} {}\n",
                id, m.peer_asn, m.prefixes_sent
            ));
        }

        output.push_str("\n# HELP ospe_bgp_uptime_seconds Session uptime in seconds\n");
        output.push_str("# TYPE ospe_bgp_uptime_seconds gauge\n");
        for (id, m) in &self.sessions {
            output.push_str(&format!(
                "ospe_bgp_uptime_seconds{{session=\"{}\",peer_asn=\"{}\"}} {}\n",
                id, m.peer_asn, m.uptime_seconds
            ));
        }

        // Port metrics
        output.push_str("\n# HELP ospe_ixp_port_bytes_in Bytes received on IXP port\n");
        output.push_str("# TYPE ospe_ixp_port_bytes_in counter\n");
        for (id, m) in &self.ports {
            output.push_str(&format!(
                "ospe_ixp_port_bytes_in{{port=\"{}\",ixp=\"{}\"}} {}\n",
                id, m.ixp_name, m.bytes_in
            ));
        }

        output.push_str("\n# HELP ospe_ixp_port_bytes_out Bytes sent on IXP port\n");
        output.push_str("# TYPE ospe_ixp_port_bytes_out counter\n");
        for (id, m) in &self.ports {
            output.push_str(&format!(
                "ospe_ixp_port_bytes_out{{port=\"{}\",ixp=\"{}\"}} {}\n",
                id, m.ixp_name, m.bytes_out
            ));
        }

        output.push_str("\n# HELP ospe_ixp_port_utilization_percent Port utilization percentage\n");
        output.push_str("# TYPE ospe_ixp_port_utilization_percent gauge\n");
        for (id, m) in &self.ports {
            output.push_str(&format!(
                "ospe_ixp_port_utilization_percent{{port=\"{}\",ixp=\"{}\",direction=\"in\"}} {:.2}\n",
                id, m.ixp_name, m.utilization_in_percent
            ));
            output.push_str(&format!(
                "ospe_ixp_port_utilization_percent{{port=\"{}\",ixp=\"{}\",direction=\"out\"}} {:.2}\n",
                id, m.ixp_name, m.utilization_out_percent
            ));
        }

        // Summary metrics
        let total_sessions = self.sessions.len();
        let established = self.sessions.values()
            .filter(|s| s.state == BgpSessionState::Established)
            .count();
        let total_prefixes: u32 = self.sessions.values()
            .map(|s| s.prefixes_received)
            .sum();

        output.push_str("\n# HELP ospe_total_sessions Total BGP sessions\n");
        output.push_str("# TYPE ospe_total_sessions gauge\n");
        output.push_str(&format!("ospe_total_sessions {}\n", total_sessions));

        output.push_str("\n# HELP ospe_established_sessions Established BGP sessions\n");
        output.push_str("# TYPE ospe_established_sessions gauge\n");
        output.push_str(&format!("ospe_established_sessions {}\n", established));

        output.push_str("\n# HELP ospe_total_prefixes_received Total prefixes received\n");
        output.push_str("# TYPE ospe_total_prefixes_received gauge\n");
        output.push_str(&format!("ospe_total_prefixes_received {}\n", total_prefixes));

        output
    }

    /// Get summary stats
    pub fn get_summary(&self) -> MetricsSummary {
        let established = self.sessions.values()
            .filter(|s| s.state == BgpSessionState::Established)
            .count();
        let total_prefixes: u32 = self.sessions.values()
            .map(|s| s.prefixes_received)
            .sum();
        let total_bytes_in: u64 = self.ports.values()
            .map(|p| p.bytes_in)
            .sum();
        let total_bytes_out: u64 = self.ports.values()
            .map(|p| p.bytes_out)
            .sum();

        MetricsSummary {
            total_sessions: self.sessions.len(),
            established_sessions: established,
            total_prefixes_received: total_prefixes,
            total_ixp_ports: self.ports.len(),
            total_traffic_in_gbps: (total_bytes_in as f64 * 8.0) / 1_000_000_000.0,
            total_traffic_out_gbps: (total_bytes_out as f64 * 8.0) / 1_000_000_000.0,
        }
    }
}

impl Default for MetricsExporter {
    fn default() -> Self {
        Self::new()
    }
}

/// Metrics summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSummary {
    pub total_sessions: usize,
    pub established_sessions: usize,
    pub total_prefixes_received: u32,
    pub total_ixp_ports: usize,
    pub total_traffic_in_gbps: f64,
    pub total_traffic_out_gbps: f64,
}

/// Alert definitions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub name: String,
    pub condition: AlertCondition,
    pub severity: AlertSeverity,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertCondition {
    SessionDown { peer_asn: u32 },
    SessionDownAny,
    PrefixCountDrop { threshold_percent: f32 },
    PortUtilizationHigh { threshold_percent: f32 },
    NoEstablishedSessions,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

/// Standard alert rules for peering
pub fn default_alert_rules() -> Vec<AlertRule> {
    vec![
        AlertRule {
            name: "no_established_sessions".to_string(),
            condition: AlertCondition::NoEstablishedSessions,
            severity: AlertSeverity::Critical,
            message: "No BGP sessions are established".to_string(),
        },
        AlertRule {
            name: "cloudflare_down".to_string(),
            condition: AlertCondition::SessionDown { peer_asn: 13335 },
            severity: AlertSeverity::Warning,
            message: "Cloudflare BGP session is down".to_string(),
        },
        AlertRule {
            name: "google_down".to_string(),
            condition: AlertCondition::SessionDown { peer_asn: 15169 },
            severity: AlertSeverity::Warning,
            message: "Google BGP session is down".to_string(),
        },
        AlertRule {
            name: "prefix_drop".to_string(),
            condition: AlertCondition::PrefixCountDrop { threshold_percent: 50.0 },
            severity: AlertSeverity::Critical,
            message: "Prefix count dropped by more than 50%".to_string(),
        },
        AlertRule {
            name: "port_saturation".to_string(),
            condition: AlertCondition::PortUtilizationHigh { threshold_percent: 80.0 },
            severity: AlertSeverity::Warning,
            message: "IXP port utilization above 80%".to_string(),
        },
    ]
}

/// Generate Prometheus alerting rules
pub fn generate_prometheus_rules() -> String {
    r#"groups:
  - name: ospe_bgp_alerts
    rules:
      - alert: OspeBgpSessionDown
        expr: ospe_bgp_session_state == 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "BGP session down"
          description: "BGP session {{ $labels.session }} to AS{{ $labels.peer_asn }} is down"

      - alert: OspeNoEstablishedSessions
        expr: ospe_established_sessions == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "No BGP sessions established"
          description: "All BGP peering sessions are down"

      - alert: OspePrefixCountLow
        expr: ospe_bgp_prefixes_received < 1000
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Low prefix count from peer"
          description: "Prefix count from AS{{ $labels.peer_asn }} is unusually low"

      - alert: OspePortHighUtilization
        expr: ospe_ixp_port_utilization_percent > 80
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "IXP port high utilization"
          description: "Port {{ $labels.port }} at {{ $labels.ixp }} is above 80% utilization"

      - alert: OspePortSaturation
        expr: ospe_ixp_port_utilization_percent > 95
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "IXP port saturated"
          description: "Port {{ $labels.port }} at {{ $labels.ixp }} is saturated (>95%)"
"#.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prometheus_export() {
        let mut exporter = MetricsExporter::new();
        
        exporter.update_session(SessionMetrics {
            session_id: "cf-decix".to_string(),
            peer_asn: 13335,
            peer_name: "Cloudflare".to_string(),
            state: BgpSessionState::Established,
            prefixes_received: 5000,
            prefixes_sent: 50,
            uptime_seconds: 86400,
            messages_received: 10000,
            messages_sent: 5000,
            bytes_received: 1_000_000,
            bytes_sent: 500_000,
            last_update: 0,
        });
        
        let output = exporter.export_prometheus();
        assert!(output.contains("ospe_bgp_session_state"));
        assert!(output.contains("13335"));
    }
}
