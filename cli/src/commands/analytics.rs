//! Analytics commands

use crate::{AnalyticsCommands, output::OutputFormat};
use super::ApiClient;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct TrafficStats {
    pub period: String,
    pub total_bytes: u64,
    pub total_requests: u64,
    pub blocked_requests: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThreatStats {
    pub period: String,
    pub total_threats: u64,
}

pub async fn handle(action: AnalyticsCommands, client: &ApiClient, format: OutputFormat) -> Result<(), String> {
    match action {
        AnalyticsCommands::Traffic { period } => {
            let stats: TrafficStats = client.get(&format!("/analytics/traffic?period={}", period)).await?;
            format.print(&stats);
        }
        AnalyticsCommands::Threats { period } => {
            let stats: ThreatStats = client.get(&format!("/analytics/threats?period={}", period)).await?;
            format.print(&stats);
        }
    }
    Ok(())
}
