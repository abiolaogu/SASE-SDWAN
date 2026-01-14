//! Alerts commands

use crate::{AlertCommands, output::OutputFormat};
use super::ApiClient;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct PaginatedAlerts {
    pub items: Vec<Alert>,
}

pub async fn handle(action: AlertCommands, client: &ApiClient, format: OutputFormat) -> Result<(), String> {
    match action {
        AlertCommands::List { severity, status } => {
            let mut params = Vec::new();
            if let Some(s) = severity { params.push(format!("severity={}", s)); }
            if let Some(s) = status { params.push(format!("status={}", s)); }
            let query = if params.is_empty() { String::new() } else { format!("?{}", params.join("&")) };
            let alerts: PaginatedAlerts = client.get(&format!("/alerts{}", query)).await?;
            format.print(&alerts.items);
        }
        AlertCommands::Get { id } => {
            let alert: Alert = client.get(&format!("/alerts/{}", id)).await?;
            format.print(&alert);
        }
        AlertCommands::Ack { id } => {
            let _: Alert = client.post(&format!("/alerts/{}/acknowledge", id), &()).await?;
            println!("Alert {} acknowledged", id);
        }
        AlertCommands::Resolve { id } => {
            let _: Alert = client.post(&format!("/alerts/{}/resolve", id), &()).await?;
            println!("Alert {} resolved", id);
        }
    }
    Ok(())
}
