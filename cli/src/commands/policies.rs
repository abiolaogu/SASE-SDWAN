//! Policies commands

use crate::{PolicyCommands, output::OutputFormat};
use super::ApiClient;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub priority: u32,
}

#[derive(Debug, Deserialize)]
pub struct PaginatedPolicies {
    pub items: Vec<Policy>,
}

pub async fn handle(action: PolicyCommands, client: &ApiClient, format: OutputFormat) -> Result<(), String> {
    match action {
        PolicyCommands::List => {
            let policies: PaginatedPolicies = client.get("/policies").await?;
            format.print(&policies.items);
        }
        PolicyCommands::Get { id } => {
            let policy: Policy = client.get(&format!("/policies/{}", id)).await?;
            format.print(&policy);
        }
        PolicyCommands::Apply { file } => {
            let content = fs::read_to_string(&file).map_err(|e| e.to_string())?;
            let body: serde_json::Value = if file.ends_with(".yaml") || file.ends_with(".yml") {
                serde_yaml::from_str(&content).map_err(|e| e.to_string())?
            } else {
                serde_json::from_str(&content).map_err(|e| e.to_string())?
            };
            let policy: Policy = client.post("/policies", &body).await?;
            println!("Applied policy: {}", policy.id);
        }
    }
    Ok(())
}
