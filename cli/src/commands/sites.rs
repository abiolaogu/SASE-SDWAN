//! Sites commands

use crate::{SiteCommands, output::OutputFormat};
use super::ApiClient;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Site {
    pub id: String,
    pub name: String,
    pub location: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct PaginatedSites {
    pub items: Vec<Site>,
    pub total: u64,
}

pub async fn handle(action: SiteCommands, client: &ApiClient, format: OutputFormat) -> Result<(), String> {
    match action {
        SiteCommands::List => {
            let sites: PaginatedSites = client.get("/sites").await?;
            format.print(&sites.items);
        }
        SiteCommands::Get { id } => {
            let site: Site = client.get(&format!("/sites/{}", id)).await?;
            format.print(&site);
        }
        SiteCommands::Create { name, location } => {
            let body = serde_json::json!({ "name": name, "location": location });
            let site: Site = client.post("/sites", &body).await?;
            println!("Created site: {}", site.id);
        }
    }
    Ok(())
}
