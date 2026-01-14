//! Users commands

use crate::{UserCommands, output::OutputFormat};
use super::ApiClient;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: String,
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct PaginatedUsers {
    pub items: Vec<User>,
}

pub async fn handle(action: UserCommands, client: &ApiClient, format: OutputFormat) -> Result<(), String> {
    match action {
        UserCommands::List { role } => {
            let path = match role {
                Some(r) => format!("/users?role={}", r),
                None => "/users".to_string(),
            };
            let users: PaginatedUsers = client.get(&path).await?;
            format.print(&users.items);
        }
        UserCommands::Get { id } => {
            let user: User = client.get(&format!("/users/{}", id)).await?;
            format.print(&user);
        }
        UserCommands::Create { email, name, role } => {
            let body = serde_json::json!({ "email": email, "name": name, "role": role });
            let user: User = client.post("/users", &body).await?;
            println!("Created user: {}", user.id);
        }
    }
    Ok(())
}
