//! Config commands

use crate::ConfigCommands;
use crate::config::Config;

pub async fn handle(action: ConfigCommands) -> Result<(), String> {
    match action {
        ConfigCommands::Init => {
            let config = Config::default();
            config.save()?;
            println!("Configuration initialized at ~/.opensase/config.toml");
        }
        ConfigCommands::Set { key, value } => {
            let mut config = Config::load(None).unwrap_or_default();
            match key.as_str() {
                "api_key" => config.api_key = Some(value),
                "tenant_id" => config.tenant_id = Some(value),
                "api_url" => config.api_url = Some(value),
                _ => return Err(format!("Unknown config key: {}", key)),
            }
            config.save()?;
            println!("Set {} successfully", key);
        }
        ConfigCommands::Get { key } => {
            let config = Config::load(None).unwrap_or_default();
            let value = match key.as_str() {
                "api_key" => config.api_key.map(|k| format!("{}****", &k[..8.min(k.len())])),
                "tenant_id" => config.tenant_id,
                "api_url" => config.api_url,
                _ => return Err(format!("Unknown config key: {}", key)),
            };
            println!("{}: {}", key, value.unwrap_or_else(|| "(not set)".into()));
        }
        ConfigCommands::List => {
            let config = Config::load(None).unwrap_or_default();
            println!("api_url: {}", config.api_url.unwrap_or_else(|| "(not set)".into()));
            println!("tenant_id: {}", config.tenant_id.unwrap_or_else(|| "(not set)".into()));
            println!("api_key: {}", config.api_key.map(|k| format!("{}****", &k[..8.min(k.len())])).unwrap_or_else(|| "(not set)".into()));
        }
    }
    Ok(())
}
