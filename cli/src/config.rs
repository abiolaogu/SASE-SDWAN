//! CLI Configuration

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    pub api_url: Option<String>,
    pub api_key: Option<String>,
    pub tenant_id: Option<String>,
    pub default_format: Option<String>,
}

impl Config {
    pub fn load(profile: Option<&str>) -> Result<Self, String> {
        let path = Self::config_path(profile)?;
        if path.exists() {
            let content = fs::read_to_string(&path).map_err(|e| e.to_string())?;
            toml::from_str(&content).map_err(|e| e.to_string())
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = Self::config_path(None)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let content = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(&path, content).map_err(|e| e.to_string())
    }

    fn config_path(profile: Option<&str>) -> Result<PathBuf, String> {
        let home = dirs::home_dir().ok_or("Cannot find home directory")?;
        let filename = match profile {
            Some(p) => format!("config.{}.toml", p),
            None => "config.toml".to_string(),
        };
        Ok(home.join(".opensase").join(filename))
    }
}
