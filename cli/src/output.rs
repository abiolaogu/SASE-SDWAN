//! Output formatting

use serde::Serialize;
use clap::ValueEnum;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Table,
    Json,
    Yaml,
}

impl OutputFormat {
    pub fn print<T: Serialize>(&self, data: &T) {
        match self {
            OutputFormat::Json => {
                println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
            }
            OutputFormat::Yaml => {
                println!("{}", serde_yaml::to_string(data).unwrap_or_default());
            }
            OutputFormat::Table => {
                // For table, just print JSON nicely for now
                println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
            }
        }
    }
}
