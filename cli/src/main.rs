//! OpenSASE CLI
//!
//! Command-line interface for the OpenSASE platform.
//!
//! # Usage
//!
//! ```bash
//! opensase sites list
//! opensase sites create --name "NYC Office" --location "New York"
//! opensase policies apply -f policy.yaml
//! opensase alerts list --severity critical
//! opensase users list --format json
//! ```

use clap::{Parser, Subcommand};

mod commands;
mod config;
mod output;

#[derive(Parser)]
#[command(name = "opensase")]
#[command(author = "OpenSASE")]
#[command(version = "0.1.0")]
#[command(about = "OpenSASE Command Line Interface", long_about = None)]
struct Cli {
    /// API endpoint URL
    #[arg(long, env = "OPENSASE_API_URL", default_value = "https://api.opensase.io/v1")]
    api_url: String,

    /// API key for authentication
    #[arg(long, env = "OPENSASE_API_KEY")]
    api_key: Option<String>,

    /// Tenant ID
    #[arg(long, env = "OPENSASE_TENANT_ID")]
    tenant_id: Option<String>,

    /// Output format
    #[arg(long, short, default_value = "table")]
    format: output::OutputFormat,

    /// Profile name from config file
    #[arg(long, short)]
    profile: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage sites
    Sites {
        #[command(subcommand)]
        action: SiteCommands,
    },
    /// Manage users
    Users {
        #[command(subcommand)]
        action: UserCommands,
    },
    /// Manage policies
    Policies {
        #[command(subcommand)]
        action: PolicyCommands,
    },
    /// Manage alerts
    Alerts {
        #[command(subcommand)]
        action: AlertCommands,
    },
    /// View analytics
    Analytics {
        #[command(subcommand)]
        action: AnalyticsCommands,
    },
    /// Configure CLI
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
    },
}

#[derive(Subcommand)]
enum SiteCommands {
    /// List all sites
    List,
    /// Get site details
    Get { id: String },
    /// Create a new site
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        location: String,
    },
}

#[derive(Subcommand)]
enum UserCommands {
    /// List all users
    List {
        #[arg(long)]
        role: Option<String>,
    },
    /// Get user details
    Get { id: String },
    /// Create a new user
    Create {
        #[arg(long)]
        email: String,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "viewer")]
        role: String,
    },
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// List all policies
    List,
    /// Get policy details
    Get { id: String },
    /// Apply policy from file
    Apply {
        #[arg(short, long)]
        file: String,
    },
}

#[derive(Subcommand)]
enum AlertCommands {
    /// List alerts
    List {
        #[arg(long)]
        severity: Option<String>,
        #[arg(long)]
        status: Option<String>,
    },
    /// Get alert details
    Get { id: String },
    /// Acknowledge an alert
    Ack { id: String },
    /// Resolve an alert
    Resolve { id: String },
}

#[derive(Subcommand)]
enum AnalyticsCommands {
    /// View traffic statistics
    Traffic {
        #[arg(long, default_value = "24h")]
        period: String,
    },
    /// View threat statistics
    Threats {
        #[arg(long, default_value = "24h")]
        period: String,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Set configuration value
    Set { key: String, value: String },
    /// Get configuration value
    Get { key: String },
    /// List all configuration
    List,
    /// Initialize configuration
    Init,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    
    let config = config::Config::load(cli.profile.as_deref()).unwrap_or_default();
    let api_key = cli.api_key.or(config.api_key);
    let tenant_id = cli.tenant_id.or(config.tenant_id);
    
    let client = commands::ApiClient::new(&cli.api_url, api_key.as_deref(), tenant_id.as_deref());
    
    let result = match cli.command {
        Commands::Sites { action } => commands::sites::handle(action, &client, cli.format).await,
        Commands::Users { action } => commands::users::handle(action, &client, cli.format).await,
        Commands::Policies { action } => commands::policies::handle(action, &client, cli.format).await,
        Commands::Alerts { action } => commands::alerts::handle(action, &client, cli.format).await,
        Commands::Analytics { action } => commands::analytics::handle(action, &client, cli.format).await,
        Commands::Config { action } => commands::config::handle(action).await,
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
