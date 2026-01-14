//! OpenSASE Edge - Main Entry Point

use opensase_edge::{OpenSASEEdge, EdgeConfig};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("OpenSASE Edge v{}", env!("CARGO_PKG_VERSION"));

    // Load config
    let config_path = std::env::var("CONFIG_PATH")
        .unwrap_or_else(|_| "/etc/opensase/edge.json".into());
    
    let config = EdgeConfig::load(&config_path)
        .unwrap_or_else(|_| {
            tracing::warn!("Config not found, using defaults");
            EdgeConfig::default()
        });

    // Create and initialize edge
    let edge = OpenSASEEdge::new(config);
    edge.init().await?;
    
    // Run
    edge.run().await?;

    Ok(())
}
