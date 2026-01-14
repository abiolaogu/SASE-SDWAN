//! xDS Server
//!
//! Main server that hosts all xDS services.

use crate::discovery::{LdsService, CdsService, RdsService};
use crate::resources::ResourceStore;
use std::sync::Arc;
use tokio::net::TcpListener;
use tonic::transport::Server;
use tracing::{info, error};

/// xDS Control Plane Server
pub struct XdsServer {
    /// Resource store
    store: Arc<ResourceStore>,
    
    /// Server address
    addr: String,
}

impl XdsServer {
    /// Create new xDS server
    pub fn new() -> Self {
        Self {
            store: Arc::new(ResourceStore::new()),
            addr: "[::]:18000".to_string(),
        }
    }
    
    /// Set server address
    pub fn with_addr(mut self, addr: &str) -> Self {
        self.addr = addr.to_string();
        self
    }
    
    /// Get resource store
    pub fn store(&self) -> Arc<ResourceStore> {
        self.store.clone()
    }
    
    /// Start serving
    pub async fn serve(&self) -> crate::Result<()> {
        let addr = self.addr.parse()
            .map_err(|e| crate::XdsError::IoError(
                std::io::Error::new(std::io::ErrorKind::InvalidInput, e)
            ))?;
        
        let lds = LdsService::new(self.store.clone());
        let cds = CdsService::new(self.store.clone());
        let rds = RdsService::new(self.store.clone());
        
        info!("xDS server listening on {}", addr);
        
        Server::builder()
            .add_service(lds.into_server())
            .add_service(cds.into_server())
            .add_service(rds.into_server())
            .serve(addr)
            .await
            .map_err(|e| crate::XdsError::IoError(
                std::io::Error::new(std::io::ErrorKind::Other, e)
            ))?;
        
        Ok(())
    }
}

impl Default for XdsServer {
    fn default() -> Self {
        Self::new()
    }
}
