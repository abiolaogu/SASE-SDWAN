//! Domain module - API entity types following DDD patterns

pub mod identity;
pub mod crm;
pub mod payments;
pub mod commerce;
pub mod common;

pub use identity::*;
pub use crm::*;
pub use payments::*;
pub use commerce::*;
pub use common::*;
