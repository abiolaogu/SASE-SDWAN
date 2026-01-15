//! Value Objects module
//!
//! Immutable, validated domain primitives.

pub mod email;
pub mod money;
pub mod phone;
pub mod address;

pub use email::{Email, EmailError};
pub use money::{Money, Currency, MoneyError};
pub use phone::{Phone, PhoneError};
pub use address::{Address, CountryCode, AddressError};

/// Identifier value object for entities
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct EntityId(String);

impl EntityId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
    
    pub fn from_string(id: impl Into<String>) -> Self {
        Self(id.into())
    }
    
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for EntityId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for EntityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for EntityId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
