//! Address Value Object
//!
//! Structured address with validation.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Address value object
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address {
    street1: String,
    street2: Option<String>,
    city: String,
    state: Option<String>,
    postal_code: String,
    country: CountryCode,
}

impl Address {
    /// Create a new address
    pub fn new(
        street1: impl Into<String>,
        street2: Option<String>,
        city: impl Into<String>,
        state: Option<String>,
        postal_code: impl Into<String>,
        country: CountryCode,
    ) -> Result<Self, AddressError> {
        let street1 = street1.into().trim().to_string();
        let city = city.into().trim().to_string();
        let postal_code = postal_code.into().trim().to_string();
        
        if street1.is_empty() {
            return Err(AddressError::MissingStreet);
        }
        
        if city.is_empty() {
            return Err(AddressError::MissingCity);
        }
        
        if postal_code.is_empty() {
            return Err(AddressError::MissingPostalCode);
        }
        
        Ok(Self {
            street1,
            street2: street2.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
            city,
            state: state.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
            postal_code,
            country,
        })
    }
    
    pub fn street1(&self) -> &str { &self.street1 }
    pub fn street2(&self) -> Option<&str> { self.street2.as_deref() }
    pub fn city(&self) -> &str { &self.city }
    pub fn state(&self) -> Option<&str> { self.state.as_deref() }
    pub fn postal_code(&self) -> &str { &self.postal_code }
    pub fn country(&self) -> &CountryCode { &self.country }
    
    /// Get full street address
    pub fn full_street(&self) -> String {
        match &self.street2 {
            Some(s2) => format!("{}\n{}", self.street1, s2),
            None => self.street1.clone(),
        }
    }
    
    /// Format as single line
    pub fn single_line(&self) -> String {
        let mut parts = vec![self.street1.clone()];
        if let Some(s2) = &self.street2 {
            parts.push(s2.clone());
        }
        parts.push(self.city.clone());
        if let Some(state) = &self.state {
            parts.push(state.clone());
        }
        parts.push(self.postal_code.clone());
        parts.push(self.country.name().to_string());
        parts.join(", ")
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.street1)?;
        if let Some(s2) = &self.street2 {
            writeln!(f, "{}", s2)?;
        }
        if let Some(state) = &self.state {
            writeln!(f, "{}, {} {}", self.city, state, self.postal_code)?;
        } else {
            writeln!(f, "{} {}", self.city, self.postal_code)?;
        }
        write!(f, "{}", self.country.name())
    }
}

/// ISO 3166-1 alpha-2 country codes
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CountryCode {
    US, GB, CA, AU, DE, FR, NG, IN, JP, CN, BR,
    Other(String),
}

impl CountryCode {
    pub fn code(&self) -> &str {
        match self {
            Self::US => "US", Self::GB => "GB", Self::CA => "CA",
            Self::AU => "AU", Self::DE => "DE", Self::FR => "FR",
            Self::NG => "NG", Self::IN => "IN", Self::JP => "JP",
            Self::CN => "CN", Self::BR => "BR",
            Self::Other(c) => c,
        }
    }
    
    pub fn name(&self) -> &str {
        match self {
            Self::US => "United States",
            Self::GB => "United Kingdom",
            Self::CA => "Canada",
            Self::AU => "Australia",
            Self::DE => "Germany",
            Self::FR => "France",
            Self::NG => "Nigeria",
            Self::IN => "India",
            Self::JP => "Japan",
            Self::CN => "China",
            Self::BR => "Brazil",
            Self::Other(c) => c,
        }
    }
    
    pub fn from_code(code: &str) -> Self {
        match code.to_uppercase().as_str() {
            "US" => Self::US, "GB" => Self::GB, "CA" => Self::CA,
            "AU" => Self::AU, "DE" => Self::DE, "FR" => Self::FR,
            "NG" => Self::NG, "IN" => Self::IN, "JP" => Self::JP,
            "CN" => Self::CN, "BR" => Self::BR,
            other => Self::Other(other.to_string()),
        }
    }
}

impl Default for CountryCode {
    fn default() -> Self { Self::US }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    MissingStreet,
    MissingCity,
    MissingPostalCode,
}

impl std::error::Error for AddressError {}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingStreet => write!(f, "Street address is required"),
            Self::MissingCity => write!(f, "City is required"),
            Self::MissingPostalCode => write!(f, "Postal code is required"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_address_creation() {
        let addr = Address::new(
            "123 Main St",
            Some("Suite 100".to_string()),
            "San Francisco",
            Some("CA".to_string()),
            "94102",
            CountryCode::US,
        ).unwrap();
        
        assert_eq!(addr.street1(), "123 Main St");
        assert_eq!(addr.city(), "San Francisco");
    }
    
    #[test]
    fn test_address_single_line() {
        let addr = Address::new(
            "123 Main St",
            None,
            "NYC",
            Some("NY".to_string()),
            "10001",
            CountryCode::US,
        ).unwrap();
        
        assert!(addr.single_line().contains("NYC"));
        assert!(addr.single_line().contains("NY"));
    }
}
