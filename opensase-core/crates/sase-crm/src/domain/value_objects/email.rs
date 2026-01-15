//! Email Value Object
//!
//! Immutable, validated email address following DDD principles.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Email value object with validation
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Email(String);

impl Email {
    /// Create a new validated email
    pub fn new(value: impl Into<String>) -> Result<Self, EmailError> {
        let value = value.into().trim().to_lowercase();
        
        if value.is_empty() {
            return Err(EmailError::Empty);
        }
        
        if !Self::is_valid_format(&value) {
            return Err(EmailError::InvalidFormat);
        }
        
        Ok(Self(value))
    }
    
    /// Create email without validation (for deserialization)
    pub fn new_unchecked(value: impl Into<String>) -> Self {
        Self(value.into().trim().to_lowercase())
    }
    
    /// Get the email as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }
    
    /// Get the domain part of the email
    pub fn domain(&self) -> Option<&str> {
        self.0.split('@').nth(1)
    }
    
    /// Get the local part (before @)
    pub fn local_part(&self) -> Option<&str> {
        self.0.split('@').next()
    }
    
    fn is_valid_format(email: &str) -> bool {
        // Basic validation: contains @ and has content on both sides
        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() != 2 {
            return false;
        }
        
        let local = parts[0];
        let domain = parts[1];
        
        !local.is_empty() 
            && !domain.is_empty() 
            && domain.contains('.')
            && !domain.starts_with('.')
            && !domain.ends_with('.')
    }
}

impl fmt::Display for Email {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmailError {
    Empty,
    InvalidFormat,
}

impl std::error::Error for EmailError {}

impl fmt::Display for EmailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "Email cannot be empty"),
            Self::InvalidFormat => write!(f, "Invalid email format"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_valid_email() {
        let email = Email::new("test@example.com").unwrap();
        assert_eq!(email.as_str(), "test@example.com");
        assert_eq!(email.domain(), Some("example.com"));
        assert_eq!(email.local_part(), Some("test"));
    }
    
    #[test]
    fn test_email_lowercase() {
        let email = Email::new("Test@EXAMPLE.com").unwrap();
        assert_eq!(email.as_str(), "test@example.com");
    }
    
    #[test]
    fn test_email_trim() {
        let email = Email::new("  test@example.com  ").unwrap();
        assert_eq!(email.as_str(), "test@example.com");
    }
    
    #[test]
    fn test_empty_email() {
        assert!(matches!(Email::new(""), Err(EmailError::Empty)));
    }
    
    #[test]
    fn test_invalid_email_no_at() {
        assert!(matches!(Email::new("invalid"), Err(EmailError::InvalidFormat)));
    }
    
    #[test]
    fn test_invalid_email_no_domain() {
        assert!(matches!(Email::new("test@"), Err(EmailError::InvalidFormat)));
    }
}
