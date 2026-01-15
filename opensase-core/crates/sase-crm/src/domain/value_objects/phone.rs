//! Phone Value Object
//!
//! Validated phone number with country code.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Phone number value object
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Phone {
    country_code: String,
    number: String,
    extension: Option<String>,
}

impl Phone {
    /// Create a new phone number
    pub fn new(
        country_code: impl Into<String>,
        number: impl Into<String>,
        extension: Option<String>,
    ) -> Result<Self, PhoneError> {
        let country_code = Self::normalize_country_code(country_code.into());
        let number = Self::normalize_number(number.into());
        
        if number.is_empty() {
            return Err(PhoneError::Empty);
        }
        
        if number.len() < 7 || number.len() > 15 {
            return Err(PhoneError::InvalidLength);
        }
        
        if !number.chars().all(|c| c.is_ascii_digit()) {
            return Err(PhoneError::InvalidCharacters);
        }
        
        Ok(Self {
            country_code,
            number,
            extension,
        })
    }
    
    /// Parse from E.164 format (+1234567890)
    pub fn from_e164(value: &str) -> Result<Self, PhoneError> {
        let value = value.trim();
        
        if !value.starts_with('+') {
            return Err(PhoneError::InvalidFormat);
        }
        
        let digits: String = value[1..].chars().filter(|c| c.is_ascii_digit()).collect();
        
        if digits.len() < 10 {
            return Err(PhoneError::InvalidLength);
        }
        
        // Assume first 1-3 digits are country code
        let (country_code, number) = if digits.starts_with('1') {
            ("+1".to_string(), digits[1..].to_string())
        } else {
            (format!("+{}", &digits[..2]), digits[2..].to_string())
        };
        
        Ok(Self {
            country_code,
            number,
            extension: None,
        })
    }
    
    /// Get country code
    pub fn country_code(&self) -> &str {
        &self.country_code
    }
    
    /// Get number without country code
    pub fn number(&self) -> &str {
        &self.number
    }
    
    /// Get extension
    pub fn extension(&self) -> Option<&str> {
        self.extension.as_deref()
    }
    
    /// Format as E.164
    pub fn to_e164(&self) -> String {
        format!("{}{}", self.country_code, self.number)
    }
    
    /// Format for display
    pub fn format_display(&self) -> String {
        let formatted = if self.number.len() == 10 {
            format!(
                "({}) {}-{}",
                &self.number[..3],
                &self.number[3..6],
                &self.number[6..]
            )
        } else {
            self.number.clone()
        };
        
        match &self.extension {
            Some(ext) => format!("{} {} ext. {}", self.country_code, formatted, ext),
            None => format!("{} {}", self.country_code, formatted),
        }
    }
    
    fn normalize_country_code(code: String) -> String {
        let code = code.trim();
        if code.starts_with('+') {
            code.to_string()
        } else {
            format!("+{}", code)
        }
    }
    
    fn normalize_number(number: String) -> String {
        number.chars().filter(|c| c.is_ascii_digit()).collect()
    }
}

impl fmt::Display for Phone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format_display())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhoneError {
    Empty,
    InvalidLength,
    InvalidCharacters,
    InvalidFormat,
}

impl std::error::Error for PhoneError {}

impl fmt::Display for PhoneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "Phone number cannot be empty"),
            Self::InvalidLength => write!(f, "Invalid phone number length"),
            Self::InvalidCharacters => write!(f, "Phone number contains invalid characters"),
            Self::InvalidFormat => write!(f, "Invalid phone number format"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_phone_creation() {
        let phone = Phone::new("+1", "5551234567", None).unwrap();
        assert_eq!(phone.country_code(), "+1");
        assert_eq!(phone.number(), "5551234567");
    }
    
    #[test]
    fn test_phone_e164() {
        let phone = Phone::from_e164("+15551234567").unwrap();
        assert_eq!(phone.to_e164(), "+15551234567");
    }
    
    #[test]
    fn test_phone_display() {
        let phone = Phone::new("+1", "5551234567", None).unwrap();
        assert_eq!(phone.format_display(), "+1 (555) 123-4567");
    }
    
    #[test]
    fn test_phone_with_extension() {
        let phone = Phone::new("+1", "5551234567", Some("123".to_string())).unwrap();
        assert!(phone.format_display().contains("ext. 123"));
    }
    
    #[test]
    fn test_empty_phone() {
        assert!(matches!(Phone::new("+1", "", None), Err(PhoneError::Empty)));
    }
}
