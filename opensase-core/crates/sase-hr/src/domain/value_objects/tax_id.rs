//! Tax ID value object

use serde::{Deserialize, Serialize};
use std::fmt;

/// Tax identification number (SSN, EIN, etc.)
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaxId {
    id_type: TaxIdType,
    value: String, // Stored encrypted in practice
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaxIdType {
    SSN,      // Social Security Number (US)
    EIN,      // Employer Identification Number (US)
    ITIN,     // Individual Taxpayer Identification Number (US)
    NIN,      // National Insurance Number (UK)
    TIN,      // Tax Identification Number (Generic)
}

impl TaxId {
    pub fn new_ssn(value: impl Into<String>) -> Result<Self, TaxIdError> {
        let value = Self::normalize(value.into());
        if !Self::validate_ssn(&value) {
            return Err(TaxIdError::Invalid);
        }
        Ok(Self { id_type: TaxIdType::SSN, value })
    }
    
    pub fn new_ein(value: impl Into<String>) -> Result<Self, TaxIdError> {
        let value = Self::normalize(value.into());
        Ok(Self { id_type: TaxIdType::EIN, value })
    }
    
    pub fn id_type(&self) -> &TaxIdType { &self.id_type }
    
    /// Get masked value (last 4 digits only)
    pub fn masked(&self) -> String {
        let len = self.value.len();
        if len > 4 {
            format!("***-**-{}", &self.value[len-4..])
        } else {
            "***-**-****".to_string()
        }
    }
    
    fn normalize(value: String) -> String {
        value.chars().filter(|c| c.is_ascii_digit()).collect()
    }
    
    fn validate_ssn(value: &str) -> bool {
        value.len() == 9 && value.chars().all(|c| c.is_ascii_digit())
    }
}

impl fmt::Display for TaxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.masked())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaxIdError {
    Invalid,
}

impl std::error::Error for TaxIdError {}
impl fmt::Display for TaxIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid tax ID")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ssn_validation() {
        let ssn = TaxId::new_ssn("123-45-6789").unwrap();
        assert_eq!(ssn.masked(), "***-**-6789");
    }
}
