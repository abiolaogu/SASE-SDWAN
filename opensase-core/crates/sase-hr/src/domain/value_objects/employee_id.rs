//! Employee ID value object

use serde::{Deserialize, Serialize};
use std::fmt;

/// Unique employee identifier (e.g., EMP-2024-00001)
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EmployeeId {
    prefix: String,
    year: u16,
    sequence: u32,
}

impl EmployeeId {
    pub fn new(year: u16, sequence: u32) -> Self {
        Self {
            prefix: "EMP".to_string(),
            year,
            sequence,
        }
    }
    
    pub fn generate(sequence: u32) -> Self {
        let year = chrono::Utc::now().format("%Y").to_string().parse().unwrap_or(2024);
        Self::new(year, sequence)
    }
    
    pub fn year(&self) -> u16 { self.year }
    pub fn sequence(&self) -> u32 { self.sequence }
}

impl fmt::Display for EmployeeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}-{:05}", self.prefix, self.year, self.sequence)
    }
}

impl Default for EmployeeId {
    fn default() -> Self {
        Self::generate(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_employee_id_format() {
        let id = EmployeeId::new(2024, 123);
        assert_eq!(id.to_string(), "EMP-2024-00123");
    }
}
