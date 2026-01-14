//! Checksum validation (Luhn, SSN, etc.)

/// Validate using Luhn algorithm (credit cards, IMEI)
#[inline]
pub fn luhn_valid(digits: &str) -> bool {
    let digits: Vec<u8> = digits
        .chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| c as u8 - b'0')
        .collect();

    if digits.len() < 2 {
        return false;
    }

    let mut sum: u32 = 0;
    for (i, &d) in digits.iter().rev().enumerate() {
        let mut val = d as u32;
        if i % 2 == 1 {
            val *= 2;
            if val > 9 {
                val -= 9;
            }
        }
        sum += val;
    }

    sum % 10 == 0
}

/// Validate SSN format (area number validation)
#[inline]
pub fn ssn_valid(ssn: &str) -> bool {
    let digits: String = ssn.chars().filter(|c| c.is_ascii_digit()).collect();
    
    if digits.len() != 9 {
        return false;
    }

    let area = &digits[0..3];
    let group = &digits[3..5];
    let serial = &digits[5..9];

    // Area cannot be 000, 666, or 900-999
    if area == "000" || area == "666" || area.starts_with('9') {
        return false;
    }

    // Group cannot be 00
    if group == "00" {
        return false;
    }

    // Serial cannot be 0000
    if serial == "0000" {
        return false;
    }

    true
}

/// Validate AWS access key format
#[inline]
pub fn aws_key_valid(key: &str) -> bool {
    if key.len() != 20 {
        return false;
    }

    let prefix = &key[0..4];
    let valid_prefixes = ["AKIA", "ABIA", "ACCA", "ASIA"];
    
    if !valid_prefixes.contains(&prefix) {
        return false;
    }

    // Remaining chars must be uppercase alphanumeric
    key[4..].chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// Validate IBAN format (basic check)
#[inline]
pub fn iban_valid(iban: &str) -> bool {
    let normalized: String = iban
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();

    if normalized.len() < 15 || normalized.len() > 34 {
        return false;
    }

    // Move first 4 chars to end and convert letters to numbers
    let rearranged = format!("{}{}", &normalized[4..], &normalized[0..4]);
    
    let mut numeric = String::new();
    for c in rearranged.chars() {
        if c.is_ascii_digit() {
            numeric.push(c);
        } else if c.is_ascii_uppercase() {
            let val = c as u32 - 'A' as u32 + 10;
            numeric.push_str(&val.to_string());
        } else {
            return false;
        }
    }

    // Check mod 97
    mod97(&numeric) == 1
}

/// Calculate mod 97 for large numbers (as string)
fn mod97(s: &str) -> u32 {
    let mut remainder = 0u32;
    for c in s.chars() {
        if let Some(d) = c.to_digit(10) {
            remainder = (remainder * 10 + d) % 97;
        }
    }
    remainder
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_luhn_valid() {
        // Valid test card numbers
        assert!(luhn_valid("4111111111111111"));
        assert!(luhn_valid("4111-1111-1111-1111"));
        assert!(luhn_valid("5500 0000 0000 0004"));

        // Invalid
        assert!(!luhn_valid("1234567890123456"));
        // Note: All zeros is technically valid by Luhn (sum=0, 0%10=0)
    }

    #[test]
    fn test_ssn_valid() {
        // Valid SSNs (format only)
        assert!(ssn_valid("123-45-6789"));
        assert!(ssn_valid("078-05-1120"));

        // Invalid
        assert!(!ssn_valid("000-12-3456"));  // Area 000
        assert!(!ssn_valid("666-12-3456"));  // Area 666
        assert!(!ssn_valid("900-12-3456"));  // Area 9xx
        assert!(!ssn_valid("123-00-4567"));  // Group 00
        assert!(!ssn_valid("123-45-0000"));  // Serial 0000
    }

    #[test]
    fn test_aws_key_valid() {
        assert!(aws_key_valid("AKIAIOSFODNN7EXAMPLE"));
        assert!(aws_key_valid("ASIAIOSFODNN7EXAMPLE"));
        
        assert!(!aws_key_valid("INVALID_KEY_FORMAT1"));
        assert!(!aws_key_valid("AKIA"));  // Too short
    }

    #[test]
    fn test_iban_valid() {
        // Valid IBANs
        assert!(iban_valid("GB82WEST12345698765432"));
        assert!(iban_valid("DE89370400440532013000"));
        
        // Invalid
        assert!(!iban_valid("GB82WEST12345698765431"));  // Wrong check digit
    }
}
