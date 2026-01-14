//! Entropy-based secret detection

/// Calculate Shannon entropy of a byte slice
/// 
/// Higher entropy = more random = more likely to be a secret
/// 
/// # Performance
/// 
/// O(n) with fast frequency counting
#[inline]
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    // Count byte frequencies
    let mut freq = [0u32; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    // Calculate entropy
    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Calculate entropy for string slice
#[inline]
pub fn string_entropy(s: &str) -> f64 {
    shannon_entropy(s.as_bytes())
}

/// Find high-entropy regions in text
/// 
/// Returns (start, end, entropy) tuples for regions above threshold
pub fn find_high_entropy_regions(
    text: &str,
    threshold: f64,
    min_len: usize,
    max_len: usize,
) -> Vec<(usize, usize, f64)> {
    let mut regions = Vec::new();
    let bytes = text.as_bytes();
    
    if bytes.len() < min_len {
        return regions;
    }

    // Sliding window approach
    let mut start = 0;
    
    while start + min_len <= bytes.len() {
        // Find word-like token boundaries
        let token_start = skip_to_token_start(bytes, start);
        if token_start >= bytes.len() {
            break;
        }
        
        let token_end = find_token_end(bytes, token_start);
        let token_len = token_end - token_start;
        
        if token_len >= min_len && token_len <= max_len {
            let token = &bytes[token_start..token_end];
            let entropy = shannon_entropy(token);
            
            if entropy >= threshold {
                regions.push((token_start, token_end, entropy));
            }
        }
        
        start = token_end + 1;
    }

    regions
}

/// Skip to start of next token
#[inline]
fn skip_to_token_start(bytes: &[u8], start: usize) -> usize {
    let mut i = start;
    while i < bytes.len() && !is_token_char(bytes[i]) {
        i += 1;
    }
    i
}

/// Find end of current token
#[inline]
fn find_token_end(bytes: &[u8], start: usize) -> usize {
    let mut i = start;
    while i < bytes.len() && is_token_char(bytes[i]) {
        i += 1;
    }
    i
}

/// Check if byte is part of a token (alphanumeric + some symbols)
#[inline]
fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'+' || b == b'/' || b == b'='
}

/// Check if string looks like a secret based on entropy
#[inline]
pub fn is_likely_secret(s: &str, threshold: f64) -> bool {
    if s.len() < 16 || s.len() > 256 {
        return false;
    }
    string_entropy(s) >= threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        // Low entropy (repetitive)
        let low = "aaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(string_entropy(low) < 1.0);

        // Medium entropy (English text)
        let medium = "the quick brown fox jumps";
        let med_entropy = string_entropy(medium);
        assert!(med_entropy > 2.0 && med_entropy < 4.5);

        // High entropy (random-looking)
        let high = "4Kx9mNpQ2wRtYuVbXzAs5DrFgHjKlMnO";
        assert!(string_entropy(high) > 4.5);
    }

    #[test]
    fn test_find_high_entropy() {
        let text = "normal text sk_live_abcdefghijklmnopqrstuvwxyz123456789012 more text";
        
        let regions = find_high_entropy_regions(text, 4.0, 16, 64);
        
        assert_eq!(regions.len(), 1);
        assert!(regions[0].2 > 4.0);  // High entropy
    }

    #[test]
    fn test_is_likely_secret() {
        assert!(!is_likely_secret("hello world", 4.5));
        assert!(is_likely_secret("sk_live_4eC39HqLyjWDarjtT1zdp7dc", 4.0));
    }
}
