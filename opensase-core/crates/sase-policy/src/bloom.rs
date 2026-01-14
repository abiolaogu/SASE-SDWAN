//! Bloom filter for fast negative lookups

use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

/// Bloom filter for fast "definitely not" checks
/// 
/// False positive rate: ~1% at 10x data size
pub struct BloomFilter {
    bits: Vec<u64>,
    num_hashes: usize,
    num_bits: usize,
}

impl BloomFilter {
    /// Create bloom filter with expected capacity
    pub fn new(expected_items: usize) -> Self {
        // Rule of thumb: 10 bits per item for ~1% FPR
        let num_bits = expected_items * 10;
        let num_words = (num_bits + 63) / 64;
        
        Self {
            bits: vec![0u64; num_words],
            num_hashes: 7,  // Optimal for 10 bits/item
            num_bits,
        }
    }

    /// Add item to filter
    #[inline]
    pub fn add<T: Hash>(&mut self, item: &T) {
        let (h1, h2) = self.hash_pair(item);
        
        for i in 0..self.num_hashes {
            let idx = self.get_index(h1, h2, i);
            let word = idx / 64;
            let bit = idx % 64;
            self.bits[word] |= 1u64 << bit;
        }
    }

    /// Check if item might be in filter
    /// 
    /// Returns:
    /// - false: Definitely NOT in filter
    /// - true: Might be in filter (check actual store)
    #[inline(always)]
    pub fn might_contain<T: Hash>(&self, item: &T) -> bool {
        let (h1, h2) = self.hash_pair(item);
        
        for i in 0..self.num_hashes {
            let idx = self.get_index(h1, h2, i);
            let word = idx / 64;
            let bit = idx % 64;
            
            if (self.bits[word] & (1u64 << bit)) == 0 {
                return false;  // Definitely not in set
            }
        }
        
        true  // Might be in set
    }

    /// Clear filter
    pub fn clear(&mut self) {
        self.bits.fill(0);
    }

    #[inline(always)]
    fn hash_pair<T: Hash>(&self, item: &T) -> (u64, u64) {
        let mut h1 = DefaultHasher::new();
        item.hash(&mut h1);
        let hash1 = h1.finish();
        
        // Use different seed for second hash
        let mut h2 = DefaultHasher::new();
        hash1.hash(&mut h2);
        let hash2 = h2.finish();
        
        (hash1, hash2)
    }

    #[inline(always)]
    fn get_index(&self, h1: u64, h2: u64, i: usize) -> usize {
        // Double hashing: h(i) = h1 + i * h2
        let hash = h1.wrapping_add((i as u64).wrapping_mul(h2));
        (hash as usize) % self.num_bits
    }
}

impl Default for BloomFilter {
    fn default() -> Self {
        Self::new(10000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_basic() {
        let mut bloom = BloomFilter::new(100);
        
        bloom.add(&"hello");
        bloom.add(&"world");
        
        // Should contain
        assert!(bloom.might_contain(&"hello"));
        assert!(bloom.might_contain(&"world"));
        
        // Should NOT contain (with very high probability)
        assert!(!bloom.might_contain(&"foo"));
        assert!(!bloom.might_contain(&"bar"));
    }

    #[test]
    fn test_bloom_false_positive_rate() {
        let mut bloom = BloomFilter::new(1000);
        
        // Add 1000 items
        for i in 0..1000 {
            bloom.add(&i);
        }
        
        // Check false positives on different items
        let mut fp_count = 0;
        for i in 1000..2000 {
            if bloom.might_contain(&i) {
                fp_count += 1;
            }
        }
        
        // Should be less than ~1%
        let fpr = fp_count as f64 / 1000.0;
        assert!(fpr < 0.02, "FPR too high: {}", fpr);
    }
}
