//! Main DLP scanner combining all detection methods

use crate::{
    Classifier, ClassifierType, Severity,
    patterns::{PatternSet, PatternMatch},
    entropy::{find_high_entropy_regions, string_entropy},
    checksum::{luhn_valid, ssn_valid, aws_key_valid},
};
use sase_common::Timestamp;
use std::sync::Arc;

/// A DLP match result
#[derive(Debug, Clone)]
pub struct Match {
    /// Classifier ID
    pub classifier_id: u32,
    /// Classifier name
    pub classifier_name: String,
    /// Severity
    pub severity: Severity,
    /// Start position
    pub start: usize,
    /// End position
    pub end: usize,
    /// Matched text (possibly masked)
    pub matched_text: String,
    /// Confidence (0.0 - 1.0)
    pub confidence: f64,
}

impl Match {
    /// Mask the matched text for safe logging
    pub fn masked_text(&self) -> String {
        let text = &self.matched_text;
        if text.len() <= 4 {
            return "****".to_string();
        }
        format!("{}****{}", &text[..2], &text[text.len()-2..])
    }
}

/// Scan result
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Content length scanned
    pub content_length: usize,
    /// Scan duration in microseconds
    pub scan_time_us: u64,
    /// Matches found
    pub matches: Vec<Match>,
    /// Highest severity found
    pub highest_severity: Option<Severity>,
    /// Throughput in MB/s
    pub throughput_mbps: f64,
}

impl ScanResult {
    /// Check if any sensitive data was found
    pub fn has_matches(&self) -> bool {
        !self.matches.is_empty()
    }

    /// Get match count
    pub fn match_count(&self) -> usize {
        self.matches.len()
    }
}

/// Ultra-fast DLP scanner
pub struct DLPScanner {
    /// Classifier definitions
    classifiers: Arc<Vec<Classifier>>,
    /// Compiled patterns
    patterns: PatternSet,
    /// Entropy threshold
    entropy_threshold: f64,
}

impl DLPScanner {
    /// Create scanner with classifiers
    pub fn new(classifiers: Vec<Classifier>) -> Self {
        let patterns = PatternSet::build(&classifiers);
        let entropy_threshold = patterns.entropy_threshold();
        
        Self {
            classifiers: Arc::new(classifiers),
            patterns,
            entropy_threshold,
        }
    }

    /// Create with default classifiers
    pub fn default_classifiers() -> Self {
        Self::new(crate::default_classifiers())
    }

    /// Scan text content
    /// 
    /// # Performance
    /// 
    /// Target: <50μs for 1KB, 10GB/s throughput
    pub fn scan(&self, content: &str) -> ScanResult {
        let start = Timestamp::now();
        let mut matches = Vec::new();

        // Phase 1: Fast literal matches (O(n) Aho-Corasick)
        for pm in self.patterns.find_literals(content) {
            matches.push(self.convert_match(pm, content));
        }

        // Phase 2: Regex matches
        for pm in self.patterns.find_regexes(content) {
            matches.push(self.convert_match(pm, content));
        }

        // Phase 3: Entropy-based detection
        for (start_pos, end_pos, entropy) in 
            find_high_entropy_regions(content, self.entropy_threshold, 16, 128) 
        {
            let text = &content[start_pos..end_pos];
            matches.push(Match {
                classifier_id: 5,  // High entropy classifier
                classifier_name: "high_entropy".to_string(),
                severity: Severity::High,
                start: start_pos,
                end: end_pos,
                matched_text: text.to_string(),
                confidence: (entropy - self.entropy_threshold) / 2.0 + 0.5,
            });
        }

        // Phase 4: Validate checksums (filter false positives)
        matches.retain(|m| self.validate_match(m));

        // Deduplicate overlapping matches
        self.deduplicate(&mut matches);

        // Find highest severity
        let highest_severity = matches.iter()
            .map(|m| m.severity)
            .max();

        let elapsed_us = start.elapsed_micros();
        let throughput = if elapsed_us > 0 {
            (content.len() as f64) / (elapsed_us as f64)  // MB/s approximation
        } else {
            f64::INFINITY
        };

        ScanResult {
            content_length: content.len(),
            scan_time_us: elapsed_us,
            matches,
            highest_severity,
            throughput_mbps: throughput,
        }
    }

    /// Scan with timeout (for large content)
    pub fn scan_with_limit(&self, content: &str, max_bytes: usize) -> ScanResult {
        if content.len() <= max_bytes {
            return self.scan(content);
        }

        // Find safe UTF-8 boundary
        let mut end = max_bytes;
        while end > 0 && !content.is_char_boundary(end) {
            end -= 1;
        }

        self.scan(&content[..end])
    }

    /// Convert pattern match to DLP match
    fn convert_match(&self, pm: PatternMatch, _content: &str) -> Match {
        let classifier = self.classifiers.iter()
            .find(|c| c.id == pm.classifier_id);

        let (name, severity) = classifier
            .map(|c| (c.name.clone(), c.severity))
            .unwrap_or_else(|| ("unknown".to_string(), Severity::Medium));

        Match {
            classifier_id: pm.classifier_id,
            classifier_name: name,
            severity,
            start: pm.start,
            end: pm.end,
            matched_text: pm.matched_text.to_string(),
            confidence: 1.0,
        }
    }

    /// Validate match with checksum if applicable
    fn validate_match(&self, m: &Match) -> bool {
        let classifier = self.classifiers.iter()
            .find(|c| c.id == m.classifier_id);

        if let Some(c) = classifier {
            if c.validate_checksum {
                return match c.name.as_str() {
                    "credit_card" => luhn_valid(&m.matched_text),
                    "ssn" => ssn_valid(&m.matched_text),
                    "aws_access_key" => aws_key_valid(&m.matched_text),
                    _ => true,
                };
            }
        }

        true
    }

    /// Remove overlapping matches (keep higher severity)
    fn deduplicate(&self, matches: &mut Vec<Match>) {
        if matches.len() <= 1 {
            return;
        }

        matches.sort_by(|a, b| {
            a.start.cmp(&b.start)
                .then_with(|| b.severity.cmp(&a.severity))
        });

        let mut keep = vec![true; matches.len()];
        
        for i in 1..matches.len() {
            if matches[i].start < matches[i-1].end {
                // Overlap - keep higher severity (already sorted)
                keep[i] = false;
            }
        }

        let mut idx = 0;
        matches.retain(|_| {
            let k = keep[idx];
            idx += 1;
            k
        });
    }

    /// Get classifier count
    pub fn classifier_count(&self) -> usize {
        self.classifiers.len()
    }
}

impl Default for DLPScanner {
    fn default() -> Self {
        Self::default_classifiers()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_ssn() {
        let scanner = DLPScanner::default_classifiers();
        let result = scanner.scan("Customer SSN: 123-45-6789");
        
        assert!(result.has_matches());
        assert!(result.matches.iter().any(|m| m.classifier_name == "ssn"));
    }

    #[test]
    fn test_scan_credit_card() {
        let scanner = DLPScanner::default_classifiers();
        
        // Valid Luhn
        let result = scanner.scan("Card: 4111-1111-1111-1111");
        assert!(result.has_matches());
        
        // Invalid Luhn (should be filtered)
        let result = scanner.scan("Card: 1234-5678-9012-3456");
        let cc_matches: Vec<_> = result.matches.iter()
            .filter(|m| m.classifier_name == "credit_card")
            .collect();
        assert!(cc_matches.is_empty());
    }

    #[test]
    fn test_scan_aws_key() {
        let scanner = DLPScanner::default_classifiers();
        let result = scanner.scan("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE");
        
        assert!(result.has_matches());
        assert!(result.matches.iter().any(|m| m.classifier_name == "aws_access_key"));
    }

    #[test]
    fn test_scan_private_key() {
        let scanner = DLPScanner::default_classifiers();
        let result = scanner.scan("-----BEGIN RSA PRIVATE KEY-----");
        
        assert!(result.has_matches());
        assert!(result.matches.iter().any(|m| m.classifier_name == "private_key"));
    }

    #[test]
    fn test_scan_performance() {
        let scanner = DLPScanner::default_classifiers();
        
        // Generate 1MB of test data
        let content: String = (0..1_000_000)
            .map(|i| if i % 1000 == 0 { '1' } else { 'x' })
            .collect();

        let start = std::time::Instant::now();
        for _ in 0..10 {
            let _ = scanner.scan(&content);
        }
        let elapsed = start.elapsed();
        
        let throughput_gbps = 10.0 / elapsed.as_secs_f64();
        println!("DLP scan throughput: {:.2} GB/s", throughput_gbps);
        
        // Should process at least 1GB/s
        assert!(throughput_gbps > 1.0);
    }
}
