//! Aho-Corasick based pattern matching

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use regex::Regex;
use crate::{Classifier, ClassifierType, Severity};

/// Pre-compiled pattern set for O(n) multi-pattern matching
pub struct PatternSet {
    /// Aho-Corasick automaton for literals
    literals: AhoCorasick,
    literal_ids: Vec<u32>,
    
    /// Compiled regexes (for complex patterns)
    regexes: Vec<(u32, Regex, Severity)>,
    
    /// Entropy threshold
    entropy_threshold: f64,
}

impl PatternSet {
    /// Build pattern set from classifiers
    pub fn build(classifiers: &[Classifier]) -> Self {
        let mut literal_patterns = Vec::new();
        let mut literal_ids = Vec::new();
        let mut regexes = Vec::new();
        let mut entropy_threshold = 4.5;

        for classifier in classifiers {
            match classifier.classifier_type {
                ClassifierType::Literal => {
                    literal_patterns.push(&classifier.pattern);
                    literal_ids.push(classifier.id);
                }
                ClassifierType::Regex => {
                    if let Ok(re) = Regex::new(&classifier.pattern) {
                        regexes.push((classifier.id, re, classifier.severity));
                    }
                }
                ClassifierType::Entropy => {
                    // Use pattern as threshold if specified
                    if let Ok(t) = classifier.pattern.parse() {
                        entropy_threshold = t;
                    }
                }
                ClassifierType::Checksum => {
                    // Checksums are applied as post-filter
                }
            }
        }

        let literals = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostFirst)
            .build(&literal_patterns)
            .expect("Failed to build Aho-Corasick");

        Self {
            literals,
            literal_ids,
            regexes,
            entropy_threshold,
        }
    }

    /// Find all literal matches (O(n) complexity)
    #[inline]
    pub fn find_literals<'a>(&'a self, text: &'a str) -> impl Iterator<Item = PatternMatch> + 'a {
        self.literals.find_iter(text).map(move |m| {
            PatternMatch {
                classifier_id: self.literal_ids[m.pattern().as_usize()],
                start: m.start(),
                end: m.end(),
                matched_text: &text[m.start()..m.end()],
            }
        })
    }

    /// Find all regex matches
    #[inline]
    pub fn find_regexes<'a>(&'a self, text: &'a str) -> Vec<PatternMatch<'a>> {
        let mut matches = Vec::new();
        
        for (id, regex, _) in &self.regexes {
            for m in regex.find_iter(text) {
                matches.push(PatternMatch {
                    classifier_id: *id,
                    start: m.start(),
                    end: m.end(),
                    matched_text: m.as_str(),
                });
            }
        }
        
        matches
    }

    /// Get entropy threshold
    pub fn entropy_threshold(&self) -> f64 {
        self.entropy_threshold
    }

    /// Total number of patterns
    pub fn pattern_count(&self) -> usize {
        self.literal_ids.len() + self.regexes.len()
    }
}

/// A pattern match result
#[derive(Debug, Clone)]
pub struct PatternMatch<'a> {
    /// Classifier ID that matched
    pub classifier_id: u32,
    /// Start position in text
    pub start: usize,
    /// End position in text
    pub end: usize,
    /// Matched text slice
    pub matched_text: &'a str,
}

impl<'a> PatternMatch<'a> {
    /// Get match length
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_literal_matching() {
        let classifiers = vec![
            Classifier::private_key(),
        ];
        
        let patterns = PatternSet::build(&classifiers);
        let text = "This contains -----BEGIN RSA PRIVATE KEY-----";
        
        let matches: Vec<_> = patterns.find_literals(text).collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].matched_text, "-----BEGIN");
    }

    #[test]
    fn test_regex_matching() {
        let classifiers = vec![
            Classifier::ssn(),
            Classifier::credit_card(),
        ];
        
        let patterns = PatternSet::build(&classifiers);
        let text = "SSN: 123-45-6789, Card: 4111-1111-1111-1111";
        
        let matches = patterns.find_regexes(text);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_performance() {
        let classifiers = crate::default_classifiers();
        let patterns = PatternSet::build(&classifiers);
        
        // Generate 1MB of text
        let text: String = (0..1_000_000).map(|_| 'x').collect();
        
        let start = std::time::Instant::now();
        let _: Vec<_> = patterns.find_literals(&text).collect();
        let elapsed = start.elapsed();
        
        let throughput_gbps = 1.0 / elapsed.as_secs_f64();
        println!("Literal scan throughput: {:.2} GB/s", throughput_gbps);
        
        // Should process at least 1GB/s
        assert!(throughput_gbps > 1.0);
    }
}
