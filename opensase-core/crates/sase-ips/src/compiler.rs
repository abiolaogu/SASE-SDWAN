//! Hyperscan Rule Compiler
//!
//! Compiles parsed Suricata rules into Hyperscan pattern databases
//! for high-performance pattern matching at line rate.

use crate::parser::{ContentPattern, PcrePattern, SuricataRule, RuleAction};
use crate::{Category, IpsError, Result, Severity};
use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// Compiled pattern with metadata
#[derive(Clone, Debug)]
pub struct CompiledPattern {
    /// Pattern ID (matches Hyperscan ID)
    pub id: u32,
    
    /// Original SID
    pub sid: u32,
    
    /// Rule action
    pub action: RuleAction,
    
    /// Pattern string (for debugging)
    pub pattern: String,
    
    /// Is case insensitive
    pub nocase: bool,
    
    /// Severity
    pub severity: Severity,
    
    /// Category
    pub category: Option<Category>,
    
    /// Message
    pub msg: String,
}

/// Compiled Hyperscan database
pub struct CompiledDatabase {
    /// Pattern count
    pub pattern_count: usize,
    
    /// Rule count (may differ from pattern_count if rules have multiple patterns)
    pub rule_count: usize,
    
    /// Pattern ID to rule metadata
    pub pattern_map: HashMap<u32, CompiledPattern>,
    
    /// SID to pattern IDs
    pub sid_map: HashMap<u32, Vec<u32>>,
    
    /// Compiled patterns as regex strings
    pub patterns: Vec<String>,
    
    /// Pattern flags (caseless, etc.)
    pub flags: Vec<u32>,
    
    /// Pattern IDs
    pub ids: Vec<u32>,
    
    #[cfg(feature = "hyperscan")]
    /// Hyperscan block database
    pub hs_database: Option<hyperscan::BlockDatabase>,
    
    #[cfg(feature = "hyperscan")]
    /// Hyperscan scratch (template for cloning)
    pub hs_scratch: Option<hyperscan::Scratch>,
}

impl CompiledDatabase {
    /// Get pattern metadata by ID
    pub fn get_pattern(&self, id: u32) -> Option<&CompiledPattern> {
        self.pattern_map.get(&id)
    }
    
    /// Check if action is blocking
    pub fn is_blocking(&self, id: u32) -> bool {
        self.pattern_map.get(&id)
            .map(|p| matches!(p.action, RuleAction::Drop | RuleAction::Reject))
            .unwrap_or(false)
    }
}

/// Rule compiler - compiles Suricata rules to Hyperscan
pub struct RuleCompiler {
    /// Current database (hot-swappable)
    database: ArcSwap<CompiledDatabase>,
    
    /// Compilation statistics
    stats: CompilerStats,
}

/// Compilation statistics
#[derive(Clone, Debug, Default)]
pub struct CompilerStats {
    pub total_rules: usize,
    pub compiled_patterns: usize,
    pub skipped_rules: usize,
    pub complex_patterns: usize,
    pub compile_time_ms: u64,
}

impl RuleCompiler {
    /// Create new compiler
    pub fn new() -> Self {
        Self {
            database: ArcSwap::new(Arc::new(CompiledDatabase {
                pattern_count: 0,
                rule_count: 0,
                pattern_map: HashMap::new(),
                sid_map: HashMap::new(),
                patterns: Vec::new(),
                flags: Vec::new(),
                ids: Vec::new(),
                #[cfg(feature = "hyperscan")]
                hs_database: None,
                #[cfg(feature = "hyperscan")]
                hs_scratch: None,
            })),
            stats: CompilerStats::default(),
        }
    }
    
    /// Compile rules to Hyperscan database
    pub fn compile(&mut self, rules: &[SuricataRule]) -> Result<CompilerStats> {
        let start = std::time::Instant::now();
        
        let mut patterns: Vec<String> = Vec::new();
        let mut flags: Vec<u32> = Vec::new();
        let mut ids: Vec<u32> = Vec::new();
        let mut pattern_map: HashMap<u32, CompiledPattern> = HashMap::new();
        let mut sid_map: HashMap<u32, Vec<u32>> = HashMap::new();
        let mut pattern_id: u32 = 0;
        let mut skipped = 0;
        let mut complex = 0;
        
        for rule in rules {
            let sid = rule.metadata.sid;
            let mut rule_patterns = Vec::new();
            
            // Extract content patterns
            for content in &rule.content_patterns {
                match self.content_to_pattern(content) {
                    Ok(regex_pattern) => {
                        let mut pattern_flags = 0u32;
                        
                        // Caseless flag
                        if content.options.nocase {
                            pattern_flags |= 1; // HS_FLAG_CASELESS
                        }
                        
                        // Single match (optimization)
                        pattern_flags |= 8; // HS_FLAG_SINGLEMATCH
                        
                        let cp = CompiledPattern {
                            id: pattern_id,
                            sid,
                            action: rule.action,
                            pattern: regex_pattern.clone(),
                            nocase: content.options.nocase,
                            severity: rule.metadata.severity,
                            category: rule.metadata.category.clone(),
                            msg: rule.metadata.msg.clone(),
                        };
                        
                        patterns.push(regex_pattern);
                        flags.push(pattern_flags);
                        ids.push(pattern_id);
                        pattern_map.insert(pattern_id, cp);
                        rule_patterns.push(pattern_id);
                        
                        pattern_id += 1;
                    }
                    Err(e) => {
                        tracing::debug!(
                            sid = sid,
                            error = %e,
                            "Skipping complex content pattern"
                        );
                        complex += 1;
                    }
                }
            }
            
            // Extract PCRE patterns
            for pcre in &rule.pcre_patterns {
                match self.pcre_to_pattern(pcre) {
                    Ok(regex_pattern) => {
                        let mut pattern_flags = 8; // HS_FLAG_SINGLEMATCH
                        
                        if pcre.modifiers.contains('i') {
                            pattern_flags |= 1; // HS_FLAG_CASELESS
                        }
                        if pcre.modifiers.contains('m') {
                            pattern_flags |= 2; // HS_FLAG_MULTILINE
                        }
                        if pcre.modifiers.contains('s') {
                            pattern_flags |= 4; // HS_FLAG_DOTALL
                        }
                        
                        let cp = CompiledPattern {
                            id: pattern_id,
                            sid,
                            action: rule.action,
                            pattern: regex_pattern.clone(),
                            nocase: pcre.modifiers.contains('i'),
                            severity: rule.metadata.severity,
                            category: rule.metadata.category.clone(),
                            msg: rule.metadata.msg.clone(),
                        };
                        
                        patterns.push(regex_pattern);
                        flags.push(pattern_flags);
                        ids.push(pattern_id);
                        pattern_map.insert(pattern_id, cp);
                        rule_patterns.push(pattern_id);
                        
                        pattern_id += 1;
                    }
                    Err(e) => {
                        tracing::debug!(
                            sid = sid,
                            error = %e,
                            "Skipping complex PCRE pattern"
                        );
                        complex += 1;
                    }
                }
            }
            
            if rule_patterns.is_empty() {
                skipped += 1;
            } else {
                sid_map.insert(sid, rule_patterns);
            }
        }
        
        // Compile Hyperscan database
        #[cfg(feature = "hyperscan")]
        let (hs_db, hs_scratch) = if !patterns.is_empty() {
            match self.compile_hyperscan(&patterns, &flags, &ids) {
                Ok((db, scratch)) => (Some(db), Some(scratch)),
                Err(e) => {
                    tracing::error!(error = %e, "Failed to compile Hyperscan database");
                    (None, None)
                }
            }
        } else {
            (None, None)
        };
        
        let compile_time = start.elapsed().as_millis() as u64;
        
        let db = CompiledDatabase {
            pattern_count: patterns.len(),
            rule_count: sid_map.len(),
            pattern_map,
            sid_map,
            patterns,
            flags,
            ids,
            #[cfg(feature = "hyperscan")]
            hs_database: hs_db,
            #[cfg(feature = "hyperscan")]
            hs_scratch: hs_scratch,
        };
        
        // Atomic swap
        self.database.store(Arc::new(db));
        
        self.stats = CompilerStats {
            total_rules: rules.len(),
            compiled_patterns: pattern_id as usize,
            skipped_rules: skipped,
            complex_patterns: complex,
            compile_time_ms: compile_time,
        };
        
        tracing::info!(
            rules = rules.len(),
            patterns = pattern_id,
            skipped = skipped,
            time_ms = compile_time,
            "Rule compilation complete"
        );
        
        Ok(self.stats.clone())
    }
    
    /// Convert content pattern to regex
    fn content_to_pattern(&self, content: &ContentPattern) -> Result<String> {
        if content.is_hex {
            // Already in regex format from parser
            Ok(content.pattern.clone())
        } else {
            // Escape regex metacharacters
            Ok(regex::escape(&content.pattern))
        }
    }
    
    /// Convert PCRE to regex (Hyperscan compatible)
    fn pcre_to_pattern(&self, pcre: &PcrePattern) -> Result<String> {
        // Hyperscan supports most PCRE syntax
        // Some features may need transformation
        let pattern = &pcre.pattern;
        
        // Check for unsupported features
        if pattern.contains("(?R)") || pattern.contains("(?P<") {
            return Err(IpsError::PatternTooComplex(
                "Recursive or named groups not supported".into()
            ));
        }
        
        Ok(pattern.clone())
    }
    
    /// Compile Hyperscan database
    #[cfg(feature = "hyperscan")]
    fn compile_hyperscan(
        &self,
        patterns: &[String],
        flags: &[u32],
        ids: &[u32],
    ) -> Result<(hyperscan::BlockDatabase, hyperscan::Scratch)> {
        use hyperscan::{Pattern, Patterns, CompileFlags};
        
        let hs_patterns: Vec<Pattern> = patterns
            .iter()
            .zip(flags.iter())
            .zip(ids.iter())
            .map(|((pat, flag), id)| {
                let mut hs_flags = CompileFlags::empty();
                if *flag & 1 != 0 { hs_flags |= CompileFlags::CASELESS; }
                if *flag & 2 != 0 { hs_flags |= CompileFlags::MULTILINE; }
                if *flag & 4 != 0 { hs_flags |= CompileFlags::DOTALL; }
                if *flag & 8 != 0 { hs_flags |= CompileFlags::SINGLEMATCH; }
                
                Pattern::with_flags(pat, *id, hs_flags)
            })
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| IpsError::HyperscanError(e.to_string()))?;
        
        let patterns = Patterns::from_iter(hs_patterns);
        let db = patterns.build()
            .map_err(|e| IpsError::HyperscanError(e.to_string()))?;
        let scratch = db.alloc_scratch()
            .map_err(|e| IpsError::HyperscanError(e.to_string()))?;
        
        Ok((db, scratch))
    }
    
    /// Hot reload rules from file
    pub fn hot_reload(&mut self, path: &Path) -> Result<CompilerStats> {
        use crate::parser::RuleParser;
        
        tracing::info!(path = %path.display(), "Hot reloading rules");
        
        let mut parser = RuleParser::new();
        parser.parse_file(path)?;
        
        let errors = parser.errors();
        if !errors.is_empty() {
            tracing::warn!(
                errors = errors.len(),
                "Some rules failed to parse"
            );
        }
        
        let rules = parser.into_rules();
        self.compile(&rules)
    }
    
    /// Get current database
    pub fn database(&self) -> Arc<CompiledDatabase> {
        self.database.load_full()
    }
    
    /// Get compilation stats
    pub fn stats(&self) -> &CompilerStats {
        &self.stats
    }
}

impl Default for RuleCompiler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::RuleParser;

    #[test]
    fn test_compile_rules() {
        let rules_text = r#"
            alert http any any -> any any (msg:"Test 1"; content:"malware"; nocase; sid:1;)
            alert tcp any any -> any any (msg:"Test 2"; content:"|00 01|"; sid:2;)
            alert http any any -> any any (msg:"Test 3"; pcre:"/eval\s*\(/i"; sid:3;)
        "#;
        
        let mut parser = RuleParser::new();
        parser.parse_content(rules_text).unwrap();
        
        let rules = parser.into_rules();
        assert_eq!(rules.len(), 3);
        
        let mut compiler = RuleCompiler::new();
        let stats = compiler.compile(&rules).unwrap();
        
        assert_eq!(stats.total_rules, 3);
        assert!(stats.compiled_patterns >= 3);
        
        let db = compiler.database();
        assert!(db.pattern_count >= 3);
    }
}
