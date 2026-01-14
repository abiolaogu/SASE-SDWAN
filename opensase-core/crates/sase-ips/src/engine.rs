//! IPS Engine
//!
//! High-performance inspection engine that uses compiled Hyperscan
//! databases to match patterns against packet payloads.

use crate::compiler::{CompiledDatabase, CompiledPattern, RuleCompiler};
use crate::parser::RuleAction;
use crate::{IpsError, Result};
use std::sync::Arc;

/// Inspection verdict
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Allow packet to pass
    Allow,
    
    /// Block/drop packet
    Block,
    
    /// Alert but allow
    Alert,
    
    /// Reject (send RST)
    Reject,
}

/// Match information
#[derive(Clone, Debug)]
pub struct Match {
    /// Pattern ID
    pub pattern_id: u32,
    
    /// SID
    pub sid: u32,
    
    /// Match start offset
    pub from: u64,
    
    /// Match end offset
    pub to: u64,
    
    /// Pattern info
    pub pattern: CompiledPattern,
}

/// Inspection result
#[derive(Clone, Debug)]
pub struct InspectionResult {
    /// Overall verdict
    pub verdict: Verdict,
    
    /// All matches found
    pub matches: Vec<Match>,
    
    /// Bytes scanned
    pub bytes_scanned: usize,
    
    /// Scan time in nanoseconds
    pub scan_time_ns: u64,
}

impl InspectionResult {
    /// Create clean result (no matches)
    pub fn clean(bytes: usize, time_ns: u64) -> Self {
        Self {
            verdict: Verdict::Allow,
            matches: Vec::new(),
            bytes_scanned: bytes,
            scan_time_ns: time_ns,
        }
    }
    
    /// Check if any blocking rule matched
    pub fn is_blocked(&self) -> bool {
        matches!(self.verdict, Verdict::Block | Verdict::Reject)
    }
    
    /// Check if any alert was generated
    pub fn has_alerts(&self) -> bool {
        !self.matches.is_empty()
    }
}

/// Match context for Hyperscan callback
struct MatchContext<'a> {
    matches: Vec<Match>,
    should_block: bool,
    database: &'a CompiledDatabase,
}

/// IPS Engine
pub struct IpsEngine {
    /// Rule compiler
    compiler: RuleCompiler,
    
    /// Statistics
    stats: EngineStats,
}

/// Engine statistics
#[derive(Clone, Debug, Default)]
pub struct EngineStats {
    pub packets_inspected: u64,
    pub bytes_inspected: u64,
    pub matches_found: u64,
    pub packets_blocked: u64,
    pub packets_alerted: u64,
}

impl IpsEngine {
    /// Create new engine
    pub fn new() -> Self {
        Self {
            compiler: RuleCompiler::new(),
            stats: EngineStats::default(),
        }
    }
    
    /// Load rules from file
    pub fn load_rules(&mut self, path: &std::path::Path) -> Result<()> {
        self.compiler.hot_reload(path)?;
        Ok(())
    }
    
    /// Compile rules
    pub fn compile_rules(&mut self, rules: &[crate::parser::SuricataRule]) -> Result<()> {
        self.compiler.compile(rules)?;
        Ok(())
    }
    
    /// Inspect data
    pub fn inspect(&mut self, data: &[u8]) -> InspectionResult {
        let start = std::time::Instant::now();
        let db = self.compiler.database();
        
        if db.pattern_count == 0 {
            return InspectionResult::clean(data.len(), 0);
        }
        
        let mut ctx = MatchContext {
            matches: Vec::new(),
            should_block: false,
            database: &db,
        };
        
        // Use Hyperscan if available
        #[cfg(feature = "hyperscan")]
        {
            if let (Some(ref hs_db), Some(ref scratch_template)) = 
                (&db.hs_database, &db.hs_scratch) 
            {
                // Clone scratch for this thread
                let scratch = scratch_template.clone();
                
                let _ = hs_db.scan(
                    data,
                    &scratch,
                    |id, from, to, _flags| {
                        self.handle_match(&mut ctx, id, from, to);
                        // Return true to stop on block
                        ctx.should_block
                    },
                );
            } else {
                // Fallback to simple matching
                self.simple_match(&mut ctx, data, &db);
            }
        }
        
        #[cfg(not(feature = "hyperscan"))]
        {
            self.simple_match(&mut ctx, data, &db);
        }
        
        let elapsed = start.elapsed().as_nanos() as u64;
        
        // Update stats
        self.stats.packets_inspected += 1;
        self.stats.bytes_inspected += data.len() as u64;
        self.stats.matches_found += ctx.matches.len() as u64;
        
        // Determine verdict
        let verdict = if ctx.should_block {
            self.stats.packets_blocked += 1;
            Verdict::Block
        } else if !ctx.matches.is_empty() {
            self.stats.packets_alerted += 1;
            Verdict::Alert
        } else {
            Verdict::Allow
        };
        
        InspectionResult {
            verdict,
            matches: ctx.matches,
            bytes_scanned: data.len(),
            scan_time_ns: elapsed,
        }
    }
    
    /// Handle a pattern match
    fn handle_match(&self, ctx: &mut MatchContext, id: u32, from: u64, to: u64) {
        if let Some(pattern) = ctx.database.get_pattern(id) {
            let m = Match {
                pattern_id: id,
                sid: pattern.sid,
                from,
                to,
                pattern: pattern.clone(),
            };
            
            ctx.matches.push(m);
            
            // Check if blocking
            if matches!(pattern.action, RuleAction::Drop | RuleAction::Reject) {
                ctx.should_block = true;
            }
        }
    }
    
    /// Simple regex-based matching (fallback)
    fn simple_match(&self, ctx: &mut MatchContext, data: &[u8], db: &CompiledDatabase) {
        use aho_corasick::AhoCorasick;
        
        // Build Aho-Corasick automaton for literal patterns
        let literals: Vec<&str> = db.patterns
            .iter()
            .filter(|p| !p.contains('\\') && !p.contains('|'))
            .map(|s| s.as_str())
            .collect();
        
        if !literals.is_empty() {
            if let Ok(ac) = AhoCorasick::new(&literals) {
                for mat in ac.find_iter(data) {
                    let id = mat.pattern().as_u32();
                    self.handle_match(ctx, id, mat.start() as u64, mat.end() as u64);
                    
                    if ctx.should_block {
                        return;
                    }
                }
            }
        }
    }
    
    /// Get engine statistics
    pub fn stats(&self) -> &EngineStats {
        &self.stats
    }
    
    /// Get compiler
    pub fn compiler(&self) -> &RuleCompiler {
        &self.compiler
    }
    
    /// Get mutable compiler
    pub fn compiler_mut(&mut self) -> &mut RuleCompiler {
        &mut self.compiler
    }
}

impl Default for IpsEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::RuleParser;

    #[test]
    fn test_inspect_match() {
        let rules_text = r#"
            alert http any any -> any any (msg:"Malware"; content:"malware"; nocase; sid:1;)
        "#;
        
        let mut parser = RuleParser::new();
        parser.parse_content(rules_text).unwrap();
        let rules = parser.into_rules();
        
        let mut engine = IpsEngine::new();
        engine.compile_rules(&rules).unwrap();
        
        // Should match
        let result = engine.inspect(b"GET /download/MALWARE.exe HTTP/1.1");
        assert!(result.has_alerts());
        assert_eq!(result.verdict, Verdict::Alert);
        
        // Should not match
        let result = engine.inspect(b"GET /index.html HTTP/1.1");
        assert!(!result.has_alerts());
        assert_eq!(result.verdict, Verdict::Allow);
    }

    #[test]
    fn test_inspect_block() {
        let rules_text = r#"
            drop http any any -> any any (msg:"Block Exe"; content:".exe"; sid:1;)
        "#;
        
        let mut parser = RuleParser::new();
        parser.parse_content(rules_text).unwrap();
        let rules = parser.into_rules();
        
        let mut engine = IpsEngine::new();
        engine.compile_rules(&rules).unwrap();
        
        let result = engine.inspect(b"GET /malware.exe HTTP/1.1");
        assert!(result.is_blocked());
        assert_eq!(result.verdict, Verdict::Block);
    }
}
