//! Attachment Analysis
//!
//! File type detection, malware indicators, and content extraction.

use crate::Attachment;
use std::collections::HashSet;

/// Attachment analyzer
pub struct AttachmentAnalyzer {
    /// Dangerous file extensions
    dangerous_extensions: HashSet<String>,
    /// Known malware hashes
    malware_hashes: dashmap::DashMap<String, MalwareInfo>,
}

#[derive(Debug, Clone)]
pub struct AttachmentResult {
    pub is_malicious: bool,
    pub needs_sandbox: bool,
    pub confidence: f64,
    pub threats: Vec<AttachmentThreat>,
    pub file_analysis: FileAnalysis,
}

#[derive(Debug, Clone)]
pub struct AttachmentThreat {
    pub threat_type: AttachmentThreatType,
    pub description: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentThreatType {
    Malware,
    Ransomware,
    Exploit,
    Macro,
    Script,
    Executable,
    PasswordProtected,
    SuspiciousArchive,
}

#[derive(Debug, Clone, Default)]
pub struct FileAnalysis {
    pub detected_type: String,
    pub magic_bytes: String,
    pub has_macros: bool,
    pub has_ole: bool,
    pub has_scripts: bool,
    pub nested_count: usize,
    pub compression_ratio: Option<f64>,
    pub entropy: f64,
}

#[derive(Debug, Clone)]
pub struct MalwareInfo {
    pub hash: String,
    pub name: String,
    pub family: String,
    pub severity: u8,
}

impl AttachmentAnalyzer {
    pub fn new() -> Self {
        Self {
            dangerous_extensions: dangerous_extensions(),
            malware_hashes: dashmap::DashMap::new(),
        }
    }
    
    /// Analyze an attachment for threats
    pub async fn analyze(&self, attachment: &Attachment) -> AttachmentResult {
        let mut result = AttachmentResult {
            is_malicious: false,
            needs_sandbox: false,
            confidence: 0.0,
            threats: Vec::new(),
            file_analysis: FileAnalysis::default(),
        };
        
        // 1. Check known malware hashes
        if let Some(malware) = self.malware_hashes.get(&attachment.hash_sha256) {
            result.is_malicious = true;
            result.confidence = 1.0;
            result.threats.push(AttachmentThreat {
                threat_type: AttachmentThreatType::Malware,
                description: format!("Known malware: {} ({})", malware.name, malware.family),
                confidence: 1.0,
            });
            return result;
        }
        
        // 2. Check file extension
        let ext = attachment.filename.rsplit('.')
            .next()
            .unwrap_or("")
            .to_lowercase();
        
        if self.dangerous_extensions.contains(&ext) {
            result.threats.push(AttachmentThreat {
                threat_type: AttachmentThreatType::Executable,
                description: format!("Dangerous file type: .{}", ext),
                confidence: 0.9,
            });
            result.is_malicious = ext == "exe" || ext == "scr" || ext == "bat";
            result.needs_sandbox = true;
        }
        
        // 3. Check for double extension
        let parts: Vec<&str> = attachment.filename.split('.').collect();
        if parts.len() > 2 {
            let second_last = parts[parts.len() - 2].to_lowercase();
            if self.dangerous_extensions.contains(&second_last) {
                result.threats.push(AttachmentThreat {
                    threat_type: AttachmentThreatType::SuspiciousArchive,
                    description: "Double file extension detected".to_string(),
                    confidence: 0.8,
                });
                result.needs_sandbox = true;
            }
        }
        
        // 4. Check content type mismatch
        if let Some(mismatch) = self.check_content_type_mismatch(attachment) {
            result.threats.push(AttachmentThreat {
                threat_type: AttachmentThreatType::SuspiciousArchive,
                description: mismatch,
                confidence: 0.7,
            });
            result.needs_sandbox = true;
        }
        
        // 5. Analyze file structure
        result.file_analysis = self.analyze_file_structure(attachment);
        
        // Check for macros in Office documents
        if result.file_analysis.has_macros {
            result.threats.push(AttachmentThreat {
                threat_type: AttachmentThreatType::Macro,
                description: "Document contains macros".to_string(),
                confidence: 0.6,
            });
            result.needs_sandbox = true;
        }
        
        // Check for scripts
        if result.file_analysis.has_scripts {
            result.threats.push(AttachmentThreat {
                threat_type: AttachmentThreatType::Script,
                description: "File contains embedded scripts".to_string(),
                confidence: 0.7,
            });
            result.needs_sandbox = true;
        }
        
        // High entropy suggests encryption/packing
        if result.file_analysis.entropy > 7.5 {
            result.threats.push(AttachmentThreat {
                threat_type: AttachmentThreatType::SuspiciousArchive,
                description: "High entropy content (possibly packed/encrypted)".to_string(),
                confidence: 0.5,
            });
            result.needs_sandbox = true;
        }
        
        // Calculate overall confidence
        if !result.threats.is_empty() {
            let max_confidence = result.threats.iter()
                .map(|t| t.confidence)
                .max_by(|a, b| a.partial_cmp(b).unwrap())
                .unwrap_or(0.0);
            result.confidence = max_confidence;
        }
        
        result
    }
    
    fn check_content_type_mismatch(&self, attachment: &Attachment) -> Option<String> {
        let ext = attachment.filename.rsplit('.')
            .next()
            .unwrap_or("")
            .to_lowercase();
        
        let content_type = &attachment.content_type.to_lowercase();
        
        // PDF claimed but different content type
        if ext == "pdf" && !content_type.contains("pdf") {
            return Some("PDF extension but non-PDF content type".to_string());
        }
        
        // Image claimed but application type
        if ["jpg", "png", "gif"].contains(&ext.as_str()) 
            && content_type.starts_with("application/") 
        {
            return Some("Image extension but application content type".to_string());
        }
        
        // Document claimed but executable type
        if ["doc", "docx", "xls", "xlsx"].contains(&ext.as_str())
            && content_type.contains("executable")
        {
            return Some("Document extension but executable content type".to_string());
        }
        
        None
    }
    
    fn analyze_file_structure(&self, attachment: &Attachment) -> FileAnalysis {
        let mut analysis = FileAnalysis::default();
        
        // Set detected type from content-type
        analysis.detected_type = attachment.content_type.clone();
        
        // Check for Office document with macros
        let content_type = &attachment.content_type.to_lowercase();
        if content_type.contains("macro") || content_type.contains("xlsm") 
            || content_type.contains("docm") 
        {
            analysis.has_macros = true;
        }
        
        // Check for OLE containers
        if content_type.contains("ms-office") || content_type.contains("oleobject") {
            analysis.has_ole = true;
        }
        
        // Count nested files
        analysis.nested_count = attachment.nested_files.len();
        
        // Calculate entropy (placeholder - would use actual file content)
        analysis.entropy = 5.0; // Default moderate entropy
        
        analysis
    }
    
    /// Add known malware hash
    pub fn add_malware_hash(&self, hash: &str, info: MalwareInfo) {
        self.malware_hashes.insert(hash.to_lowercase(), info);
    }
}

impl Default for AttachmentAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

fn dangerous_extensions() -> HashSet<String> {
    [
        // Executables
        "exe", "com", "bat", "cmd", "scr", "pif", "msi", "msp",
        // Scripts
        "js", "jse", "vbs", "vbe", "wsf", "wsh", "ps1", "psm1",
        // Office macros
        "docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam",
        // Other dangerous
        "hta", "cpl", "jar", "reg", "lnk", "inf", "scf",
        // Archives (need inspection)
        "iso", "img", "vhd",
    ].iter().map(|s| s.to_string()).collect()
}
