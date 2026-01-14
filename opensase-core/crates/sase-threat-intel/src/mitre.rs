//! MITRE ATT&CK Framework Integration
//!
//! Maps indicators to ATT&CK tactics and techniques.

use crate::{Indicator, ThreatType};
use std::collections::HashMap;

/// MITRE ATT&CK mapper
pub struct MitreMapper {
    /// Tactic definitions
    tactics: HashMap<String, Tactic>,
    /// Technique definitions
    techniques: HashMap<String, Technique>,
    /// Sub-technique definitions
    sub_techniques: HashMap<String, SubTechnique>,
    /// Mapping rules
    rules: Vec<MappingRule>,
}

#[derive(Debug, Clone)]
pub struct Tactic {
    pub id: String,
    pub name: String,
    pub shortname: String,
    pub description: String,
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct Technique {
    pub id: String,
    pub name: String,
    pub description: String,
    pub tactics: Vec<String>,
    pub platforms: Vec<String>,
    pub data_sources: Vec<String>,
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct SubTechnique {
    pub id: String,
    pub name: String,
    pub parent_id: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct MappingRule {
    pub name: String,
    pub conditions: Vec<MappingCondition>,
    pub tactics: Vec<String>,
    pub techniques: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum MappingCondition {
    ThreatType(ThreatType),
    Tag(String),
    HasKillChainPhase(String),
    MalwareFamily(String),
}

impl MitreMapper {
    pub fn new() -> Self {
        let mut mapper = Self {
            tactics: HashMap::new(),
            techniques: HashMap::new(),
            sub_techniques: HashMap::new(),
            rules: Vec::new(),
        };
        
        // Load ATT&CK framework
        mapper.load_framework();
        mapper.load_mapping_rules();
        
        mapper
    }
    
    /// Map indicator to ATT&CK
    pub fn map(&self, indicator: &mut Indicator) {
        // Apply rules
        for rule in &self.rules {
            if self.matches_rule(indicator, rule) {
                for tactic in &rule.tactics {
                    if !indicator.mitre_tactics.contains(tactic) {
                        indicator.mitre_tactics.push(tactic.clone());
                    }
                }
                for technique in &rule.techniques {
                    if !indicator.mitre_techniques.contains(technique) {
                        indicator.mitre_techniques.push(technique.clone());
                    }
                }
            }
        }
        
        // Map based on threat type
        if let Some(threat_type) = indicator.context.threat_type {
            let (tactics, techniques) = self.map_threat_type(threat_type);
            for tactic in tactics {
                if !indicator.mitre_tactics.contains(&tactic) {
                    indicator.mitre_tactics.push(tactic);
                }
            }
            for technique in techniques {
                if !indicator.mitre_techniques.contains(&technique) {
                    indicator.mitre_techniques.push(technique);
                }
            }
        }
        
        // Map based on kill chain phases
        for phase in &indicator.context.kill_chain_phases {
            if let Some(tactic) = self.kill_chain_to_tactic(phase) {
                if !indicator.mitre_tactics.contains(&tactic) {
                    indicator.mitre_tactics.push(tactic);
                }
            }
        }
    }
    
    /// Get tactic details
    pub fn get_tactic(&self, id: &str) -> Option<&Tactic> {
        self.tactics.get(id)
    }
    
    /// Get technique details
    pub fn get_technique(&self, id: &str) -> Option<&Technique> {
        self.techniques.get(id)
    }
    
    /// Get all tactics for a technique
    pub fn get_tactics_for_technique(&self, technique_id: &str) -> Vec<String> {
        self.techniques.get(technique_id)
            .map(|t| t.tactics.clone())
            .unwrap_or_default()
    }
    
    fn matches_rule(&self, indicator: &Indicator, rule: &MappingRule) -> bool {
        for condition in &rule.conditions {
            let matches = match condition {
                MappingCondition::ThreatType(tt) => {
                    indicator.context.threat_type == Some(*tt)
                }
                MappingCondition::Tag(tag) => {
                    indicator.tags.iter().any(|t| t.to_lowercase().contains(&tag.to_lowercase()))
                }
                MappingCondition::HasKillChainPhase(phase) => {
                    indicator.context.kill_chain_phases.contains(phase)
                }
                MappingCondition::MalwareFamily(family) => {
                    indicator.context.malware_family.as_ref()
                        .map(|f| f.to_lowercase().contains(&family.to_lowercase()))
                        .unwrap_or(false)
                }
            };
            
            if !matches {
                return false;
            }
        }
        true
    }
    
    fn map_threat_type(&self, threat_type: ThreatType) -> (Vec<String>, Vec<String>) {
        match threat_type {
            ThreatType::C2 => (
                vec!["TA0011".to_string()], // Command and Control
                vec!["T1071".to_string(), "T1095".to_string()], // Application Layer Protocol, Non-Application Layer Protocol
            ),
            ThreatType::Phishing => (
                vec!["TA0001".to_string()], // Initial Access
                vec!["T1566".to_string()], // Phishing
            ),
            ThreatType::Ransomware => (
                vec!["TA0040".to_string()], // Impact
                vec!["T1486".to_string()], // Data Encrypted for Impact
            ),
            ThreatType::Botnet => (
                vec!["TA0011".to_string()], // Command and Control
                vec!["T1071".to_string(), "T1568".to_string()], // Application Layer Protocol, Dynamic Resolution
            ),
            ThreatType::Malware => (
                vec!["TA0002".to_string()], // Execution
                vec!["T1204".to_string()], // User Execution
            ),
            ThreatType::Scanner => (
                vec!["TA0043".to_string()], // Reconnaissance
                vec!["T1595".to_string()], // Active Scanning
            ),
            ThreatType::Exploit => (
                vec!["TA0001".to_string()], // Initial Access
                vec!["T1190".to_string()], // Exploit Public-Facing Application
            ),
            ThreatType::Apt => (
                vec!["TA0001".to_string(), "TA0003".to_string()], // Initial Access, Persistence
                vec!["T1566".to_string(), "T1053".to_string()], // Phishing, Scheduled Task
            ),
            ThreatType::Cryptominer => (
                vec!["TA0040".to_string()], // Impact
                vec!["T1496".to_string()], // Resource Hijacking
            ),
            ThreatType::Spam | ThreatType::Proxy | ThreatType::Tor | ThreatType::Vpn => (
                Vec::new(),
                Vec::new(),
            ),
        }
    }
    
    fn kill_chain_to_tactic(&self, phase: &str) -> Option<String> {
        match phase.to_lowercase().as_str() {
            "reconnaissance" => Some("TA0043".to_string()),
            "resource-development" | "weaponization" => Some("TA0042".to_string()),
            "initial-access" | "delivery" => Some("TA0001".to_string()),
            "execution" | "exploitation" => Some("TA0002".to_string()),
            "persistence" | "installation" => Some("TA0003".to_string()),
            "privilege-escalation" => Some("TA0004".to_string()),
            "defense-evasion" => Some("TA0005".to_string()),
            "credential-access" => Some("TA0006".to_string()),
            "discovery" => Some("TA0007".to_string()),
            "lateral-movement" => Some("TA0008".to_string()),
            "collection" => Some("TA0009".to_string()),
            "command-and-control" | "c2" => Some("TA0011".to_string()),
            "exfiltration" => Some("TA0010".to_string()),
            "impact" | "actions-on-objectives" => Some("TA0040".to_string()),
            _ => None,
        }
    }
    
    fn load_framework(&mut self) {
        // Load enterprise ATT&CK tactics
        let tactics_data = [
            ("TA0043", "Reconnaissance", "reconnaissance"),
            ("TA0042", "Resource Development", "resource-development"),
            ("TA0001", "Initial Access", "initial-access"),
            ("TA0002", "Execution", "execution"),
            ("TA0003", "Persistence", "persistence"),
            ("TA0004", "Privilege Escalation", "privilege-escalation"),
            ("TA0005", "Defense Evasion", "defense-evasion"),
            ("TA0006", "Credential Access", "credential-access"),
            ("TA0007", "Discovery", "discovery"),
            ("TA0008", "Lateral Movement", "lateral-movement"),
            ("TA0009", "Collection", "collection"),
            ("TA0011", "Command and Control", "command-and-control"),
            ("TA0010", "Exfiltration", "exfiltration"),
            ("TA0040", "Impact", "impact"),
        ];
        
        for (id, name, shortname) in tactics_data {
            self.tactics.insert(id.to_string(), Tactic {
                id: id.to_string(),
                name: name.to_string(),
                shortname: shortname.to_string(),
                description: String::new(),
                url: format!("https://attack.mitre.org/tactics/{}/", id),
            });
        }
        
        // Load common techniques
        let techniques_data = [
            ("T1566", "Phishing", vec!["TA0001"]),
            ("T1190", "Exploit Public-Facing Application", vec!["TA0001"]),
            ("T1071", "Application Layer Protocol", vec!["TA0011"]),
            ("T1095", "Non-Application Layer Protocol", vec!["TA0011"]),
            ("T1486", "Data Encrypted for Impact", vec!["TA0040"]),
            ("T1496", "Resource Hijacking", vec!["TA0040"]),
            ("T1595", "Active Scanning", vec!["TA0043"]),
            ("T1204", "User Execution", vec!["TA0002"]),
            ("T1053", "Scheduled Task/Job", vec!["TA0003", "TA0004"]),
            ("T1568", "Dynamic Resolution", vec!["TA0011"]),
        ];
        
        for (id, name, tactics) in techniques_data {
            self.techniques.insert(id.to_string(), Technique {
                id: id.to_string(),
                name: name.to_string(),
                description: String::new(),
                tactics: tactics.iter().map(|s| s.to_string()).collect(),
                platforms: vec!["Windows".to_string(), "Linux".to_string(), "macOS".to_string()],
                data_sources: Vec::new(),
                url: format!("https://attack.mitre.org/techniques/{}/", id),
            });
        }
    }
    
    fn load_mapping_rules(&mut self) {
        self.rules = vec![
            MappingRule {
                name: "cobalt_strike".to_string(),
                conditions: vec![
                    MappingCondition::MalwareFamily("cobalt".to_string()),
                ],
                tactics: vec!["TA0011".to_string(), "TA0008".to_string()],
                techniques: vec!["T1071".to_string(), "T1095".to_string()],
            },
            MappingRule {
                name: "emotet".to_string(),
                conditions: vec![
                    MappingCondition::MalwareFamily("emotet".to_string()),
                ],
                tactics: vec!["TA0001".to_string(), "TA0011".to_string()],
                techniques: vec!["T1566".to_string(), "T1071".to_string()],
            },
        ];
    }
}

impl Default for MitreMapper {
    fn default() -> Self {
        Self::new()
    }
}
