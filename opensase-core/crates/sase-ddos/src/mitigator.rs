//! Mitigation Engine
//!
//! <1ms mitigation activation with multi-layer defense.

use crate::{
    ActiveMitigation, Attack, AttackType, MitigationRule, MitigationStats,
    MitigationStrategy, Protocol, RateLimit, RuleAction, RuleType,
};
use std::net::IpAddr;
use tracing::{info, warn};

/// Mitigation engine that activates defenses
pub struct MitigationEngine {
    /// VPP control socket path
    vpp_socket: String,
    /// BIRD control socket path  
    bird_socket: String,
    /// Enable automatic RTBH
    auto_rtbh: bool,
    /// Enable automatic Flowspec
    auto_flowspec: bool,
    /// Maximum ACL rules
    max_acl_rules: usize,
}

impl MitigationEngine {
    pub fn new() -> Self {
        Self {
            vpp_socket: "/run/vpp/cli.sock".to_string(),
            bird_socket: "/run/bird/bird.ctl".to_string(),
            auto_rtbh: true,
            auto_flowspec: true,
            max_acl_rules: 10000,
        }
    }
    
    /// Activate mitigation for an attack
    pub async fn activate(&self, attack: &Attack) -> ActiveMitigation {
        let strategy = attack.attack_type.mitigation_strategy();
        self.activate_with_strategy(attack, strategy).await
    }
    
    /// Activate mitigation with specific strategy
    pub async fn activate_with_strategy(
        &self,
        attack: &Attack,
        strategy: MitigationStrategy,
    ) -> ActiveMitigation {
        info!(
            "Activating {} mitigation for {} attack on {}",
            format!("{:?}", strategy),
            format!("{:?}", attack.attack_type),
            attack.target.ip
        );
        
        let rules = match strategy {
            MitigationStrategy::SynCookie => {
                self.activate_syn_cookies(&attack.target.ip).await
            }
            MitigationStrategy::SynProxy => {
                self.activate_syn_proxy(&attack.target.ip).await
            }
            MitigationStrategy::RateLimit => {
                self.activate_rate_limiting(attack).await
            }
            MitigationStrategy::SourceBlock => {
                self.activate_source_blocking(attack).await
            }
            MitigationStrategy::PortBlock => {
                self.activate_port_blocking(attack).await
            }
            MitigationStrategy::BgpFlowspec => {
                self.activate_flowspec(attack).await
            }
            MitigationStrategy::Rtbh => {
                self.activate_rtbh(attack).await
            }
            _ => vec![],
        };
        
        ActiveMitigation {
            id: uuid::Uuid::new_v4().to_string(),
            strategy,
            rules,
            started_at: chrono::Utc::now(),
            stats: MitigationStats::default(),
        }
    }
    
    /// Deactivate mitigation
    pub async fn deactivate(&self, mitigation: &ActiveMitigation) {
        info!("Deactivating mitigation {}", mitigation.id);
        
        for rule in &mitigation.rules {
            match rule.rule_type {
                RuleType::VppAcl => {
                    self.remove_vpp_acl(rule).await;
                }
                RuleType::VppPolicer => {
                    self.remove_vpp_policer(rule).await;
                }
                RuleType::BirdRtbh => {
                    self.remove_rtbh(rule).await;
                }
                RuleType::BgpFlowspec => {
                    self.remove_flowspec(rule).await;
                }
                _ => {}
            }
        }
    }
    
    // =========================================================================
    // SYN Flood Mitigations
    // =========================================================================
    
    async fn activate_syn_cookies(&self, target: &IpAddr) -> Vec<MitigationRule> {
        // VPP command: tcp syn-cookie threshold 100
        let cmd = format!("tcp syn-flood threshold 100 for {}", target);
        self.vpp_exec(&cmd).await;
        
        vec![MitigationRule {
            rule_type: RuleType::SynCookie,
            source: None,
            source_prefix: None,
            destination: Some(*target),
            protocol: Some(Protocol::Tcp),
            port: None,
            action: RuleAction::SynCookie,
            rate_limit: None,
            priority: 100,
            expires_at: None,
        }]
    }
    
    async fn activate_syn_proxy(&self, target: &IpAddr) -> Vec<MitigationRule> {
        // Enable TCP SYN proxy in VPP
        let cmd = format!("tcp session table syn-proxy on for {}", target);
        self.vpp_exec(&cmd).await;
        
        vec![MitigationRule {
            rule_type: RuleType::SynProxy,
            source: None,
            source_prefix: None,
            destination: Some(*target),
            protocol: Some(Protocol::Tcp),
            port: None,
            action: RuleAction::SynCookie,
            rate_limit: None,
            priority: 100,
            expires_at: None,
        }]
    }
    
    // =========================================================================
    // Rate Limiting
    // =========================================================================
    
    async fn activate_rate_limiting(&self, attack: &Attack) -> Vec<MitigationRule> {
        let mut rules = Vec::new();
        
        // Calculate rate limits based on baseline
        let allowed_pps = attack.metrics.total_pps / 10; // 10% of attack rate
        let allowed_bps = attack.metrics.total_bps / 10;
        
        // Global rate limit for destination
        let cmd = format!(
            "policer add name ddos_{} rate {} pps burst {} drop",
            attack.target.ip.to_string().replace(".", "_"),
            allowed_pps,
            allowed_pps * 2
        );
        self.vpp_exec(&cmd).await;
        
        rules.push(MitigationRule {
            rule_type: RuleType::VppPolicer,
            source: None,
            source_prefix: None,
            destination: Some(attack.target.ip),
            protocol: Some(attack.target.protocol),
            port: attack.target.port,
            action: RuleAction::RateLimit,
            rate_limit: Some(RateLimit {
                pps: Some(allowed_pps),
                bps: Some(allowed_bps),
                burst: (allowed_pps * 2) as u32,
            }),
            priority: 200,
            expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        });
        
        // Per-source rate limits for top attackers
        for source in attack.sources.iter().take(100) {
            let per_source_pps = allowed_pps / 100;
            
            let cmd = format!(
                "acl add permit+rate-limit {} to {} pps {}",
                source.ip, attack.target.ip, per_source_pps
            );
            self.vpp_exec(&cmd).await;
            
            rules.push(MitigationRule {
                rule_type: RuleType::VppAcl,
                source: Some(source.ip),
                source_prefix: None,
                destination: Some(attack.target.ip),
                protocol: Some(attack.target.protocol),
                port: attack.target.port,
                action: RuleAction::RateLimit,
                rate_limit: Some(RateLimit {
                    pps: Some(per_source_pps),
                    bps: None,
                    burst: (per_source_pps * 2) as u32,
                }),
                priority: 300,
                expires_at: Some(chrono::Utc::now() + chrono::Duration::minutes(30)),
            });
        }
        
        rules
    }
    
    // =========================================================================
    // Source Blocking
    // =========================================================================
    
    async fn activate_source_blocking(&self, attack: &Attack) -> Vec<MitigationRule> {
        let mut rules = Vec::new();
        
        for source in attack.sources.iter().take(self.max_acl_rules) {
            // Add VPP ACL to drop traffic from source
            let cmd = format!(
                "acl add deny {} to {} proto {}",
                source.ip,
                attack.target.ip,
                protocol_to_num(&attack.target.protocol)
            );
            self.vpp_exec(&cmd).await;
            
            rules.push(MitigationRule {
                rule_type: RuleType::VppAcl,
                source: Some(source.ip),
                source_prefix: None,
                destination: Some(attack.target.ip),
                protocol: Some(attack.target.protocol),
                port: attack.target.port,
                action: RuleAction::Drop,
                rate_limit: None,
                priority: 500,
                expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(2)),
            });
        }
        
        rules
    }
    
    // =========================================================================
    // Port Blocking
    // =========================================================================
    
    async fn activate_port_blocking(&self, attack: &Attack) -> Vec<MitigationRule> {
        let port = match attack.attack_type {
            AttackType::MemcachedAmplification => Some(11211),
            AttackType::SsdpAmplification => Some(1900),
            AttackType::NtpAmplification => Some(123),
            AttackType::ChargenAmplification => Some(19),
            _ => attack.target.port,
        };
        
        if let Some(p) = port {
            let cmd = format!(
                "acl add deny any to {} proto {} port {}",
                attack.target.ip,
                protocol_to_num(&Protocol::Udp),
                p
            );
            self.vpp_exec(&cmd).await;
            
            return vec![MitigationRule {
                rule_type: RuleType::VppAcl,
                source: None,
                source_prefix: None,
                destination: Some(attack.target.ip),
                protocol: Some(Protocol::Udp),
                port: Some(p),
                action: RuleAction::Drop,
                rate_limit: None,
                priority: 400,
                expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(24)),
            }];
        }
        
        vec![]
    }
    
    // =========================================================================
    // BGP Flowspec
    // =========================================================================
    
    async fn activate_flowspec(&self, attack: &Attack) -> Vec<MitigationRule> {
        if !self.auto_flowspec {
            return vec![];
        }
        
        // Generate Flowspec rule
        let flowspec = format!(
            "flow4 {{
                dst {}/32;
                proto = {};
                {}
            }} then {{
                rate-limit {};
            }}",
            attack.target.ip,
            protocol_to_num(&attack.target.protocol),
            if let Some(p) = attack.target.port { format!("dport = {};", p) } else { String::new() },
            attack.metrics.total_bps / 100 // 1% of attack
        );
        
        // Inject via BIRD
        let cmd = format!("birdc configure soft \"{}\"", flowspec);
        self.bird_exec(&cmd).await;
        
        vec![MitigationRule {
            rule_type: RuleType::BgpFlowspec,
            source: None,
            source_prefix: None,
            destination: Some(attack.target.ip),
            protocol: Some(attack.target.protocol),
            port: attack.target.port,
            action: RuleAction::RateLimit,
            rate_limit: Some(RateLimit {
                pps: None,
                bps: Some(attack.metrics.total_bps / 100),
                burst: 0,
            }),
            priority: 50,
            expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        }]
    }
    
    // =========================================================================
    // RTBH (Remote Triggered Black Hole)
    // =========================================================================
    
    async fn activate_rtbh(&self, attack: &Attack) -> Vec<MitigationRule> {
        if !self.auto_rtbh {
            warn!("RTBH disabled, skipping for {}", attack.target.ip);
            return vec![];
        }
        
        // Announce /32 to blackhole community
        let cmd = format!(
            "birdc route add {}/32 blackhole community 65535:666",
            attack.target.ip
        );
        self.bird_exec(&cmd).await;
        
        vec![MitigationRule {
            rule_type: RuleType::BirdRtbh,
            source: None,
            source_prefix: None,
            destination: Some(attack.target.ip),
            protocol: None,
            port: None,
            action: RuleAction::Drop,
            rate_limit: None,
            priority: 10,
            expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        }]
    }
    
    // =========================================================================
    // Cleanup
    // =========================================================================
    
    async fn remove_vpp_acl(&self, rule: &MitigationRule) {
        if let Some(src) = rule.source {
            let cmd = format!("acl del {} to {:?}", src, rule.destination);
            self.vpp_exec(&cmd).await;
        }
    }
    
    async fn remove_vpp_policer(&self, rule: &MitigationRule) {
        if let Some(dst) = rule.destination {
            let cmd = format!("policer del ddos_{}", dst.to_string().replace(".", "_"));
            self.vpp_exec(&cmd).await;
        }
    }
    
    async fn remove_rtbh(&self, rule: &MitigationRule) {
        if let Some(dst) = rule.destination {
            let cmd = format!("birdc route del {}/32 blackhole", dst);
            self.bird_exec(&cmd).await;
        }
    }
    
    async fn remove_flowspec(&self, _rule: &MitigationRule) {
        // Remove Flowspec via BIRD reconfigure
        self.bird_exec("birdc configure").await;
    }
    
    // =========================================================================
    // Command Execution
    // =========================================================================
    
    async fn vpp_exec(&self, cmd: &str) -> String {
        use tokio::process::Command;
        
        let output = Command::new("vppctl")
            .arg("-s")
            .arg(&self.vpp_socket)
            .arg(cmd)
            .output()
            .await;
        
        match output {
            Ok(out) => String::from_utf8_lossy(&out.stdout).to_string(),
            Err(e) => {
                warn!("VPP command failed: {}", e);
                String::new()
            }
        }
    }
    
    async fn bird_exec(&self, cmd: &str) -> String {
        use tokio::process::Command;
        
        let output = Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .output()
            .await;
        
        match output {
            Ok(out) => String::from_utf8_lossy(&out.stdout).to_string(),
            Err(e) => {
                warn!("BIRD command failed: {}", e);
                String::new()
            }
        }
    }
}

impl Default for MitigationEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn protocol_to_num(proto: &Protocol) -> u8 {
    match proto {
        Protocol::Tcp => 6,
        Protocol::Udp => 17,
        Protocol::Icmp => 1,
        Protocol::Gre => 47,
        Protocol::Other(n) => *n,
    }
}
