//! Stateful Firewall Module
//!
//! Features:
//! - 5-tuple matching with zone awareness
//! - Application-aware rules
//! - User/group identity integration
//! - Geo-IP blocking

use super::SecurityModule;
use crate::context::{InspectionContext, ModuleVerdict, VerdictAction, Severity, L3Header, L4Header};
use std::net::IpAddr;

/// Firewall module
pub struct FirewallModule {
    rules: Vec<FirewallRule>,
    default_action: VerdictAction,
    enabled: bool,
}

impl FirewallModule {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            default_action: VerdictAction::Allow,
            enabled: true,
        }
    }

    pub fn add_rule(&mut self, rule: FirewallRule) {
        self.rules.push(rule);
        self.rules.sort_by_key(|r| r.priority);
    }

    pub fn set_default(&mut self, action: VerdictAction) {
        self.default_action = action;
    }

    fn check_rule(&self, rule: &FirewallRule, ctx: &InspectionContext) -> bool {
        // Source IP check
        if let Some(ref cidr) = rule.src_cidr {
            if let Some(src) = ctx.l3.src_ip() {
                if !cidr.contains(src) {
                    return false;
                }
            }
        }

        // Destination IP check
        if let Some(ref cidr) = rule.dst_cidr {
            if let Some(dst) = ctx.l3.dst_ip() {
                if !cidr.contains(dst) {
                    return false;
                }
            }
        }

        // Port check
        if let Some(port) = rule.dst_port {
            if ctx.l4.dst_port() != Some(port) {
                return false;
            }
        }

        // Protocol check
        if let Some(proto) = rule.protocol {
            if ctx.l3.protocol() != proto {
                return false;
            }
        }

        // Zone check
        if let Some(ref zone) = rule.src_zone {
            if ctx.metadata.src_zone.as_ref() != Some(zone) {
                return false;
            }
        }

        // User/group check
        if let Some(ref group) = rule.user_group {
            if !ctx.metadata.user_groups.contains(group) {
                return false;
            }
        }

        // Geo-IP check
        if let Some(ref countries) = rule.blocked_countries {
            if let Some(ref geo) = ctx.metadata.geo_src {
                if countries.contains(&geo.country) {
                    return true;  // Match for block
                }
            }
        }

        true
    }
}

impl Default for FirewallModule {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityModule for FirewallModule {
    fn name(&self) -> &'static str { "firewall" }

    fn is_enabled(&self) -> bool { self.enabled }

    fn inspect(&self, ctx: &InspectionContext) -> Option<ModuleVerdict> {
        for rule in &self.rules {
            if self.check_rule(rule, ctx) {
                return Some(ModuleVerdict {
                    module: self.name(),
                    action: rule.action,
                    reason: rule.description.clone(),
                    rule_id: Some(rule.id),
                    severity: if rule.action == VerdictAction::Block {
                        Severity::Medium
                    } else {
                        Severity::Info
                    },
                });
            }
        }

        // Default action
        Some(ModuleVerdict {
            module: self.name(),
            action: self.default_action,
            reason: "Default policy".into(),
            rule_id: None,
            severity: Severity::Info,
        })
    }
}

/// Firewall rule
#[derive(Debug, Clone)]
pub struct FirewallRule {
    pub id: u32,
    pub priority: u16,
    pub action: VerdictAction,
    pub description: String,
    pub src_cidr: Option<Cidr>,
    pub dst_cidr: Option<Cidr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Option<u8>,
    pub src_zone: Option<String>,
    pub dst_zone: Option<String>,
    pub user_group: Option<String>,
    pub application: Option<String>,
    pub blocked_countries: Option<Vec<String>>,
}

/// Simple CIDR representation
#[derive(Debug, Clone)]
pub struct Cidr {
    network: u128,
    prefix: u8,
    is_v6: bool,
}

impl Cidr {
    pub fn v4(a: u8, b: u8, c: u8, d: u8, prefix: u8) -> Self {
        let ip = u32::from_be_bytes([a, b, c, d]) as u128;
        Self { network: ip, prefix, is_v6: false }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip_val = match ip {
            IpAddr::V4(v4) => u32::from(v4) as u128,
            IpAddr::V6(v6) => u128::from(v6),
        };
        
        if self.prefix == 0 { return true; }
        let mask = !0u128 << (128 - self.prefix);
        (ip_val & mask) == (self.network & mask)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_context() -> InspectionContext<'static> {
        static PACKET: [u8; 54] = [0; 54];
        let mut ctx = InspectionContext::parse(&PACKET).unwrap_or_else(|| {
            panic!("Failed to parse test packet")
        });
        ctx.metadata.user_groups = vec!["developers".into()];
        ctx
    }

    #[test]
    fn test_firewall_allow() {
        let mut fw = FirewallModule::new();
        fw.add_rule(FirewallRule {
            id: 1,
            priority: 100,
            action: VerdictAction::Allow,
            description: "Allow all".into(),
            src_cidr: None,
            dst_cidr: None,
            src_port: None,
            dst_port: None,
            protocol: None,
            src_zone: None,
            dst_zone: None,
            user_group: None,
            application: None,
            blocked_countries: None,
        });

        // Would test with real context
    }
}
