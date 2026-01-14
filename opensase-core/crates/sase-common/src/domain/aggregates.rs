//! Aggregates - Consistency boundaries for domain entities
//!
//! Aggregates are:
//! - Consistency boundaries
//! - Loaded and saved as a unit
//! - Referenced by ID only from outside
//! - Enforce invariants

use super::value_objects::*;
use std::time::Instant;

/// Policy Aggregate Root
/// 
/// # Bounded Context: Policy Management
/// 
/// # Invariants
/// - Must have at least one rule
/// - Rules are ordered by priority
/// - Deny rules take precedence
#[derive(Debug, Clone)]
pub struct PolicyAggregate {
    id: PolicyId,
    version: u64,
    rules: Vec<PolicyRule>,
    default_action: Action,
    created_at: Instant,
    updated_at: Instant,
}

impl PolicyAggregate {
    /// Create new policy aggregate
    pub fn new(id: PolicyId, default_action: Action) -> Self {
        let now = Instant::now();
        Self {
            id,
            version: 1,
            rules: Vec::new(),
            default_action,
            created_at: now,
            updated_at: now,
        }
    }

    /// Get ID
    pub fn id(&self) -> &PolicyId {
        &self.id
    }

    /// Get version
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Add rule (maintains invariants)
    pub fn add_rule(&mut self, rule: PolicyRule) -> Result<(), DomainError> {
        // Invariant: no duplicate priorities
        if self.rules.iter().any(|r| r.priority == rule.priority) {
            return Err(DomainError::InvariantViolation(
                "duplicate priority".into()
            ));
        }

        self.rules.push(rule);
        self.rules.sort_by_key(|r| r.priority);
        self.version += 1;
        self.updated_at = Instant::now();
        Ok(())
    }

    /// Evaluate policy for a flow
    pub fn evaluate(&self, flow: &FlowContext) -> PolicyDecision {
        for rule in &self.rules {
            if rule.matches(flow) {
                return PolicyDecision {
                    action: rule.action,
                    rule_id: Some(rule.id),
                    reason: format!("Matched rule {}", rule.id),
                };
            }
        }

        PolicyDecision {
            action: self.default_action,
            rule_id: None,
            reason: "Default action".into(),
        }
    }

    /// Get rules count
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

/// Policy Rule (Entity within Policy Aggregate)
#[derive(Debug, Clone)]
pub struct PolicyRule {
    pub id: u32,
    pub priority: u16,
    pub action: Action,
    pub conditions: Vec<Condition>,
}

impl PolicyRule {
    /// Check if rule matches flow
    pub fn matches(&self, flow: &FlowContext) -> bool {
        self.conditions.iter().all(|c| c.matches(flow))
    }
}

/// Rule condition
#[derive(Debug, Clone)]
pub enum Condition {
    SourceCidr { network: u128, prefix: u8 },
    DestCidr { network: u128, prefix: u8 },
    DestPort { port: u16 },
    Protocol { proto: u8 },
    UserGroup { group: String },
}

impl Condition {
    fn matches(&self, flow: &FlowContext) -> bool {
        match self {
            Self::SourceCidr { network, prefix } => {
                cidr_match(flow.src_ip, *network, *prefix)
            }
            Self::DestCidr { network, prefix } => {
                cidr_match(flow.dst_ip, *network, *prefix)
            }
            Self::DestPort { port } => flow.dst_port == *port,
            Self::Protocol { proto } => flow.protocol == *proto,
            Self::UserGroup { group } => {
                flow.user_groups.iter().any(|g| g == group)
            }
        }
    }
}

fn cidr_match(ip: u128, network: u128, prefix: u8) -> bool {
    if prefix == 0 { return true; }
    if prefix >= 128 { return ip == network; }
    let mask = !0u128 << (128 - prefix);
    (ip & mask) == (network & mask)
}

/// Flow context for policy evaluation
#[derive(Debug, Clone)]
pub struct FlowContext {
    pub src_ip: u128,
    pub dst_ip: u128,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub user_groups: Vec<String>,
}

/// Policy action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Deny,
    Inspect,
    Log,
}

impl Default for Action {
    fn default() -> Self {
        Self::Allow
    }
}

/// Policy decision result
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub action: Action,
    pub rule_id: Option<u32>,
    pub reason: String,
}

// === Session Aggregate ===

/// Session Aggregate Root
/// 
/// # Bounded Context: Identity & Access
/// 
/// # Invariants
/// - Session must have valid user
/// - Risk score always in 0.0-1.0 range
/// - State transitions are valid
#[derive(Debug, Clone)]
pub struct SessionAggregate {
    id: String,
    user_id: UserId,
    state: SessionState,
    risk_score: Score,
    mfa_verified: bool,
    created_at: Instant,
    last_activity: Instant,
}

impl SessionAggregate {
    /// Create new session
    pub fn new(id: String, user_id: UserId) -> Self {
        let now = Instant::now();
        Self {
            id,
            user_id,
            state: SessionState::Active,
            risk_score: Score::zero(),
            mfa_verified: false,
            created_at: now,
            last_activity: now,
        }
    }

    /// Get session ID
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get user ID
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Get current risk score
    pub fn risk_score(&self) -> Score {
        self.risk_score
    }

    /// Update risk score (enforces invariant)
    pub fn update_risk(&mut self, score: Score) {
        self.risk_score = score;
        self.last_activity = Instant::now();

        // Auto-transition based on risk
        if score.value() > 0.9 {
            self.state = SessionState::Blocked;
        } else if score.value() > 0.7 && !self.mfa_verified {
            self.state = SessionState::RequiresMfa;
        }
    }

    /// Mark MFA as verified
    pub fn verify_mfa(&mut self) {
        self.mfa_verified = true;
        if self.state == SessionState::RequiresMfa {
            self.state = SessionState::Active;
        }
        self.last_activity = Instant::now();
    }

    /// Terminate session
    pub fn terminate(&mut self) {
        self.state = SessionState::Terminated;
    }

    /// Check if session is active
    pub fn is_active(&self) -> bool {
        matches!(self.state, SessionState::Active)
    }

    /// Check if blocked
    pub fn is_blocked(&self) -> bool {
        matches!(self.state, SessionState::Blocked)
    }
}

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Active,
    RequiresMfa,
    Blocked,
    Terminated,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_aggregate_creation() {
        let id = PolicyId::new("test-policy").unwrap();
        let policy = PolicyAggregate::new(id, Action::Deny);
        
        assert_eq!(policy.version(), 1);
        assert_eq!(policy.rule_count(), 0);
    }

    #[test]
    fn test_policy_add_rule() {
        let id = PolicyId::new("test-policy").unwrap();
        let mut policy = PolicyAggregate::new(id, Action::Deny);

        let rule = PolicyRule {
            id: 1,
            priority: 100,
            action: Action::Allow,
            conditions: vec![Condition::DestPort { port: 443 }],
        };

        policy.add_rule(rule).unwrap();
        assert_eq!(policy.rule_count(), 1);
        assert_eq!(policy.version(), 2);
    }

    #[test]
    fn test_policy_duplicate_priority_fails() {
        let id = PolicyId::new("test-policy").unwrap();
        let mut policy = PolicyAggregate::new(id, Action::Deny);

        let rule1 = PolicyRule {
            id: 1,
            priority: 100,
            action: Action::Allow,
            conditions: vec![],
        };
        let rule2 = PolicyRule {
            id: 2,
            priority: 100,  // Same priority
            action: Action::Deny,
            conditions: vec![],
        };

        policy.add_rule(rule1).unwrap();
        assert!(policy.add_rule(rule2).is_err());
    }

    #[test]
    fn test_policy_evaluation() {
        let id = PolicyId::new("test-policy").unwrap();
        let mut policy = PolicyAggregate::new(id, Action::Deny);

        policy.add_rule(PolicyRule {
            id: 1,
            priority: 100,
            action: Action::Allow,
            conditions: vec![Condition::DestPort { port: 443 }],
        }).unwrap();

        // Match
        let flow = FlowContext {
            src_ip: 0,
            dst_ip: 0,
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            user_groups: vec![],
        };
        assert_eq!(policy.evaluate(&flow).action, Action::Allow);

        // No match -> default
        let flow2 = FlowContext {
            dst_port: 80,
            ..flow
        };
        assert_eq!(policy.evaluate(&flow2).action, Action::Deny);
    }

    #[test]
    fn test_session_risk_transitions() {
        let user = UserId::new("user1").unwrap();
        let mut session = SessionAggregate::new("sess1".into(), user);

        assert!(session.is_active());

        // High risk -> requires MFA
        session.update_risk(Score::new(0.75).unwrap());
        assert_eq!(session.state, SessionState::RequiresMfa);

        // MFA verified -> back to active
        session.verify_mfa();
        assert!(session.is_active());

        // Very high risk -> blocked
        session.update_risk(Score::new(0.95).unwrap());
        assert!(session.is_blocked());
    }
}
