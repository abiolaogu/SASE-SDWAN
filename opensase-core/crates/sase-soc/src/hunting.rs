//! Threat Hunting
//!
//! Proactive threat detection.

use crate::{Indicator, IndicatorType, ThreatIntelMatch};

pub struct ThreatHunter {
    feeds: dashmap::DashMap<String, ThreatFeed>,
    indicator_cache: dashmap::DashMap<String, CachedIndicator>,
    queries: dashmap::DashMap<String, HuntingQuery>,
}

#[derive(Clone)]
pub struct ThreatFeed {
    pub id: String,
    pub name: String,
    pub feed_type: FeedType,
    pub enabled: bool,
    pub last_update: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FeedType { OpenSource, Commercial, Internal }

#[derive(Clone)]
pub struct CachedIndicator {
    pub value: String,
    pub indicator_type: IndicatorType,
    pub feeds: Vec<String>,
    pub confidence: f64,
}

#[derive(Clone)]
pub struct HuntingQuery {
    pub id: String,
    pub name: String,
    pub query: String,
    pub mitre_attack: Vec<String>,
    pub enabled: bool,
}

impl ThreatHunter {
    pub fn new() -> Self {
        Self {
            feeds: dashmap::DashMap::new(),
            indicator_cache: dashmap::DashMap::new(),
            queries: dashmap::DashMap::new(),
        }
    }
    
    pub async fn check_indicator(&self, indicator: &Indicator) -> Option<ThreatIntelMatch> {
        if let Some(cached) = self.indicator_cache.get(&indicator.value) {
            return Some(ThreatIntelMatch {
                feed: cached.feeds.first().cloned().unwrap_or_default(),
                indicator: indicator.value.clone(),
                threat_type: "malicious".to_string(),
                confidence: cached.confidence,
            });
        }
        None
    }
    
    pub fn add_indicator(&self, indicator: CachedIndicator) {
        self.indicator_cache.insert(indicator.value.clone(), indicator);
    }
    
    pub fn register_query(&self, query: HuntingQuery) {
        self.queries.insert(query.id.clone(), query);
    }
}

impl Default for ThreatHunter {
    fn default() -> Self { Self::new() }
}
