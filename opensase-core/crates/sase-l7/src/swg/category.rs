//! Category Database - URL categorization

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

/// URL category
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Category {
    // Blocked by default
    Malware,
    Phishing,
    Gambling,
    Adult,
    Weapons,
    Hacking,
    
    // Warn/Isolate
    SocialMedia,
    Streaming,
    Gaming,
    FileSharing,
    Proxy,
    
    // Business
    Business,
    Technology,
    News,
    Finance,
    Government,
    Education,
    Healthcare,
    Shopping,
    Travel,
    
    // Unknown
    Unknown,
}

impl Category {
    /// Get category as string
    pub fn as_str(&self) -> &'static str {
        match self {
            Category::Malware => "malware",
            Category::Phishing => "phishing",
            Category::Gambling => "gambling",
            Category::Adult => "adult",
            Category::Weapons => "weapons",
            Category::Hacking => "hacking",
            Category::SocialMedia => "social-media",
            Category::Streaming => "streaming",
            Category::Gaming => "gaming",
            Category::FileSharing => "file-sharing",
            Category::Proxy => "proxy",
            Category::Business => "business",
            Category::Technology => "technology",
            Category::News => "news",
            Category::Finance => "finance",
            Category::Government => "government",
            Category::Education => "education",
            Category::Healthcare => "healthcare",
            Category::Shopping => "shopping",
            Category::Travel => "travel",
            Category::Unknown => "unknown",
        }
    }
    
    /// Parse category from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "malware" => Some(Category::Malware),
            "phishing" => Some(Category::Phishing),
            "gambling" => Some(Category::Gambling),
            "adult" => Some(Category::Adult),
            "weapons" => Some(Category::Weapons),
            "hacking" => Some(Category::Hacking),
            "social-media" | "social_media" => Some(Category::SocialMedia),
            "streaming" => Some(Category::Streaming),
            "gaming" => Some(Category::Gaming),
            "file-sharing" | "file_sharing" => Some(Category::FileSharing),
            "proxy" => Some(Category::Proxy),
            "business" => Some(Category::Business),
            "technology" => Some(Category::Technology),
            "news" => Some(Category::News),
            "finance" => Some(Category::Finance),
            "government" => Some(Category::Government),
            "education" => Some(Category::Education),
            "healthcare" => Some(Category::Healthcare),
            "shopping" => Some(Category::Shopping),
            "travel" => Some(Category::Travel),
            _ => None,
        }
    }
}

/// Category database
pub struct CategoryDatabase {
    /// Domain to category mapping
    categories: DashMap<String, Category>,
    
    /// Category patterns (suffix matching)
    patterns: DashMap<String, Category>,
}

impl CategoryDatabase {
    /// Create new category database
    pub fn new() -> Self {
        Self {
            categories: DashMap::new(),
            patterns: DashMap::new(),
        }
    }
    
    /// Lookup domain category
    pub async fn lookup(&self, domain: &str) -> Option<Category> {
        let domain_lower = domain.to_lowercase();
        
        // Direct lookup
        if let Some(cat) = self.categories.get(&domain_lower) {
            return Some(*cat);
        }
        
        // Pattern matching (suffix)
        for entry in self.patterns.iter() {
            if domain_lower.ends_with(entry.key()) {
                return Some(*entry.value());
            }
        }
        
        // Heuristic categorization
        self.categorize_heuristic(&domain_lower)
    }
    
    /// Add domain category
    pub fn add(&self, domain: &str, category: Category) {
        self.categories.insert(domain.to_lowercase(), category);
    }
    
    /// Add pattern (suffix match)
    pub fn add_pattern(&self, pattern: &str, category: Category) {
        self.patterns.insert(pattern.to_lowercase(), category);
    }
    
    /// Heuristic categorization
    fn categorize_heuristic(&self, domain: &str) -> Option<Category> {
        // Social media
        if domain.contains("facebook") || domain.contains("twitter") ||
           domain.contains("instagram") || domain.contains("tiktok") ||
           domain.contains("linkedin") || domain.contains("pinterest") {
            return Some(Category::SocialMedia);
        }
        
        // Streaming
        if domain.contains("netflix") || domain.contains("youtube") ||
           domain.contains("twitch") || domain.contains("hulu") ||
           domain.contains("spotify") || domain.contains("disney") {
            return Some(Category::Streaming);
        }
        
        // Technology
        if domain.ends_with(".dev") || domain.ends_with(".io") ||
           domain.contains("github") || domain.contains("gitlab") ||
           domain.contains("stackoverflow") || domain.contains("docker") {
            return Some(Category::Technology);
        }
        
        // Finance
        if domain.contains("bank") || domain.contains("paypal") ||
           domain.contains("stripe") || domain.contains("crypto") ||
           domain.contains("trading") {
            return Some(Category::Finance);
        }
        
        // Government
        if domain.ends_with(".gov") || domain.ends_with(".mil") {
            return Some(Category::Government);
        }
        
        // Education
        if domain.ends_with(".edu") || domain.contains("university") ||
           domain.contains("college") || domain.contains("school") {
            return Some(Category::Education);
        }
        
        // Shopping
        if domain.contains("amazon") || domain.contains("ebay") ||
           domain.contains("shop") || domain.contains("store") ||
           domain.contains("buy") {
            return Some(Category::Shopping);
        }
        
        // News
        if domain.contains("news") || domain.contains("cnn") ||
           domain.contains("bbc") || domain.contains("reuters") ||
           domain.contains("nytimes") {
            return Some(Category::News);
        }
        
        None
    }
    
    /// Load default categories
    pub fn load_defaults(&self) {
        // Social media
        for domain in ["facebook.com", "twitter.com", "instagram.com", "tiktok.com", 
                       "linkedin.com", "pinterest.com", "reddit.com", "snapchat.com"] {
            self.add(domain, Category::SocialMedia);
        }
        
        // Streaming
        for domain in ["netflix.com", "youtube.com", "twitch.tv", "hulu.com",
                       "disneyplus.com", "spotify.com", "soundcloud.com"] {
            self.add(domain, Category::Streaming);
        }
        
        // Technology
        for domain in ["github.com", "gitlab.com", "stackoverflow.com", "docker.com",
                       "aws.amazon.com", "cloud.google.com", "azure.microsoft.com"] {
            self.add(domain, Category::Technology);
        }
        
        // File sharing
        for domain in ["dropbox.com", "box.com", "wetransfer.com", "mega.nz"] {
            self.add(domain, Category::FileSharing);
        }
        
        // Proxy
        for domain in ["hidemyass.com", "protonvpn.com", "nordvpn.com"] {
            self.add(domain, Category::Proxy);
        }
        
        // Finance
        for domain in ["paypal.com", "stripe.com", "square.com", "venmo.com"] {
            self.add(domain, Category::Finance);
        }
        
        // Business
        for domain in ["salesforce.com", "hubspot.com", "zendesk.com", "slack.com",
                       "zoom.us", "teams.microsoft.com", "meet.google.com"] {
            self.add(domain, Category::Business);
        }
    }
}

impl Default for CategoryDatabase {
    fn default() -> Self {
        Self::new()
    }
}
