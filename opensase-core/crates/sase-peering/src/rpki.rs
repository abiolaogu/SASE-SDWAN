//! RPKI/ROA Validation
//!
//! Route origin authentication using RPKI validators.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// RPKI validation status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum RpkiStatus {
    Valid,
    Invalid,
    NotFound,
    Unknown,
}

/// ROA (Route Origin Authorization) entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoaEntry {
    pub prefix: String,
    pub max_length: u8,
    pub origin_asn: u32,
    pub trust_anchor: String,
}

/// RPKI validator configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpkiConfig {
    pub rtr_server: String,
    pub rtr_port: u16,
    pub refresh_seconds: u32,
    pub retry_seconds: u32,
    pub expire_seconds: u32,
}

impl Default for RpkiConfig {
    fn default() -> Self {
        Self {
            rtr_server: "rpki.cloudflare.com".to_string(),
            rtr_port: 8282,
            refresh_seconds: 900,
            retry_seconds: 600,
            expire_seconds: 7200,
        }
    }
}

/// RPKI manager
pub struct RpkiManager {
    config: RpkiConfig,
    our_asn: u32,
    our_prefixes: Vec<String>,
}

impl RpkiManager {
    pub fn new(our_asn: u32) -> Self {
        Self {
            config: RpkiConfig::default(),
            our_asn,
            our_prefixes: Vec::new(),
        }
    }

    /// Add our prefix
    pub fn add_prefix(&mut self, prefix: &str) {
        self.our_prefixes.push(prefix.to_string());
    }

    /// Generate BIRD RPKI configuration
    pub fn generate_bird_rpki_config(&self) -> String {
        format!(r#"# RPKI Configuration

# ROA tables
roa4 table roa_v4;
roa6 table roa_v6;

# Primary RPKI validator (Cloudflare)
protocol rpki rpki_cloudflare {{
    roa4 {{ table roa_v4; }};
    roa6 {{ table roa_v6; }};
    remote "{}" port {};
    retry keep {};
    refresh keep {};
    expire keep {};
}}

# Backup RPKI validator (RIPE)
protocol rpki rpki_ripe {{
    roa4 {{ table roa_v4; }};
    roa6 {{ table roa_v6; }};
    remote "rpki-validator.ripe.net" port 8323;
    retry keep {};
    refresh keep {};
    expire keep {};
}}

# Local Routinator (optional)
# protocol rpki rpki_local {{
#     roa4 {{ table roa_v4; }};
#     roa6 {{ table roa_v6; }};
#     remote "127.0.0.1" port 3323;
# }}
"#,
            self.config.rtr_server, self.config.rtr_port,
            self.config.retry_seconds, self.config.refresh_seconds, self.config.expire_seconds,
            self.config.retry_seconds, self.config.refresh_seconds, self.config.expire_seconds
        )
    }

    /// Generate RPKI validation filter
    pub fn generate_rpki_filter(&self) -> String {
        r#"# RPKI Validation Functions

function rpki_valid() {
    return roa_check(roa_v4, net, bgp_path.last) = ROA_VALID;
}

function rpki_invalid() {
    return roa_check(roa_v4, net, bgp_path.last) = ROA_INVALID;
}

function rpki_unknown() {
    return roa_check(roa_v4, net, bgp_path.last) = ROA_UNKNOWN;
}

# Use in import filter:
# filter import_rpki {
#     if rpki_invalid() then {
#         print "RPKI INVALID: ", net, " origin AS", bgp_path.last;
#         reject;
#     }
#     if rpki_valid() then {
#         bgp_local_pref = bgp_local_pref + 10;
#     }
#     accept;
# }
"#.to_string()
    }

    /// Generate ROA creation guide
    pub fn generate_roa_guide(&self) -> String {
        let prefixes = self.our_prefixes.iter()
            .map(|p| format!("   - Prefix: {}\n     Max Length: 24\n     Origin ASN: {}", p, self.our_asn))
            .collect::<Vec<_>>()
            .join("\n");

        format!(r#"=== ROA (Route Origin Authorization) Creation Guide ===

Your ASN: AS{}
Your Prefixes:
{}

=== Step 1: Access RIR Portal ===

RIPE NCC (Europe):
  https://my.ripe.net → RPKI → ROAs

ARIN (North America):
  https://account.arin.net → IRR → RPKI/ROAs

APNIC (Asia Pacific):
  https://myapnic.net → Resources → RPKI

=== Step 2: Create ROA ===

For each prefix:
1. Click "Create ROA" or "Add ROA"
2. Enter prefix: e.g., 203.0.113.0/24
3. Enter max length: Usually same as prefix length (24 for /24)
4. Enter origin ASN: {}
5. Submit and sign

=== Step 3: Verify ROA ===

Wait 15-30 minutes, then verify at:
- https://rpki-validator.ripe.net/
- https://stat.ripe.net/widget/rpki-validation
- https://bgp.he.net/AS{} (check RPKI status)

=== Step 4: Configure BIRD for RPKI ===

Add to bird.conf:
```
{}
```

=== ROA Best Practices ===

1. Create ROAs for ALL your prefixes
2. Set max_length carefully:
   - /24 announcements: max_length = 24
   - Allow deaggregation: max_length = 28
3. Don't create overlapping ROAs with different origins
4. Update ROAs before any prefix transfers
5. Monitor for ROA expiration

=== Troubleshooting ===

ROA not propagating:
- Wait 30-60 minutes
- Check RIR portal for errors
- Verify prefix is allocated to your ASN

RPKI Invalid routes:
- Check if ROA exists
- Verify origin ASN matches
- Check max_length setting
"#,
            self.our_asn,
            if self.our_prefixes.is_empty() {
                "   (No prefixes configured)".to_string()
            } else {
                prefixes
            },
            self.our_asn,
            self.our_asn,
            self.generate_bird_rpki_config().lines()
                .take(15)
                .collect::<Vec<_>>()
                .join("\n")
        )
    }

    /// Get public RPKI validators
    pub fn get_public_validators() -> Vec<(&'static str, &'static str, u16)> {
        vec![
            ("Cloudflare", "rpki.cloudflare.com", 8282),
            ("RIPE NCC", "rpki-validator.ripe.net", 8323),
            ("NTT", "rtr.rpki.cloudflare.com", 8282),
            ("LACNIC", "rpki.lacnic.net", 8323),
        ]
    }

    /// Generate Routinator config (local validator)
    pub fn generate_routinator_config(&self) -> String {
        r#"# Routinator Configuration
# /etc/routinator/routinator.conf

[server]
rtr-listen = ["127.0.0.1:3323", "[::1]:3323"]
http-listen = ["127.0.0.1:8080"]

[repository]
cache-dir = "/var/cache/routinator"

[tal]
tal-dir = "/etc/routinator/tals"

[log]
log-level = "info"
log-target = "syslog"

[timing]
refresh = 3600
retry = 600
expire = 7200
"#.to_string()
    }

    /// Generate systemd service for Routinator
    pub fn generate_routinator_service(&self) -> String {
        r#"[Unit]
Description=Routinator RPKI Validator
After=network.target

[Service]
Type=simple
User=routinator
ExecStart=/usr/bin/routinator server
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"#.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpki_config() {
        let config = RpkiConfig::default();
        assert_eq!(config.rtr_port, 8282);
    }

    #[test]
    fn test_bird_rpki_generation() {
        let manager = RpkiManager::new(65100);
        let config = manager.generate_bird_rpki_config();
        assert!(config.contains("rpki_cloudflare"));
        assert!(config.contains("roa_v4"));
    }

    #[test]
    fn test_roa_guide() {
        let mut manager = RpkiManager::new(65100);
        manager.add_prefix("203.0.113.0/24");
        let guide = manager.generate_roa_guide();
        assert!(guide.contains("203.0.113.0/24"));
        assert!(guide.contains("AS65100"));
    }
}
