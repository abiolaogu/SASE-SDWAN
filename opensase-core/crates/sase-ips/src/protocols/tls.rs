//! TLS Protocol Analyzer
//!
//! Analyzes TLS handshakes for security threats including
//! JA3/JA3S fingerprinting and cipher suite policy enforcement.

use sha2::{Sha256, Digest};
use md5::Md5;

/// TLS analysis verdict
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlsVerdict {
    Allow,
    Block(&'static str),
    Alert(&'static str),
    NeedMore,
}

/// TLS client hello info
#[derive(Clone, Debug, Default)]
pub struct ClientHello {
    /// TLS version
    pub version: u16,
    
    /// Server Name Indication
    pub sni: Option<String>,
    
    /// Cipher suites
    pub cipher_suites: Vec<u16>,
    
    /// Extensions
    pub extensions: Vec<u16>,
    
    /// Elliptic curves (supported groups)
    pub elliptic_curves: Vec<u16>,
    
    /// EC point formats
    pub ec_point_formats: Vec<u8>,
    
    /// JA3 fingerprint
    pub ja3: Option<String>,
    
    /// JA3 hash (MD5)
    pub ja3_hash: Option<String>,
}

/// TLS analyzer configuration
#[derive(Clone, Debug)]
pub struct TlsConfig {
    /// Minimum TLS version allowed
    pub min_version: u16,
    
    /// Blocked cipher suites (weak)
    pub blocked_ciphers: Vec<u16>,
    
    /// Blocked JA3 fingerprints (known malware)
    pub blocked_ja3: Vec<String>,
    
    /// Blocked SNIs (domains)
    pub blocked_snis: Vec<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            min_version: 0x0303, // TLS 1.2
            blocked_ciphers: vec![
                // NULL ciphers
                0x0000, 0x0001, 0x0002, 0x002C, 0x002D, 0x002E,
                // Export ciphers
                0x0003, 0x0006, 0x0008, 0x0009, 0x000A, 0x000B, 0x000E,
                // DES/3DES ciphers
                0x0007, 0x000C, 0x0012, 0x0013, 0x001B,
                // RC4 ciphers
                0x0005, 0x0004, 0x0017, 0x0018, 0x0024,
            ],
            blocked_ja3: vec![
                // Known malware JA3s
                "e7d705a3286e19ea42f587b344ee6865".into(), // Emotet
                "51c64c77e60f3980eea90869b68c58a8".into(), // TrickBot
            ],
            blocked_snis: Vec::new(),
        }
    }
}

/// TLS protocol analyzer
pub struct TlsAnalyzer {
    config: TlsConfig,
}

impl TlsAnalyzer {
    /// Create new analyzer
    pub fn new(config: TlsConfig) -> Self {
        Self { config }
    }
    
    /// Analyze TLS client hello
    pub fn analyze_client_hello(&self, data: &[u8]) -> TlsVerdict {
        let hello = match self.parse_client_hello(data) {
            Some(h) => h,
            None => return TlsVerdict::NeedMore,
        };
        
        // Check TLS version
        if hello.version < self.config.min_version {
            return TlsVerdict::Block("TLS version too low");
        }
        
        // Check cipher suites
        for cipher in &hello.cipher_suites {
            if self.config.blocked_ciphers.contains(cipher) {
                return TlsVerdict::Block("Weak cipher suite");
            }
        }
        
        // Check JA3 fingerprint
        if let Some(ref ja3_hash) = hello.ja3_hash {
            if self.config.blocked_ja3.contains(ja3_hash) {
                return TlsVerdict::Block("Known malware JA3");
            }
        }
        
        // Check SNI
        if let Some(ref sni) = hello.sni {
            for blocked in &self.config.blocked_snis {
                if sni.ends_with(blocked) || sni == blocked {
                    return TlsVerdict::Block("Blocked domain");
                }
            }
        }
        
        TlsVerdict::Allow
    }
    
    /// Parse TLS client hello
    fn parse_client_hello(&self, data: &[u8]) -> Option<ClientHello> {
        if data.len() < 43 {
            return None;
        }
        
        // Check TLS record header
        if data[0] != 0x16 {
            return None; // Not handshake
        }
        
        let record_version = ((data[1] as u16) << 8) | (data[2] as u16);
        let record_length = ((data[3] as u16) << 8) | (data[4] as u16);
        
        if data.len() < (5 + record_length as usize) {
            return None;
        }
        
        let handshake = &data[5..];
        
        // Check handshake type
        if handshake[0] != 0x01 {
            return None; // Not client hello
        }
        
        // Skip handshake header (4 bytes)
        let client_hello = &handshake[4..];
        if client_hello.len() < 38 {
            return None;
        }
        
        let client_version = ((client_hello[0] as u16) << 8) | (client_hello[1] as u16);
        
        // Skip random (32 bytes)
        let mut pos = 34;
        
        // Session ID length
        if pos >= client_hello.len() {
            return None;
        }
        let session_id_len = client_hello[pos] as usize;
        pos += 1 + session_id_len;
        
        // Cipher suites
        if pos + 2 > client_hello.len() {
            return None;
        }
        let cipher_len = ((client_hello[pos] as usize) << 8) | (client_hello[pos + 1] as usize);
        pos += 2;
        
        if pos + cipher_len > client_hello.len() {
            return None;
        }
        
        let mut cipher_suites = Vec::new();
        for i in (0..cipher_len).step_by(2) {
            let cipher = ((client_hello[pos + i] as u16) << 8) | 
                         (client_hello[pos + i + 1] as u16);
            cipher_suites.push(cipher);
        }
        pos += cipher_len;
        
        // Compression methods
        if pos >= client_hello.len() {
            return None;
        }
        let comp_len = client_hello[pos] as usize;
        pos += 1 + comp_len;
        
        // Extensions
        let mut extensions = Vec::new();
        let mut elliptic_curves = Vec::new();
        let mut ec_point_formats = Vec::new();
        let mut sni = None;
        
        if pos + 2 <= client_hello.len() {
            let ext_len = ((client_hello[pos] as usize) << 8) | 
                          (client_hello[pos + 1] as usize);
            pos += 2;
            
            let ext_end = (pos + ext_len).min(client_hello.len());
            
            while pos + 4 <= ext_end {
                let ext_type = ((client_hello[pos] as u16) << 8) | 
                               (client_hello[pos + 1] as u16);
                let ext_data_len = ((client_hello[pos + 2] as usize) << 8) | 
                                   (client_hello[pos + 3] as usize);
                pos += 4;
                
                extensions.push(ext_type);
                
                if pos + ext_data_len <= ext_end {
                    let ext_data = &client_hello[pos..pos + ext_data_len];
                    
                    match ext_type {
                        0x0000 => {
                            // SNI
                            if ext_data.len() > 5 {
                                let name_len = ((ext_data[3] as usize) << 8) | 
                                              (ext_data[4] as usize);
                                if ext_data.len() >= 5 + name_len {
                                    sni = String::from_utf8(
                                        ext_data[5..5+name_len].to_vec()
                                    ).ok();
                                }
                            }
                        }
                        0x000A => {
                            // Supported groups (elliptic curves)
                            if ext_data.len() >= 2 {
                                let groups_len = ((ext_data[0] as usize) << 8) | 
                                                 (ext_data[1] as usize);
                                for i in (2..2+groups_len).step_by(2) {
                                    if i + 1 < ext_data.len() {
                                        let group = ((ext_data[i] as u16) << 8) | 
                                                    (ext_data[i + 1] as u16);
                                        elliptic_curves.push(group);
                                    }
                                }
                            }
                        }
                        0x000B => {
                            // EC point formats
                            if !ext_data.is_empty() {
                                let formats_len = ext_data[0] as usize;
                                for i in 1..=formats_len.min(ext_data.len() - 1) {
                                    ec_point_formats.push(ext_data[i]);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                
                pos += ext_data_len;
            }
        }
        
        // Calculate JA3
        let ja3 = self.calculate_ja3(
            client_version, 
            &cipher_suites, 
            &extensions, 
            &elliptic_curves, 
            &ec_point_formats
        );
        
        let ja3_hash = ja3.as_ref().map(|j| {
            let mut hasher = Md5::new();
            hasher.update(j.as_bytes());
            hex::encode(hasher.finalize())
        });
        
        Some(ClientHello {
            version: client_version,
            sni,
            cipher_suites,
            extensions,
            elliptic_curves,
            ec_point_formats,
            ja3,
            ja3_hash,
        })
    }
    
    /// Calculate JA3 fingerprint
    fn calculate_ja3(
        &self,
        version: u16,
        ciphers: &[u16],
        extensions: &[u16],
        curves: &[u16],
        ec_formats: &[u8],
    ) -> Option<String> {
        // Filter GREASE values
        let filter_grease_u16 = |v: &[u16]| -> Vec<u16> {
            v.iter()
                .copied()
                .filter(|&x| !Self::is_grease(x))
                .collect()
        };
        
        let ciphers = filter_grease_u16(ciphers);
        let extensions = filter_grease_u16(extensions);
        let curves = filter_grease_u16(curves);
        
        // JA3 format: Version,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
        let cipher_str = ciphers.iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-");
        let ext_str = extensions.iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("-");
        let curve_str = curves.iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-");
        let ec_format_str = ec_formats.iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join("-");
        
        Some(format!("{},{},{},{},{}", 
            version, cipher_str, ext_str, curve_str, ec_format_str))
    }
    
    /// Check if value is GREASE
    fn is_grease(value: u16) -> bool {
        // GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, etc.
        (value & 0x0f0f) == 0x0a0a
    }
    
    /// Get JA3 hash for data
    pub fn get_ja3_hash(&self, data: &[u8]) -> Option<String> {
        self.parse_client_hello(data)
            .and_then(|h| h.ja3_hash)
    }
}

impl Default for TlsAnalyzer {
    fn default() -> Self {
        Self::new(TlsConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_grease() {
        assert!(TlsAnalyzer::is_grease(0x0a0a));
        assert!(TlsAnalyzer::is_grease(0x1a1a));
        assert!(TlsAnalyzer::is_grease(0x2a2a));
        
        assert!(!TlsAnalyzer::is_grease(0x0035));
        assert!(!TlsAnalyzer::is_grease(0xc02f));
    }
}
