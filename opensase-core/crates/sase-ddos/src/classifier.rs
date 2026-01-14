//! Attack Classifier
//!
//! Automatic attack classification using traffic signatures.

use crate::{Attack, AttackMetrics, AttackType, Protocol};

/// Classify an attack based on traffic patterns
pub fn classify(attack: &Attack) -> Attack {
    let mut classified = attack.clone();
    
    // Use heuristics to refine attack type
    classified.attack_type = classify_by_metrics(&attack.metrics, &attack.target.protocol);
    
    classified
}

/// Classify based on traffic metrics
fn classify_by_metrics(metrics: &AttackMetrics, protocol: &Protocol) -> AttackType {
    let avg_packet_size = metrics.avg_packet_size;
    let pps = metrics.total_pps;
    let bps = metrics.total_bps;
    
    // Very small packets = SYN/ACK flood (40-60 bytes)
    if avg_packet_size < 100 && *protocol == Protocol::Tcp {
        return AttackType::SynFlood;
    }
    
    // Large UDP packets = amplification
    if *protocol == Protocol::Udp && avg_packet_size > 1000 {
        // Check ratio - amplification has higher bps:pps
        if bps / pps.max(1) > 8000 {
            return AttackType::DnsAmplification;
        }
    }
    
    // High PPS with small packets = volumetric
    if pps > 10_000_000 && avg_packet_size < 200 {
        return match protocol {
            Protocol::Tcp => AttackType::SynFlood,
            Protocol::Udp => AttackType::UdpFlood,
            Protocol::Icmp => AttackType::IcmpFlood,
            _ => AttackType::Unknown,
        };
    }
    
    // Low unique sources = spoofed
    if metrics.unique_sources < 100 && pps > 1_000_000 {
        return AttackType::SynFlood; // Likely spoofed SYN
    }
    
    AttackType::Unknown
}

/// Attack signature for fingerprinting
#[derive(Debug, Clone)]
pub struct AttackSignature {
    pub protocol: Protocol,
    pub avg_packet_size_range: (u32, u32),
    pub tcp_flags: Option<u8>,
    pub src_port_range: Option<(u16, u16)>,
    pub dst_port: Option<u16>,
    pub pps_threshold: u64,
}

/// Known attack signatures
pub fn known_signatures() -> Vec<(AttackType, AttackSignature)> {
    vec![
        // SYN Flood: Small TCP SYN packets
        (AttackType::SynFlood, AttackSignature {
            protocol: Protocol::Tcp,
            avg_packet_size_range: (40, 80),
            tcp_flags: Some(0x02), // SYN
            src_port_range: None,
            dst_port: None,
            pps_threshold: 100_000,
        }),
        
        // DNS Amplification: Large UDP from port 53
        (AttackType::DnsAmplification, AttackSignature {
            protocol: Protocol::Udp,
            avg_packet_size_range: (500, 4096),
            tcp_flags: None,
            src_port_range: Some((53, 53)),
            dst_port: None,
            pps_threshold: 10_000,
        }),
        
        // NTP Amplification: Large UDP from port 123
        (AttackType::NtpAmplification, AttackSignature {
            protocol: Protocol::Udp,
            avg_packet_size_range: (400, 500),
            tcp_flags: None,
            src_port_range: Some((123, 123)),
            dst_port: None,
            pps_threshold: 10_000,
        }),
        
        // Memcached Amplification: Huge UDP from port 11211
        (AttackType::MemcachedAmplification, AttackSignature {
            protocol: Protocol::Udp,
            avg_packet_size_range: (1000, 65535),
            tcp_flags: None,
            src_port_range: Some((11211, 11211)),
            dst_port: None,
            pps_threshold: 1_000,
        }),
        
        // SSDP Amplification: UDP from port 1900
        (AttackType::SsdpAmplification, AttackSignature {
            protocol: Protocol::Udp,
            avg_packet_size_range: (200, 500),
            tcp_flags: None,
            src_port_range: Some((1900, 1900)),
            dst_port: None,
            pps_threshold: 10_000,
        }),
        
        // ICMP Flood
        (AttackType::IcmpFlood, AttackSignature {
            protocol: Protocol::Icmp,
            avg_packet_size_range: (64, 1500),
            tcp_flags: None,
            src_port_range: None,
            dst_port: None,
            pps_threshold: 100_000,
        }),
        
        // ACK Flood
        (AttackType::AckFlood, AttackSignature {
            protocol: Protocol::Tcp,
            avg_packet_size_range: (40, 80),
            tcp_flags: Some(0x10), // ACK
            src_port_range: None,
            dst_port: None,
            pps_threshold: 100_000,
        }),
    ]
}

/// Match traffic against known signatures
pub fn match_signature(
    protocol: Protocol,
    avg_packet_size: u32,
    tcp_flags: Option<u8>,
    src_port: u16,
) -> Option<AttackType> {
    for (attack_type, sig) in known_signatures() {
        if sig.protocol != protocol {
            continue;
        }
        
        if avg_packet_size < sig.avg_packet_size_range.0 
           || avg_packet_size > sig.avg_packet_size_range.1 {
            continue;
        }
        
        if let Some(expected_flags) = sig.tcp_flags {
            if tcp_flags != Some(expected_flags) {
                continue;
            }
        }
        
        if let Some((min_port, max_port)) = sig.src_port_range {
            if src_port < min_port || src_port > max_port {
                continue;
            }
        }
        
        return Some(attack_type);
    }
    
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_syn_flood_signature() {
        let result = match_signature(
            Protocol::Tcp,
            60,
            Some(0x02),
            12345,
        );
        assert_eq!(result, Some(AttackType::SynFlood));
    }
    
    #[test]
    fn test_dns_amp_signature() {
        let result = match_signature(
            Protocol::Udp,
            1500,
            None,
            53,
        );
        assert_eq!(result, Some(AttackType::DnsAmplification));
    }
}
