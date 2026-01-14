//! Network flow types for high-performance packet processing
//!
//! Zero-copy flow key extraction and hashing

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// 5-tuple flow key (optimized for cache-line)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C, align(32))]
pub struct FlowKey {
    /// Source IP (v4 stored in low bits)
    pub src_ip: u128,
    /// Destination IP
    pub dst_ip: u128,
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// IP protocol
    pub protocol: u8,
    /// Padding for alignment
    _pad: [u8; 3],
}

impl FlowKey {
    /// Create from IPv4 tuple
    #[inline(always)]
    pub const fn from_v4(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Self {
        Self {
            src_ip: u32::from_be_bytes(src.octets()) as u128,
            dst_ip: u32::from_be_bytes(dst.octets()) as u128,
            src_port,
            dst_port,
            protocol,
            _pad: [0; 3],
        }
    }

    /// Create from IPv6 tuple
    #[inline(always)]
    pub const fn from_v6(
        src: Ipv6Addr,
        dst: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Self {
        Self {
            src_ip: u128::from_be_bytes(src.octets()),
            dst_ip: u128::from_be_bytes(dst.octets()),
            src_port,
            dst_port,
            protocol,
            _pad: [0; 3],
        }
    }

    /// Get reverse flow key (for bidirectional matching)
    #[inline(always)]
    pub const fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
            _pad: [0; 3],
        }
    }

    /// Fast hash using FxHash algorithm
    #[inline(always)]
    pub fn fx_hash(&self) -> u64 {
        const K: u64 = 0x517cc1b727220a95;
        let mut h: u64 = 0;
        
        h = h.wrapping_add((self.src_ip as u64).wrapping_mul(K));
        h = h.rotate_left(31);
        h = h.wrapping_add(((self.src_ip >> 64) as u64).wrapping_mul(K));
        h = h.rotate_left(31);
        h = h.wrapping_add((self.dst_ip as u64).wrapping_mul(K));
        h = h.rotate_left(31);
        h = h.wrapping_add(((self.dst_ip >> 64) as u64).wrapping_mul(K));
        h = h.rotate_left(31);
        h = h.wrapping_add(((self.src_port as u64) << 48 | 
                           (self.dst_port as u64) << 32 |
                           (self.protocol as u64)).wrapping_mul(K));
        h
    }
}

/// Flow state for connection tracking
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FlowState {
    /// Packets seen
    pub packets: u64,
    /// Bytes seen
    pub bytes: u64,
    /// First packet timestamp (nanos)
    pub first_seen: u64,
    /// Last packet timestamp (nanos)
    pub last_seen: u64,
    /// TCP state (if TCP)
    pub tcp_state: TcpState,
    /// Flags
    pub flags: FlowFlags,
}

/// TCP connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TcpState {
    /// New connection
    New = 0,
    /// SYN sent
    SynSent = 1,
    /// SYN received
    SynRecv = 2,
    /// Established
    Established = 3,
    /// FIN wait
    FinWait = 4,
    /// Close wait
    CloseWait = 5,
    /// Closed
    Closed = 6,
}

impl Default for TcpState {
    fn default() -> Self {
        Self::New
    }
}

/// Flow flags
#[derive(Debug, Clone, Copy, Default)]
#[repr(transparent)]
pub struct FlowFlags(u16);

impl FlowFlags {
    /// Flow is inspected
    pub const INSPECTED: u16 = 1 << 0;
    /// Flow is encrypted
    pub const ENCRYPTED: u16 = 1 << 1;
    /// Flow has DLP match
    pub const DLP_MATCH: u16 = 1 << 2;
    /// Flow is rate-limited
    pub const RATE_LIMITED: u16 = 1 << 3;
    /// Flow is logged
    pub const LOGGED: u16 = 1 << 4;

    /// Check if flag is set
    #[inline(always)]
    pub const fn has(&self, flag: u16) -> bool {
        self.0 & flag != 0
    }

    /// Set flag
    #[inline(always)]
    pub fn set(&mut self, flag: u16) {
        self.0 |= flag;
    }
}

/// Packet metadata for fast path
#[derive(Debug, Clone, Copy)]
#[repr(C, align(64))]
pub struct PacketMeta {
    /// Flow key
    pub flow: FlowKey,
    /// Packet length
    pub len: u16,
    /// IP header offset
    pub ip_offset: u16,
    /// L4 header offset
    pub l4_offset: u16,
    /// Payload offset
    pub payload_offset: u16,
    /// Timestamp (nanos)
    pub timestamp: u64,
}

impl PacketMeta {
    /// Parse from raw packet (Ethernet frame)
    #[inline]
    pub fn parse(data: &[u8], timestamp: u64) -> Option<Self> {
        if data.len() < 14 + 20 {  // Eth + min IPv4
            return None;
        }

        // Check Ethernet type
        let eth_type = u16::from_be_bytes([data[12], data[13]]);
        
        match eth_type {
            0x0800 => Self::parse_ipv4(&data[14..], 14, timestamp),
            0x86DD => Self::parse_ipv6(&data[14..], 14, timestamp),
            _ => None,
        }
    }

    #[inline]
    fn parse_ipv4(data: &[u8], ip_offset: u16, timestamp: u64) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }

        let ihl = ((data[0] & 0x0f) * 4) as usize;
        let protocol = data[9];
        let src_ip = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let dst_ip = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);

        let l4_offset = ip_offset + ihl as u16;
        let (src_port, dst_port, payload_offset) = if protocol == 6 || protocol == 17 {
            // TCP or UDP
            let ports = &data[ihl..];
            if ports.len() >= 4 {
                let sp = u16::from_be_bytes([ports[0], ports[1]]);
                let dp = u16::from_be_bytes([ports[2], ports[3]]);
                let hdr_len = if protocol == 6 { 20 } else { 8 };
                (sp, dp, l4_offset + hdr_len)
            } else {
                (0, 0, l4_offset)
            }
        } else {
            (0, 0, l4_offset)
        };

        Some(Self {
            flow: FlowKey::from_v4(
                Ipv4Addr::from(src_ip),
                Ipv4Addr::from(dst_ip),
                src_port,
                dst_port,
                protocol,
            ),
            len: (data.len() + ip_offset as usize) as u16,
            ip_offset,
            l4_offset,
            payload_offset,
            timestamp,
        })
    }

    #[inline]
    fn parse_ipv6(data: &[u8], ip_offset: u16, timestamp: u64) -> Option<Self> {
        if data.len() < 40 {
            return None;
        }

        let protocol = data[6];  // Next header (simplified)
        let src_ip: [u8; 16] = data[8..24].try_into().ok()?;
        let dst_ip: [u8; 16] = data[24..40].try_into().ok()?;

        let l4_offset = ip_offset + 40;
        let (src_port, dst_port, payload_offset) = if protocol == 6 || protocol == 17 {
            let ports = &data[40..];
            if ports.len() >= 4 {
                let sp = u16::from_be_bytes([ports[0], ports[1]]);
                let dp = u16::from_be_bytes([ports[2], ports[3]]);
                let hdr_len = if protocol == 6 { 20 } else { 8 };
                (sp, dp, l4_offset + hdr_len)
            } else {
                (0, 0, l4_offset)
            }
        } else {
            (0, 0, l4_offset)
        };

        Some(Self {
            flow: FlowKey::from_v6(
                Ipv6Addr::from(src_ip),
                Ipv6Addr::from(dst_ip),
                src_port,
                dst_port,
                protocol,
            ),
            len: (data.len() + ip_offset as usize) as u16,
            ip_offset,
            l4_offset,
            payload_offset,
            timestamp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_key_size() {
        // Ensure alignment (struct may be larger due to padding)
        assert!(std::mem::size_of::<FlowKey>() >= 32);
        assert_eq!(std::mem::align_of::<FlowKey>(), 32);
    }

    #[test]
    fn test_flow_hash() {
        let flow = FlowKey::from_v4(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(10, 0, 0, 1),
            12345,
            443,
            6,
        );
        let hash = flow.fx_hash();
        assert_ne!(hash, 0);
        
        // Same flow should have same hash
        let flow2 = flow.clone();
        assert_eq!(flow.fx_hash(), flow2.fx_hash());
    }

    #[test]
    fn test_parse_packet() {
        // Minimal Ethernet + IPv4 + TCP packet
        let pkt = [
            // Ethernet
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // dst mac
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // src mac
            0x08, 0x00,                          // IPv4
            // IPv4
            0x45, 0x00, 0x00, 0x28,              // version, ihl, len
            0x00, 0x00, 0x00, 0x00,              // id, flags, frag
            0x40, 0x06, 0x00, 0x00,              // ttl, protocol (TCP), checksum
            0xc0, 0xa8, 0x01, 0x01,              // src: 192.168.1.1
            0x0a, 0x00, 0x00, 0x01,              // dst: 10.0.0.1
            // TCP
            0x30, 0x39,                          // src port: 12345
            0x01, 0xbb,                          // dst port: 443
            0x00, 0x00, 0x00, 0x00,              // seq
        ];

        let meta = PacketMeta::parse(&pkt, 0).expect("parse failed");
        assert_eq!(meta.flow.src_port, 12345);
        assert_eq!(meta.flow.dst_port, 443);
        assert_eq!(meta.flow.protocol, 6);
    }
}
