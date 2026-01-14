//! Inspection Context - Single parse, multiple inspections
//!
//! The context is created ONCE per packet and shared across all modules.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Inspection context - parsed ONCE, inspected by all modules
#[derive(Debug, Clone)]
pub struct InspectionContext<'a> {
    /// L2 Ethernet header
    pub l2: Option<EthernetHeader>,
    /// L3 header (IPv4/IPv6)
    pub l3: L3Header,
    /// L4 header (TCP/UDP/ICMP)
    pub l4: L4Header,
    /// L7 protocol detection
    pub l7: Option<L7Protocol>,
    /// Zero-copy payload view
    pub payload: PayloadView<'a>,
    /// Flow metadata
    pub metadata: FlowMetadata,
    /// Accumulated verdicts from modules
    pub verdicts: VerdictSet,
}

/// Ethernet header
#[derive(Debug, Clone, Copy)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
    pub vlan: Option<u16>,
}

/// L3 Header (unified IPv4/IPv6)
#[derive(Debug, Clone, Copy)]
pub enum L3Header {
    IPv4(Ipv4Header),
    IPv6(Ipv6Header),
    Other(u16),
}

impl L3Header {
    pub fn src_ip(&self) -> Option<IpAddr> {
        match self {
            L3Header::IPv4(h) => Some(IpAddr::V4(h.src)),
            L3Header::IPv6(h) => Some(IpAddr::V6(h.src)),
            _ => None,
        }
    }

    pub fn dst_ip(&self) -> Option<IpAddr> {
        match self {
            L3Header::IPv4(h) => Some(IpAddr::V4(h.dst)),
            L3Header::IPv6(h) => Some(IpAddr::V6(h.dst)),
            _ => None,
        }
    }

    pub fn protocol(&self) -> u8 {
        match self {
            L3Header::IPv4(h) => h.protocol,
            L3Header::IPv6(h) => h.next_header,
            _ => 0,
        }
    }
}

/// IPv4 header
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
}

/// IPv6 header
#[derive(Debug, Clone, Copy)]
pub struct Ipv6Header {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
}

/// L4 Header
#[derive(Debug, Clone, Copy)]
pub enum L4Header {
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Icmp(IcmpHeader),
    Other(u8),
}

impl L4Header {
    pub fn src_port(&self) -> Option<u16> {
        match self {
            L4Header::Tcp(h) => Some(h.src_port),
            L4Header::Udp(h) => Some(h.src_port),
            _ => None,
        }
    }

    pub fn dst_port(&self) -> Option<u16> {
        match self {
            L4Header::Tcp(h) => Some(h.dst_port),
            L4Header::Udp(h) => Some(h.dst_port),
            _ => None,
        }
    }
}

/// TCP header
#[derive(Debug, Clone, Copy)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub data_offset: u8,
    pub flags: TcpFlags,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

/// TCP flags
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl TcpFlags {
    pub fn from_byte(b: u8) -> Self {
        Self {
            fin: b & 0x01 != 0,
            syn: b & 0x02 != 0,
            rst: b & 0x04 != 0,
            psh: b & 0x08 != 0,
            ack: b & 0x10 != 0,
            urg: b & 0x20 != 0,
            ece: b & 0x40 != 0,
            cwr: b & 0x80 != 0,
        }
    }
}

/// UDP header
#[derive(Debug, Clone, Copy)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

/// ICMP header
#[derive(Debug, Clone, Copy)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
}

/// L7 Protocol detection
#[derive(Debug, Clone)]
pub enum L7Protocol {
    Http(HttpInfo),
    Https(TlsInfo),
    Dns(DnsInfo),
    Ssh,
    Ftp,
    Smtp,
    Imap,
    Pop3,
    Rdp,
    Smb,
    Unknown,
}

/// HTTP info extracted from request/response
#[derive(Debug, Clone)]
pub struct HttpInfo {
    pub method: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub user_agent: Option<String>,
    pub content_type: Option<String>,
}

/// TLS/HTTPS info (from ClientHello, no decryption)
#[derive(Debug, Clone)]
pub struct TlsInfo {
    pub sni: Option<String>,
    pub version: u16,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
}

/// DNS info
#[derive(Debug, Clone)]
pub struct DnsInfo {
    pub query_id: u16,
    pub is_response: bool,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsAnswer>,
}

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone)]
pub struct DnsAnswer {
    pub name: String,
    pub atype: u16,
    pub ttl: u32,
    pub data: Vec<u8>,
}

/// Zero-copy payload view
#[derive(Debug, Clone)]
pub struct PayloadView<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> PayloadView<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data[self.offset..]
    }

    pub fn len(&self) -> usize {
        self.data.len() - self.offset
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn advance(&mut self, n: usize) {
        self.offset = (self.offset + n).min(self.data.len());
    }
}

/// Flow metadata from connection tracking
#[derive(Debug, Clone, Default)]
pub struct FlowMetadata {
    pub flow_id: u64,
    pub direction: Direction,
    pub user_id: Option<String>,
    pub user_groups: Vec<String>,
    pub src_zone: Option<String>,
    pub dst_zone: Option<String>,
    pub application: Option<String>,
    pub geo_src: Option<GeoInfo>,
    pub geo_dst: Option<GeoInfo>,
    pub session_start: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub packets_sent: u64,
    pub packets_recv: u64,
}

/// Traffic direction
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Direction {
    #[default]
    Inbound,
    Outbound,
    Internal,
}

/// Geographic info (from GeoIP)
#[derive(Debug, Clone)]
pub struct GeoInfo {
    pub country: String,
    pub city: Option<String>,
    pub asn: Option<u32>,
    pub org: Option<String>,
}

/// Verdict set (accumulated from all modules)
#[derive(Debug, Clone, Default)]
pub struct VerdictSet {
    pub firewall: Option<ModuleVerdict>,
    pub ips: Option<ModuleVerdict>,
    pub url_filter: Option<ModuleVerdict>,
    pub dns_security: Option<ModuleVerdict>,
    pub dlp: Option<ModuleVerdict>,
    pub antimalware: Option<ModuleVerdict>,
}

/// Single module verdict
#[derive(Debug, Clone)]
pub struct ModuleVerdict {
    pub module: &'static str,
    pub action: VerdictAction,
    pub reason: String,
    pub rule_id: Option<u32>,
    pub severity: Severity,
}

/// Verdict action
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VerdictAction {
    Allow,
    Log,
    Throttle,
    Redirect,
    Block,
}

/// Severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl<'a> InspectionContext<'a> {
    /// Create context from raw packet
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < 34 {
            return None;
        }

        // Parse Ethernet
        let l2 = Some(EthernetHeader {
            dst_mac: [data[0], data[1], data[2], data[3], data[4], data[5]],
            src_mac: [data[6], data[7], data[8], data[9], data[10], data[11]],
            ethertype: u16::from_be_bytes([data[12], data[13]]),
            vlan: None,
        });

        // Parse L3
        let l3_offset = 14;
        let l3 = match u16::from_be_bytes([data[12], data[13]]) {
            0x0800 => Self::parse_ipv4(&data[l3_offset..])?,
            0x86DD => Self::parse_ipv6(&data[l3_offset..])?,
            other => L3Header::Other(other),
        };

        // Parse L4
        let l4_offset = l3_offset + match &l3 {
            L3Header::IPv4(h) => (h.ihl * 4) as usize,
            L3Header::IPv6(_) => 40,
            _ => return None,
        };

        let l4 = Self::parse_l4(&data[l4_offset..], l3.protocol())?;

        // Payload offset
        let payload_offset = l4_offset + match &l4 {
            L4Header::Tcp(h) => (h.data_offset * 4) as usize,
            L4Header::Udp(_) => 8,
            L4Header::Icmp(_) => 8,
            _ => 0,
        };

        let payload = if payload_offset < data.len() {
            PayloadView::new(&data[payload_offset..])
        } else {
            PayloadView::new(&[])
        };

        Some(Self {
            l2,
            l3,
            l4,
            l7: None,
            payload,
            metadata: FlowMetadata::default(),
            verdicts: VerdictSet::default(),
        })
    }

    fn parse_ipv4(data: &[u8]) -> Option<L3Header> {
        if data.len() < 20 { return None; }
        Some(L3Header::IPv4(Ipv4Header {
            version: data[0] >> 4,
            ihl: data[0] & 0x0F,
            dscp: data[1] >> 2,
            ecn: data[1] & 0x03,
            total_length: u16::from_be_bytes([data[2], data[3]]),
            identification: u16::from_be_bytes([data[4], data[5]]),
            flags: data[6] >> 5,
            fragment_offset: u16::from_be_bytes([data[6] & 0x1F, data[7]]),
            ttl: data[8],
            protocol: data[9],
            checksum: u16::from_be_bytes([data[10], data[11]]),
            src: Ipv4Addr::new(data[12], data[13], data[14], data[15]),
            dst: Ipv4Addr::new(data[16], data[17], data[18], data[19]),
        }))
    }

    fn parse_ipv6(data: &[u8]) -> Option<L3Header> {
        if data.len() < 40 { return None; }
        let src = Ipv6Addr::new(
            u16::from_be_bytes([data[8], data[9]]),
            u16::from_be_bytes([data[10], data[11]]),
            u16::from_be_bytes([data[12], data[13]]),
            u16::from_be_bytes([data[14], data[15]]),
            u16::from_be_bytes([data[16], data[17]]),
            u16::from_be_bytes([data[18], data[19]]),
            u16::from_be_bytes([data[20], data[21]]),
            u16::from_be_bytes([data[22], data[23]]),
        );
        let dst = Ipv6Addr::new(
            u16::from_be_bytes([data[24], data[25]]),
            u16::from_be_bytes([data[26], data[27]]),
            u16::from_be_bytes([data[28], data[29]]),
            u16::from_be_bytes([data[30], data[31]]),
            u16::from_be_bytes([data[32], data[33]]),
            u16::from_be_bytes([data[34], data[35]]),
            u16::from_be_bytes([data[36], data[37]]),
            u16::from_be_bytes([data[38], data[39]]),
        );
        Some(L3Header::IPv6(Ipv6Header {
            version: data[0] >> 4,
            traffic_class: ((data[0] & 0x0F) << 4) | (data[1] >> 4),
            flow_label: u32::from_be_bytes([0, data[1] & 0x0F, data[2], data[3]]),
            payload_length: u16::from_be_bytes([data[4], data[5]]),
            next_header: data[6],
            hop_limit: data[7],
            src,
            dst,
        }))
    }

    fn parse_l4(data: &[u8], protocol: u8) -> Option<L4Header> {
        match protocol {
            6 if data.len() >= 20 => {
                let flags = TcpFlags::from_byte(data[13]);
                Some(L4Header::Tcp(TcpHeader {
                    src_port: u16::from_be_bytes([data[0], data[1]]),
                    dst_port: u16::from_be_bytes([data[2], data[3]]),
                    seq: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
                    ack: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
                    data_offset: data[12] >> 4,
                    flags,
                    window: u16::from_be_bytes([data[14], data[15]]),
                    checksum: u16::from_be_bytes([data[16], data[17]]),
                    urgent_ptr: u16::from_be_bytes([data[18], data[19]]),
                }))
            }
            17 if data.len() >= 8 => Some(L4Header::Udp(UdpHeader {
                src_port: u16::from_be_bytes([data[0], data[1]]),
                dst_port: u16::from_be_bytes([data[2], data[3]]),
                length: u16::from_be_bytes([data[4], data[5]]),
                checksum: u16::from_be_bytes([data[6], data[7]]),
            })),
            1 | 58 if data.len() >= 8 => Some(L4Header::Icmp(IcmpHeader {
                icmp_type: data[0],
                code: data[1],
                checksum: u16::from_be_bytes([data[2], data[3]]),
            })),
            _ => Some(L4Header::Other(protocol)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_packet() -> Vec<u8> {
        let mut pkt = vec![0u8; 54];
        // Ethernet
        pkt[12] = 0x08; pkt[13] = 0x00;
        // IPv4
        pkt[14] = 0x45;
        pkt[23] = 6; // TCP
        pkt[26..30].copy_from_slice(&[192, 168, 1, 1]);
        pkt[30..34].copy_from_slice(&[10, 0, 0, 1]);
        // TCP
        pkt[34] = 0x30; pkt[35] = 0x39;
        pkt[36] = 0x01; pkt[37] = 0xBB;
        pkt[46] = 0x50; // Data offset
        pkt
    }

    #[test]
    fn test_context_parse() {
        let pkt = make_test_packet();
        let ctx = InspectionContext::parse(&pkt).unwrap();
        
        assert!(matches!(ctx.l3, L3Header::IPv4(_)));
        assert!(matches!(ctx.l4, L4Header::Tcp(_)));
        
        assert_eq!(ctx.l4.src_port(), Some(12345));
        assert_eq!(ctx.l4.dst_port(), Some(443));
    }
}
