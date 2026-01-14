//! Complete SASE Packet Pipeline
//!
//! RX → Parse → Classify → NAT → Encrypt → Encap → QoS → TX
//!
//! All stages are zero-copy transformations.

use crate::buffer::PacketBuffer;
use crate::flow::{FlowKey, FlowVerdict, NatState, NatType};
use std::net::Ipv4Addr;

/// Pipeline stage result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageResult {
    /// Continue to next stage
    Continue,
    /// Drop packet
    Drop,
    /// Redirect to port
    Redirect(u16),
    /// Send to slow path
    SlowPath,
}

/// Pipeline context
#[derive(Debug, Default)]
pub struct PipelineContext {
    // Parsed headers
    pub flow_key: Option<FlowKey>,
    pub l2_offset: u16,
    pub l3_offset: u16,
    pub l4_offset: u16,
    pub payload_offset: u16,
    
    // Classification
    pub verdict: FlowVerdict,
    pub app_id: u16,
    pub qos_class: u8,
    
    // NAT
    pub nat_state: Option<NatState>,
    pub needs_snat: bool,
    pub needs_dnat: bool,
    
    // Encryption
    pub needs_encrypt: bool,
    pub tunnel_id: u32,
    pub crypto_ctx: u32,
    
    // Encapsulation
    pub encap_type: EncapType,
    pub outer_src: u32,
    pub outer_dst: u32,
    
    // Ports
    pub in_port: u16,
    pub out_port: u16,
}

/// Encapsulation type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EncapType {
    #[default]
    None,
    VxLAN,
    GRE,
    IPsec,
    WireGuard,
    Geneve,
}

/// Pipeline stage trait
pub trait Stage: Send + Sync {
    fn process(&self, buf: &mut PacketBuffer, ctx: &mut PipelineContext) -> StageResult;
    fn name(&self) -> &'static str;
}

/// Complete SASE pipeline
pub struct Pipeline {
    stages: Vec<Box<dyn Stage>>,
}

impl Pipeline {
    pub fn new() -> Self {
        Self { stages: Vec::new() }
    }

    /// Create full SASE pipeline
    pub fn sase_pipeline() -> Self {
        let mut p = Self::new();
        p.add_stage(Box::new(ParseStage));
        p.add_stage(Box::new(ClassifyStage::new()));
        p.add_stage(Box::new(NatStage::new()));
        p.add_stage(Box::new(EncryptStage::new()));
        p.add_stage(Box::new(EncapStage::new()));
        p.add_stage(Box::new(QosStage::new()));
        p
    }

    pub fn add_stage(&mut self, stage: Box<dyn Stage>) {
        self.stages.push(stage);
    }

    #[inline]
    pub fn process(&self, buf: &mut PacketBuffer, ctx: &mut PipelineContext) -> StageResult {
        for stage in &self.stages {
            match stage.process(buf, ctx) {
                StageResult::Continue => continue,
                result => return result,
            }
        }
        StageResult::Continue
    }

    pub fn stage_count(&self) -> usize {
        self.stages.len()
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::sase_pipeline()
    }
}

// ============================================================================
// Stage 1: Parse (L2-L4 header extraction)
// ============================================================================

pub struct ParseStage;

impl Stage for ParseStage {
    fn process(&self, buf: &mut PacketBuffer, ctx: &mut PipelineContext) -> StageResult {
        let data = buf.data();
        if data.len() < 34 {
            return StageResult::Drop;
        }

        ctx.l2_offset = 0;
        ctx.l3_offset = 14;

        // Ethernet type
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        if ethertype != 0x0800 {
            return StageResult::Continue; // Non-IPv4 passthrough
        }

        // IPv4 header
        let ihl = ((data[14] & 0x0F) * 4) as u16;
        ctx.l4_offset = 14 + ihl;
        
        let src_ip = u32::from_be_bytes([data[26], data[27], data[28], data[29]]);
        let dst_ip = u32::from_be_bytes([data[30], data[31], data[32], data[33]]);
        let protocol = data[23];

        // L4 ports
        let l4 = ctx.l4_offset as usize;
        let (src_port, dst_port) = if l4 + 4 <= data.len() {
            (u16::from_be_bytes([data[l4], data[l4 + 1]]),
             u16::from_be_bytes([data[l4 + 2], data[l4 + 3]]))
        } else {
            (0, 0)
        };

        ctx.flow_key = Some(FlowKey::new(src_ip, dst_ip, src_port, dst_port, protocol));
        ctx.payload_offset = ctx.l4_offset + match protocol {
            6 => 20,  // TCP
            17 => 8,  // UDP
            _ => 0,
        };

        StageResult::Continue
    }

    fn name(&self) -> &'static str { "parse" }
}

// ============================================================================
// Stage 2: Classify (DPI + Policy lookup)
// ============================================================================

pub struct ClassifyStage {
    /// Application signature patterns (simplified)
    app_patterns: Vec<(u16, u16, u8)>, // (dst_port, app_id, qos_class)
}

impl ClassifyStage {
    pub fn new() -> Self {
        Self {
            app_patterns: vec![
                (443, 1, 2),   // HTTPS → Web → QoS 2
                (80, 1, 2),    // HTTP
                (53, 2, 1),    // DNS → Priority
                (5060, 3, 0),  // SIP → Voice → Highest
                (5061, 3, 0),  // SIP-TLS
                (3478, 4, 0),  // STUN → RTC
                (3479, 4, 0),  // TURN
                (1194, 5, 3),  // OpenVPN
                (51820, 6, 3), // WireGuard
                (22, 7, 2),    // SSH
                (3389, 8, 2),  // RDP
            ],
        }
    }

    fn classify_by_port(&self, dst_port: u16) -> (u16, u8) {
        for (port, app_id, qos_class) in &self.app_patterns {
            if dst_port == *port {
                return (*app_id, *qos_class);
            }
        }
        (0, 4) // Unknown → Best effort
    }
}

impl Stage for ClassifyStage {
    fn process(&self, buf: &mut PacketBuffer, ctx: &mut PipelineContext) -> StageResult {
        if let Some(ref key) = ctx.flow_key {
            let (app_id, qos_class) = self.classify_by_port(key.dst_port);
            ctx.app_id = app_id;
            ctx.qos_class = qos_class;

            // Policy lookup (simplified - always allow)
            ctx.verdict = FlowVerdict::Allow;
        }

        match ctx.verdict {
            FlowVerdict::Drop => StageResult::Drop,
            FlowVerdict::Reject => StageResult::Drop,
            FlowVerdict::Inspect => StageResult::SlowPath,
            _ => StageResult::Continue,
        }
    }

    fn name(&self) -> &'static str { "classify" }
}

// ============================================================================
// Stage 3: NAT (SNAT/DNAT)
// ============================================================================

pub struct NatStage {
    /// SNAT pool (simplified - single IP)
    snat_ip: u32,
    /// DNAT mappings
    dnat_rules: Vec<(u32, u16, u32, u16)>, // (match_ip, match_port, xlate_ip, xlate_port)
}

impl NatStage {
    pub fn new() -> Self {
        Self {
            snat_ip: u32::from_be_bytes([10, 0, 0, 1]),
            dnat_rules: Vec::new(),
        }
    }

    pub fn set_snat_ip(&mut self, ip: u32) {
        self.snat_ip = ip;
    }

    pub fn add_dnat(&mut self, match_ip: u32, match_port: u16, xlate_ip: u32, xlate_port: u16) {
        self.dnat_rules.push((match_ip, match_port, xlate_ip, xlate_port));
    }

    fn apply_snat(&self, buf: &mut PacketBuffer, ctx: &PipelineContext) {
        let data = buf.data_mut();
        let l3 = ctx.l3_offset as usize;
        
        // Modify source IP
        let new_ip = self.snat_ip.to_be_bytes();
        data[l3 + 12] = new_ip[0];
        data[l3 + 13] = new_ip[1];
        data[l3 + 14] = new_ip[2];
        data[l3 + 15] = new_ip[3];
        
        // TODO: Recalculate checksums
    }

    fn apply_dnat(&self, buf: &mut PacketBuffer, ctx: &PipelineContext, xlate_ip: u32, _xlate_port: u16) {
        let data = buf.data_mut();
        let l3 = ctx.l3_offset as usize;
        
        // Modify destination IP
        let new_ip = xlate_ip.to_be_bytes();
        data[l3 + 16] = new_ip[0];
        data[l3 + 17] = new_ip[1];
        data[l3 + 18] = new_ip[2];
        data[l3 + 19] = new_ip[3];
        
        // TODO: Recalculate checksums
    }
}

impl Stage for NatStage {
    fn process(&self, buf: &mut PacketBuffer, ctx: &mut PipelineContext) -> StageResult {
        if let Some(ref key) = ctx.flow_key {
            // Check DNAT rules
            for (match_ip, match_port, xlate_ip, xlate_port) in &self.dnat_rules {
                if key.dst_ip == *match_ip && key.dst_port == *match_port {
                    self.apply_dnat(buf, ctx, *xlate_ip, *xlate_port);
                    ctx.nat_state = Some(NatState {
                        xlate_src_ip: *xlate_ip,
                        xlate_src_port: *xlate_port,
                        nat_type: NatType::Dnat,
                    });
                    break;
                }
            }

            // Apply SNAT if needed
            if ctx.needs_snat {
                self.apply_snat(buf, ctx);
            }
        }

        StageResult::Continue
    }

    fn name(&self) -> &'static str { "nat" }
}

// ============================================================================
// Stage 4: Encrypt (IPsec/WireGuard)
// ============================================================================

pub struct EncryptStage {
    /// Tunnel keys (tunnel_id → key material)
    tunnel_keys: Vec<(u32, [u8; 32])>,
}

impl EncryptStage {
    pub fn new() -> Self {
        Self { tunnel_keys: Vec::new() }
    }

    pub fn add_tunnel(&mut self, tunnel_id: u32, key: [u8; 32]) {
        self.tunnel_keys.push((tunnel_id, key));
    }

    fn encrypt_payload(&self, buf: &mut PacketBuffer, ctx: &PipelineContext, _key: &[u8; 32]) {
        // Placeholder - in production use ring/chacha20poly1305
        let data = buf.data_mut();
        let start = ctx.payload_offset as usize;
        
        // XOR with pseudo-key (demo only - NOT SECURE)
        for i in start..data.len() {
            data[i] ^= 0x55;
        }
    }
}

impl Stage for EncryptStage {
    fn process(&self, buf: &mut PacketBuffer, ctx: &mut PipelineContext) -> StageResult {
        if !ctx.needs_encrypt {
            return StageResult::Continue;
        }

        // Find tunnel key
        for (tid, key) in &self.tunnel_keys {
            if *tid == ctx.tunnel_id {
                self.encrypt_payload(buf, ctx, key);
                break;
            }
        }

        StageResult::Continue
    }

    fn name(&self) -> &'static str { "encrypt" }
}

// ============================================================================
// Stage 5: Encap (VxLAN/GRE/Geneve)
// ============================================================================

pub struct EncapStage {
    /// VNI for VxLAN
    default_vni: u32,
}

impl EncapStage {
    pub fn new() -> Self {
        Self { default_vni: 100 }
    }

    fn encap_vxlan(&self, buf: &mut PacketBuffer, ctx: &PipelineContext) {
        // VxLAN: 8 bytes UDP + 8 bytes VxLAN header
        let vxlan_hdr = [
            0x08, 0x00, 0x00, 0x00,  // Flags + Reserved
            (self.default_vni >> 16) as u8,
            (self.default_vni >> 8) as u8,
            self.default_vni as u8,
            0x00,  // Reserved
        ];

        // Prepend outer headers (simplified)
        if let Some(hdr) = buf.prepend(50) {  // Outer Eth + IP + UDP + VxLAN
            // Outer Ethernet (14 bytes) - placeholder
            hdr[0..6].copy_from_slice(&[0x00; 6]);   // Dst MAC
            hdr[6..12].copy_from_slice(&[0x00; 6]); // Src MAC
            hdr[12] = 0x08;
            hdr[13] = 0x00;  // IPv4

            // Outer IP (20 bytes)
            hdr[14] = 0x45;  // Ver + IHL
            hdr[15] = 0x00;  // TOS
            // Length, ID, Flags, TTL, Protocol (UDP=17)
            hdr[23] = 17;
            // Src/Dst IP
            let src = ctx.outer_src.to_be_bytes();
            let dst = ctx.outer_dst.to_be_bytes();
            hdr[26..30].copy_from_slice(&src);
            hdr[30..34].copy_from_slice(&dst);

            // Outer UDP (8 bytes) - VxLAN uses port 4789
            hdr[34] = 0x12;
            hdr[35] = 0xB5;  // Src port
            hdr[36] = 0x12;
            hdr[37] = 0xB5;  // Dst port 4789

            // VxLAN header
            hdr[42..50].copy_from_slice(&vxlan_hdr);
        }
    }
}

impl Stage for EncapStage {
    fn process(&self, buf: &mut PacketBuffer, ctx: &mut PipelineContext) -> StageResult {
        match ctx.encap_type {
            EncapType::None => {},
            EncapType::VxLAN => self.encap_vxlan(buf, ctx),
            EncapType::GRE => {
                // TODO: GRE encapsulation
            },
            EncapType::IPsec => {
                // Handled by encrypt stage
            },
            EncapType::WireGuard => {
                // TODO: WireGuard encapsulation
            },
            EncapType::Geneve => {
                // TODO: Geneve encapsulation
            },
        }

        StageResult::Continue
    }

    fn name(&self) -> &'static str { "encap" }
}

// ============================================================================
// Stage 6: QoS (DSCP marking + rate limiting)
// ============================================================================

pub struct QosStage {
    /// DSCP values per QoS class
    dscp_map: [u8; 8],
    /// Rate limits per class (bytes/sec, 0 = unlimited)
    rate_limits: [u64; 8],
}

impl QosStage {
    pub fn new() -> Self {
        Self {
            dscp_map: [
                46,  // Class 0: EF (Expedited Forwarding) - Voice
                34,  // Class 1: AF41 - Video
                26,  // Class 2: AF31 - Interactive
                18,  // Class 3: AF21 - Streaming
                10,  // Class 4: AF11 - Bulk
                0,   // Class 5: Best Effort
                0,   // Class 6: Scavenger
                0,   // Class 7: Reserved
            ],
            rate_limits: [0; 8],  // No limits by default
        }
    }

    pub fn set_dscp(&mut self, class: u8, dscp: u8) {
        if class < 8 {
            self.dscp_map[class as usize] = dscp;
        }
    }

    pub fn set_rate_limit(&mut self, class: u8, bytes_per_sec: u64) {
        if class < 8 {
            self.rate_limits[class as usize] = bytes_per_sec;
        }
    }
}

impl Stage for QosStage {
    fn process(&self, buf: &mut PacketBuffer, ctx: &mut PipelineContext) -> StageResult {
        let qos_class = (ctx.qos_class as usize).min(7);
        let dscp = self.dscp_map[qos_class];

        // Mark DSCP in IP header
        let data = buf.data_mut();
        let l3 = ctx.l3_offset as usize;
        if l3 + 2 <= data.len() {
            // TOS field = DSCP << 2 | ECN
            let ecn = data[l3 + 1] & 0x03;
            data[l3 + 1] = (dscp << 2) | ecn;
        }

        // Rate limiting would be applied here
        // (using token bucket per qos_class)

        StageResult::Continue
    }

    fn name(&self) -> &'static str { "qos" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::BufferPool;

    fn make_packet(buf: &mut PacketBuffer) {
        let data = buf.append(54).unwrap();
        // Ethernet
        data[12] = 0x08; data[13] = 0x00;
        // IPv4
        data[14] = 0x45;
        data[23] = 6; // TCP
        // IPs
        data[26..30].copy_from_slice(&[192, 168, 1, 1]);
        data[30..34].copy_from_slice(&[10, 0, 0, 1]);
        // Ports: 12345 → 443
        data[34] = 0x30; data[35] = 0x39;
        data[36] = 0x01; data[37] = 0xBB;
    }

    #[test]
    fn test_full_pipeline() {
        let pipeline = Pipeline::sase_pipeline();
        assert_eq!(pipeline.stage_count(), 6);

        let pool = BufferPool::new(16);
        let buf = pool.alloc().unwrap();
        make_packet(buf);

        let mut ctx = PipelineContext::default();
        let result = pipeline.process(buf, &mut ctx);

        assert_eq!(result, StageResult::Continue);
        assert!(ctx.flow_key.is_some());
        assert_eq!(ctx.app_id, 1);  // HTTPS
        assert_eq!(ctx.qos_class, 2);
    }

    #[test]
    fn test_classify_voice() {
        let stage = ClassifyStage::new();
        let pool = BufferPool::new(16);
        let buf = pool.alloc().unwrap();
        
        let data = buf.append(54).unwrap();
        data[12] = 0x08; data[13] = 0x00;
        data[14] = 0x45;
        data[23] = 17; // UDP
        data[26..30].copy_from_slice(&[192, 168, 1, 1]);
        data[30..34].copy_from_slice(&[10, 0, 0, 1]);
        // Ports: 5060 (SIP)
        data[34] = 0x13; data[35] = 0xC4;
        data[36] = 0x13; data[37] = 0xC4;

        let mut ctx = PipelineContext::default();
        ctx.flow_key = Some(FlowKey::new(0, 0, 5060, 5060, 17));

        stage.process(buf, &mut ctx);
        assert_eq!(ctx.app_id, 3);  // SIP
        assert_eq!(ctx.qos_class, 0);  // Highest priority
    }
}
