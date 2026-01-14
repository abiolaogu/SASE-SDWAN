//! Hardware Abstraction

use serde::{Deserialize, Serialize};

/// Hardware detection and abstraction
pub struct HardwareInfo {
    pub cpu: CpuInfo,
    pub memory: MemoryInfo,
    pub nics: Vec<NicInfo>,
    pub crypto: CryptoCapabilities,
}

impl HardwareInfo {
    /// Detect hardware
    pub fn detect() -> Self {
        Self {
            cpu: Self::detect_cpu(),
            memory: Self::detect_memory(),
            nics: Self::detect_nics(),
            crypto: Self::detect_crypto(),
        }
    }

    fn detect_cpu() -> CpuInfo {
        // In production: read from /proc/cpuinfo
        CpuInfo {
            model: "Intel Xeon E-2278G".into(),
            cores: 8,
            threads: 16,
            frequency_mhz: 3400,
            architecture: Architecture::X86_64,
        }
    }

    fn detect_memory() -> MemoryInfo {
        MemoryInfo {
            total_mb: 8192,
            available_mb: 6000,
        }
    }

    fn detect_nics() -> Vec<NicInfo> {
        // In production: scan /sys/class/net
        vec![
            NicInfo {
                name: "eth0".into(),
                driver: "igb".into(),
                vendor: NicVendor::Intel,
                model: "I210 Gigabit".into(),
                mac_address: "00:11:22:33:44:55".into(),
                speed_mbps: Some(1000),
                link_up: true,
                offload_capable: true,
            },
            NicInfo {
                name: "eth1".into(),
                driver: "igb".into(),
                vendor: NicVendor::Intel,
                model: "I210 Gigabit".into(),
                mac_address: "00:11:22:33:44:56".into(),
                speed_mbps: Some(1000),
                link_up: true,
                offload_capable: true,
            },
        ]
    }

    fn detect_crypto() -> CryptoCapabilities {
        CryptoCapabilities {
            aes_ni: true,
            sha_ni: true,
            qat: false,
            wireguard_offload: false,
        }
    }

    /// Check minimum requirements
    pub fn check_requirements(&self) -> RequirementsCheck {
        let mut issues = Vec::new();

        if self.cpu.cores < 2 {
            issues.push("Minimum 2 CPU cores required".into());
        }
        if self.memory.total_mb < 4096 {
            issues.push("Minimum 4GB RAM required".into());
        }
        if self.nics.len() < 2 {
            issues.push("Minimum 2 NICs recommended".into());
        }

        RequirementsCheck {
            passed: issues.is_empty(),
            issues,
        }
    }

    /// Get recommended settings based on hardware
    pub fn recommended_settings(&self) -> RecommendedSettings {
        RecommendedSettings {
            worker_threads: self.cpu.cores.min(8) as usize,
            max_connections: if self.memory.total_mb >= 8192 { 100_000 } else { 50_000 },
            use_crypto_offload: self.crypto.aes_ni,
            use_qat: self.crypto.qat,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuInfo {
    pub model: String,
    pub cores: u32,
    pub threads: u32,
    pub frequency_mhz: u32,
    pub architecture: Architecture,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Architecture {
    X86_64,
    Arm64,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInfo {
    pub total_mb: u64,
    pub available_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NicInfo {
    pub name: String,
    pub driver: String,
    pub vendor: NicVendor,
    pub model: String,
    pub mac_address: String,
    pub speed_mbps: Option<u32>,
    pub link_up: bool,
    pub offload_capable: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum NicVendor {
    Intel,
    Mellanox,
    Broadcom,
    Realtek,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoCapabilities {
    pub aes_ni: bool,
    pub sha_ni: bool,
    pub qat: bool,
    pub wireguard_offload: bool,
}

#[derive(Debug, Clone)]
pub struct RequirementsCheck {
    pub passed: bool,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RecommendedSettings {
    pub worker_threads: usize,
    pub max_connections: usize,
    pub use_crypto_offload: bool,
    pub use_qat: bool,
}
