//! Power Management
//!
//! Battery-efficient connection management.

use serde::{Deserialize, Serialize};

pub struct PowerManager {
    state: parking_lot::RwLock<PowerState>,
    settings: parking_lot::RwLock<PowerSettings>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PowerState {
    /// On AC power
    Plugged,
    /// On battery
    Battery,
    /// Low battery (< 20%)
    LowBattery,
    /// Critical battery (< 5%)
    CriticalBattery,
    /// Unknown
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PowerSettings {
    /// Reduce keepalive frequency on battery
    pub battery_saver_enabled: bool,
    /// Keepalive interval when plugged in (seconds)
    pub plugged_keepalive_secs: u64,
    /// Keepalive interval on battery (seconds)
    pub battery_keepalive_secs: u64,
    /// Disconnect on critical battery
    pub disconnect_on_critical: bool,
    /// Pause posture checks on battery
    pub pause_posture_on_battery: bool,
}

impl Default for PowerSettings {
    fn default() -> Self {
        Self {
            battery_saver_enabled: true,
            plugged_keepalive_secs: 25,
            battery_keepalive_secs: 60,
            disconnect_on_critical: false,
            pause_posture_on_battery: true,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct BatteryStatus {
    pub state: PowerState,
    pub percentage: Option<u8>,
    pub time_remaining_mins: Option<u32>,
    pub charging: bool,
}

impl PowerManager {
    pub fn new(settings: PowerSettings) -> Self {
        Self {
            state: parking_lot::RwLock::new(PowerState::Unknown),
            settings: parking_lot::RwLock::new(settings),
        }
    }
    
    /// Get current battery status
    pub fn get_battery_status(&self) -> BatteryStatus {
        #[cfg(target_os = "macos")]
        return self.get_battery_macos();
        
        #[cfg(target_os = "windows")]
        return self.get_battery_windows();
        
        #[cfg(target_os = "linux")]
        return self.get_battery_linux();
        
        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        return BatteryStatus {
            state: PowerState::Unknown,
            percentage: None,
            time_remaining_mins: None,
            charging: false,
        };
    }
    
    #[cfg(target_os = "macos")]
    fn get_battery_macos(&self) -> BatteryStatus {
        // Use ioreg or pmset to get battery info
        // Simplified implementation
        BatteryStatus {
            state: PowerState::Plugged,
            percentage: Some(100),
            time_remaining_mins: None,
            charging: false,
        }
    }
    
    #[cfg(target_os = "windows")]
    fn get_battery_windows(&self) -> BatteryStatus {
        // Use GetSystemPowerStatus
        BatteryStatus {
            state: PowerState::Plugged,
            percentage: Some(100),
            time_remaining_mins: None,
            charging: false,
        }
    }
    
    #[cfg(target_os = "linux")]
    fn get_battery_linux(&self) -> BatteryStatus {
        // Read from /sys/class/power_supply
        let capacity_path = std::path::Path::new("/sys/class/power_supply/BAT0/capacity");
        let status_path = std::path::Path::new("/sys/class/power_supply/BAT0/status");
        
        let percentage = std::fs::read_to_string(capacity_path)
            .ok()
            .and_then(|s| s.trim().parse::<u8>().ok());
        
        let status = std::fs::read_to_string(status_path)
            .unwrap_or_default()
            .trim()
            .to_lowercase();
        
        let charging = status == "charging";
        let state = if status == "not charging" || charging {
            PowerState::Plugged
        } else if let Some(pct) = percentage {
            if pct < 5 {
                PowerState::CriticalBattery
            } else if pct < 20 {
                PowerState::LowBattery
            } else {
                PowerState::Battery
            }
        } else {
            PowerState::Unknown
        };
        
        BatteryStatus {
            state,
            percentage,
            time_remaining_mins: None,
            charging,
        }
    }
    
    /// Get recommended keepalive interval based on power state
    pub fn get_keepalive_interval(&self) -> u64 {
        let settings = self.settings.read();
        let status = self.get_battery_status();
        
        if !settings.battery_saver_enabled {
            return settings.plugged_keepalive_secs;
        }
        
        match status.state {
            PowerState::Plugged => settings.plugged_keepalive_secs,
            PowerState::Battery => settings.battery_keepalive_secs,
            PowerState::LowBattery => settings.battery_keepalive_secs * 2,
            PowerState::CriticalBattery => settings.battery_keepalive_secs * 3,
            PowerState::Unknown => settings.plugged_keepalive_secs,
        }
    }
    
    /// Check if posture checks should be paused
    pub fn should_pause_posture(&self) -> bool {
        let settings = self.settings.read();
        if !settings.pause_posture_on_battery {
            return false;
        }
        
        let status = self.get_battery_status();
        matches!(status.state, PowerState::Battery | PowerState::LowBattery | PowerState::CriticalBattery)
    }
    
    /// Check if should disconnect
    pub fn should_disconnect(&self) -> bool {
        let settings = self.settings.read();
        if !settings.disconnect_on_critical {
            return false;
        }
        
        let status = self.get_battery_status();
        status.state == PowerState::CriticalBattery
    }
    
    /// Update settings
    pub fn update_settings(&self, settings: PowerSettings) {
        *self.settings.write() = settings;
    }
}

impl Default for PowerManager {
    fn default() -> Self { Self::new(PowerSettings::default()) }
}
