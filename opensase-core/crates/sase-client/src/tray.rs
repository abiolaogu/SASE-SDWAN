//! System Tray and UI Integration
//!
//! Cross-platform system tray and notification support.

use serde::{Deserialize, Serialize};

/// UI Service for system tray and notifications
pub struct UiService {
    tray_state: parking_lot::RwLock<TrayState>,
    menu_items: parking_lot::RwLock<Vec<MenuItem>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TrayState {
    pub icon: TrayIcon,
    pub tooltip: String,
    pub visible: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrayIcon {
    Connected,
    Disconnected,
    Connecting,
    Error,
    PostureWarning,
}

#[derive(Clone, Debug, Serialize)]
pub struct MenuItem {
    pub id: String,
    pub label: String,
    pub enabled: bool,
    pub checked: Option<bool>,
    pub submenu: Option<Vec<MenuItem>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Notification {
    pub title: String,
    pub message: String,
    pub icon: NotificationIcon,
    pub actions: Vec<NotificationAction>,
    pub timeout_ms: Option<u32>,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub enum NotificationIcon {
    Info,
    Warning,
    Error,
    Success,
}

#[derive(Clone, Debug, Serialize)]
pub struct NotificationAction {
    pub id: String,
    pub label: String,
}

impl UiService {
    pub fn new() -> Self {
        Self {
            tray_state: parking_lot::RwLock::new(TrayState {
                icon: TrayIcon::Disconnected,
                tooltip: "OpenSASE - Disconnected".to_string(),
                visible: true,
            }),
            menu_items: parking_lot::RwLock::new(Self::default_menu()),
        }
    }
    
    fn default_menu() -> Vec<MenuItem> {
        vec![
            MenuItem {
                id: "status".to_string(),
                label: "Status: Disconnected".to_string(),
                enabled: false,
                checked: None,
                submenu: None,
            },
            MenuItem {
                id: "separator1".to_string(),
                label: "-".to_string(),
                enabled: false,
                checked: None,
                submenu: None,
            },
            MenuItem {
                id: "connect".to_string(),
                label: "Connect".to_string(),
                enabled: true,
                checked: None,
                submenu: None,
            },
            MenuItem {
                id: "disconnect".to_string(),
                label: "Disconnect".to_string(),
                enabled: false,
                checked: None,
                submenu: None,
            },
            MenuItem {
                id: "separator2".to_string(),
                label: "-".to_string(),
                enabled: false,
                checked: None,
                submenu: None,
            },
            MenuItem {
                id: "settings".to_string(),
                label: "Settings...".to_string(),
                enabled: true,
                checked: None,
                submenu: None,
            },
            MenuItem {
                id: "diagnostics".to_string(),
                label: "Diagnostics...".to_string(),
                enabled: true,
                checked: None,
                submenu: None,
            },
            MenuItem {
                id: "logs".to_string(),
                label: "View Logs...".to_string(),
                enabled: true,
                checked: None,
                submenu: None,
            },
            MenuItem {
                id: "separator3".to_string(),
                label: "-".to_string(),
                enabled: false,
                checked: None,
                submenu: None,
            },
            MenuItem {
                id: "about".to_string(),
                label: "About OpenSASE".to_string(),
                enabled: true,
                checked: None,
                submenu: None,
            },
            MenuItem {
                id: "quit".to_string(),
                label: "Quit".to_string(),
                enabled: true,
                checked: None,
                submenu: None,
            },
        ]
    }
    
    pub fn set_icon(&self, icon: TrayIcon) {
        let mut state = self.tray_state.write();
        state.icon = icon;
        state.tooltip = match icon {
            TrayIcon::Connected => "OpenSASE - Connected".to_string(),
            TrayIcon::Disconnected => "OpenSASE - Disconnected".to_string(),
            TrayIcon::Connecting => "OpenSASE - Connecting...".to_string(),
            TrayIcon::Error => "OpenSASE - Error".to_string(),
            TrayIcon::PostureWarning => "OpenSASE - Posture Warning".to_string(),
        };
    }
    
    pub fn set_connected(&self, connected: bool, server: Option<&str>) {
        self.set_icon(if connected { TrayIcon::Connected } else { TrayIcon::Disconnected });
        
        let mut items = self.menu_items.write();
        for item in items.iter_mut() {
            match item.id.as_str() {
                "status" => {
                    item.label = if connected {
                        format!("Connected to {}", server.unwrap_or("server"))
                    } else {
                        "Status: Disconnected".to_string()
                    };
                }
                "connect" => item.enabled = !connected,
                "disconnect" => item.enabled = connected,
                _ => {}
            }
        }
    }
    
    pub fn get_tray_state(&self) -> TrayState {
        self.tray_state.read().clone()
    }
    
    pub fn get_menu_items(&self) -> Vec<MenuItem> {
        self.menu_items.read().clone()
    }
    
    pub async fn show_notification(&self, notification: Notification) {
        let platform = crate::platform::get_platform();
        let _ = platform.show_notification(&notification.title, &notification.message).await;
    }
    
    pub async fn notify_connected(&self, server: &str) {
        self.show_notification(Notification {
            title: "OpenSASE Connected".to_string(),
            message: format!("Securely connected to {}", server),
            icon: NotificationIcon::Success,
            actions: vec![],
            timeout_ms: Some(5000),
        }).await;
    }
    
    pub async fn notify_disconnected(&self, reason: &str) {
        self.show_notification(Notification {
            title: "OpenSASE Disconnected".to_string(),
            message: reason.to_string(),
            icon: NotificationIcon::Warning,
            actions: vec![
                NotificationAction {
                    id: "reconnect".to_string(),
                    label: "Reconnect".to_string(),
                },
            ],
            timeout_ms: Some(10000),
        }).await;
    }
    
    pub async fn notify_posture_warning(&self, issues: &[String]) {
        self.show_notification(Notification {
            title: "Posture Compliance Warning".to_string(),
            message: format!("Issues found: {}", issues.join(", ")),
            icon: NotificationIcon::Warning,
            actions: vec![
                NotificationAction {
                    id: "view".to_string(),
                    label: "View Details".to_string(),
                },
            ],
            timeout_ms: Some(15000),
        }).await;
    }
}

impl Default for UiService {
    fn default() -> Self { Self::new() }
}
