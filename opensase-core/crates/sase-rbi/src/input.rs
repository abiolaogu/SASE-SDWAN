//! Input Handling
//!
//! User input event processing and validation.

use crate::{InputEvent, MouseButton, Modifiers, Touch};

/// Input validator and sanitizer
pub struct InputHandler {
    config: InputConfig,
    rate_limiter: InputRateLimiter,
}

#[derive(Debug, Clone)]
pub struct InputConfig {
    /// Max mouse events per second
    pub max_mouse_events_per_sec: u32,
    /// Max keyboard events per second
    pub max_keyboard_events_per_sec: u32,
    /// Max paste size
    pub max_paste_size: usize,
    /// Allowed key combinations
    pub blocked_key_combos: Vec<KeyCombo>,
    /// Enable right-click
    pub right_click_enabled: bool,
}

impl Default for InputConfig {
    fn default() -> Self {
        Self {
            max_mouse_events_per_sec: 120,
            max_keyboard_events_per_sec: 60,
            max_paste_size: 100_000,
            blocked_key_combos: default_blocked_combos(),
            right_click_enabled: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct KeyCombo {
    pub key: String,
    pub modifiers: Modifiers,
}

struct InputRateLimiter {
    mouse_count: std::sync::atomic::AtomicU64,
    key_count: std::sync::atomic::AtomicU64,
    last_reset: parking_lot::Mutex<std::time::Instant>,
}

impl InputRateLimiter {
    fn new() -> Self {
        Self {
            mouse_count: std::sync::atomic::AtomicU64::new(0),
            key_count: std::sync::atomic::AtomicU64::new(0),
            last_reset: parking_lot::Mutex::new(std::time::Instant::now()),
        }
    }
    
    fn check_mouse(&self, max: u32) -> bool {
        self.maybe_reset();
        let count = self.mouse_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        count < max as u64
    }
    
    fn check_key(&self, max: u32) -> bool {
        self.maybe_reset();
        let count = self.key_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        count < max as u64
    }
    
    fn maybe_reset(&self) {
        let mut last = self.last_reset.lock();
        if last.elapsed() > std::time::Duration::from_secs(1) {
            self.mouse_count.store(0, std::sync::atomic::Ordering::Relaxed);
            self.key_count.store(0, std::sync::atomic::Ordering::Relaxed);
            *last = std::time::Instant::now();
        }
    }
}

impl InputHandler {
    pub fn new(config: InputConfig) -> Self {
        Self {
            config,
            rate_limiter: InputRateLimiter::new(),
        }
    }
    
    /// Validate and sanitize input event
    pub fn process(&self, event: InputEvent) -> Result<InputEvent, InputError> {
        match &event {
            InputEvent::MouseMove { .. } |
            InputEvent::MouseDown { .. } |
            InputEvent::MouseUp { .. } |
            InputEvent::Click { .. } |
            InputEvent::DoubleClick { .. } |
            InputEvent::Scroll { .. } => {
                self.validate_mouse(&event)?;
            }
            InputEvent::KeyDown { key, modifiers, .. } |
            InputEvent::KeyUp { key, modifiers, .. } |
            InputEvent::KeyPress { key, modifiers, .. } => {
                self.validate_key(key, modifiers)?;
            }
            InputEvent::Paste { text } => {
                self.validate_paste(text)?;
            }
            _ => {}
        }
        
        Ok(event)
    }
    
    fn validate_mouse(&self, event: &InputEvent) -> Result<(), InputError> {
        // Check rate limit
        if !self.rate_limiter.check_mouse(self.config.max_mouse_events_per_sec) {
            return Err(InputError::RateLimited);
        }
        
        // Check right-click
        if let InputEvent::Click { button: MouseButton::Right, .. } |
               InputEvent::MouseDown { button: MouseButton::Right, .. } = event {
            if !self.config.right_click_enabled {
                return Err(InputError::Blocked("Right-click disabled".to_string()));
            }
        }
        
        Ok(())
    }
    
    fn validate_key(&self, key: &str, modifiers: &Modifiers) -> Result<(), InputError> {
        // Check rate limit
        if !self.rate_limiter.check_key(self.config.max_keyboard_events_per_sec) {
            return Err(InputError::RateLimited);
        }
        
        // Check blocked combos
        for combo in &self.config.blocked_key_combos {
            if combo.key.to_lowercase() == key.to_lowercase() &&
               combo.modifiers.ctrl == modifiers.ctrl &&
               combo.modifiers.alt == modifiers.alt &&
               combo.modifiers.shift == modifiers.shift &&
               combo.modifiers.meta == modifiers.meta {
                return Err(InputError::Blocked(format!("Key combo blocked: {}", key)));
            }
        }
        
        Ok(())
    }
    
    fn validate_paste(&self, text: &str) -> Result<(), InputError> {
        if text.len() > self.config.max_paste_size {
            return Err(InputError::TooLarge(text.len(), self.config.max_paste_size));
        }
        Ok(())
    }
}

impl Default for InputHandler {
    fn default() -> Self {
        Self::new(InputConfig::default())
    }
}

#[derive(Debug, Clone)]
pub enum InputError {
    RateLimited,
    Blocked(String),
    TooLarge(usize, usize),
    Invalid(String),
}

impl std::fmt::Display for InputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RateLimited => write!(f, "Input rate limited"),
            Self::Blocked(reason) => write!(f, "Input blocked: {}", reason),
            Self::TooLarge(size, max) => write!(f, "Input too large: {} > {}", size, max),
            Self::Invalid(reason) => write!(f, "Invalid input: {}", reason),
        }
    }
}

fn default_blocked_combos() -> Vec<KeyCombo> {
    vec![
        // Block F12 (DevTools)
        KeyCombo { key: "F12".to_string(), modifiers: Modifiers::default() },
        // Block Ctrl+Shift+I (DevTools)
        KeyCombo { 
            key: "i".to_string(), 
            modifiers: Modifiers { ctrl: true, shift: true, ..Default::default() } 
        },
        // Block Ctrl+Shift+J (Console)
        KeyCombo { 
            key: "j".to_string(), 
            modifiers: Modifiers { ctrl: true, shift: true, ..Default::default() } 
        },
        // Block Ctrl+U (View Source)
        KeyCombo { 
            key: "u".to_string(), 
            modifiers: Modifiers { ctrl: true, ..Default::default() } 
        },
    ]
}
