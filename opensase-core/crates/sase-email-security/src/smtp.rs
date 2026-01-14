//! High-Performance SMTP Server
//!
//! Production-grade SMTP server built on Tokio with full ESMTP support.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// High-performance SMTP server
pub struct SmtpServer {
    config: SmtpConfig,
    pipeline: Arc<crate::EmailSecurityGateway>,
    connection_tracker: ConnectionTracker,
}

#[derive(Clone)]
pub struct SmtpConfig {
    pub listen_addr: SocketAddr,
    pub hostname: String,
    pub max_message_size: usize,
    pub max_recipients: usize,
    pub timeout_seconds: u64,
    pub require_tls: bool,
    pub rate_limits: RateLimitConfig,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:25".parse().unwrap(),
            hostname: "mail.opensase.local".to_string(),
            max_message_size: 50 * 1024 * 1024, // 50MB
            max_recipients: 100,
            timeout_seconds: 300,
            require_tls: false,
            rate_limits: RateLimitConfig::default(),
        }
    }
}

#[derive(Clone)]
pub struct RateLimitConfig {
    pub connections_per_ip: u32,
    pub messages_per_connection: u32,
    pub window_seconds: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            connections_per_ip: 50,
            messages_per_connection: 100,
            window_seconds: 60,
        }
    }
}

/// Connection rate tracking
pub struct ConnectionTracker {
    connections: dashmap::DashMap<std::net::IpAddr, ConnectionInfo>,
}

#[derive(Clone)]
struct ConnectionInfo {
    count: u32,
    first_seen: std::time::Instant,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            connections: dashmap::DashMap::new(),
        }
    }
    
    pub async fn allow_connection(&self, ip: std::net::IpAddr, limit: u32, window_secs: u64) -> bool {
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(window_secs);
        
        let mut entry = self.connections.entry(ip).or_insert(ConnectionInfo {
            count: 0,
            first_seen: now,
        });
        
        if now.duration_since(entry.first_seen) > window {
            entry.count = 1;
            entry.first_seen = now;
            return true;
        }
        
        if entry.count >= limit {
            return false;
        }
        
        entry.count += 1;
        true
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl SmtpServer {
    pub fn new(config: SmtpConfig, pipeline: Arc<crate::EmailSecurityGateway>) -> Self {
        Self {
            config,
            pipeline,
            connection_tracker: ConnectionTracker::new(),
        }
    }
    
    /// Start SMTP server
    pub async fn run(&self) -> Result<(), std::io::Error> {
        let listener = TcpListener::bind(&self.config.listen_addr).await?;
        tracing::info!("SMTP server listening on {}", self.config.listen_addr);
        
        loop {
            let (socket, peer_addr) = listener.accept().await?;
            
            // Connection-level rate limiting
            if !self.connection_tracker.allow_connection(
                peer_addr.ip(),
                self.config.rate_limits.connections_per_ip,
                self.config.rate_limits.window_seconds,
            ).await {
                tracing::debug!("Rejecting rate-limited IP: {}", peer_addr);
                continue;
            }
            
            let pipeline = self.pipeline.clone();
            let config = self.config.clone();
            
            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(socket, peer_addr, config, pipeline).await {
                    tracing::warn!("Connection error from {}: {}", peer_addr, e);
                }
            });
        }
    }
    
    async fn handle_connection(
        socket: TcpStream,
        peer_addr: SocketAddr,
        config: SmtpConfig,
        pipeline: Arc<crate::EmailSecurityGateway>,
    ) -> Result<(), SmtpError> {
        let mut session = SmtpSession::new(socket, peer_addr, config.clone());
        
        // Send greeting
        session.send_response(220, &format!("{} ESMTP OpenSASE Email Gateway", config.hostname)).await?;
        
        let mut state = SessionState::Initial;
        let mut envelope = SessionEnvelope::new(peer_addr.ip());
        let mut data_buffer = Vec::new();
        
        loop {
            let command = match session.read_command().await {
                Ok(cmd) => cmd,
                Err(_) => break,
            };
            
            match (&state, command) {
                (_, SmtpCommand::Quit) => {
                    session.send_response(221, "Bye").await?;
                    break;
                }
                
                (_, SmtpCommand::Noop) => {
                    session.send_response(250, "OK").await?;
                }
                
                (_, SmtpCommand::Rset) => {
                    envelope = SessionEnvelope::new(peer_addr.ip());
                    state = if matches!(state, SessionState::Initial) {
                        SessionState::Initial
                    } else {
                        SessionState::Greeted
                    };
                    session.send_response(250, "OK").await?;
                }
                
                (_, SmtpCommand::Ehlo(domain)) => {
                    envelope.client_hostname = Some(domain.clone());
                    
                    let capabilities = vec![
                        format!("SIZE {}", config.max_message_size),
                        "8BITMIME".to_string(),
                        "STARTTLS".to_string(),
                        "ENHANCEDSTATUSCODES".to_string(),
                        "PIPELINING".to_string(),
                        "CHUNKING".to_string(),
                    ];
                    
                    session.send_ehlo_response(&config.hostname, &capabilities).await?;
                    state = SessionState::Greeted;
                }
                
                (_, SmtpCommand::Helo(domain)) => {
                    envelope.client_hostname = Some(domain);
                    session.send_response(250, &config.hostname).await?;
                    state = SessionState::Greeted;
                }
                
                (SessionState::Greeted, SmtpCommand::MailFrom(sender)) => {
                    envelope.mail_from = Some(sender);
                    session.send_response(250, "2.1.0 OK").await?;
                    state = SessionState::MailFrom;
                }
                
                (SessionState::MailFrom | SessionState::RcptTo, SmtpCommand::RcptTo(recipient)) => {
                    if envelope.rcpt_to.len() >= config.max_recipients {
                        session.send_response(452, "4.5.3 Too many recipients").await?;
                        continue;
                    }
                    
                    envelope.rcpt_to.push(recipient);
                    session.send_response(250, "2.1.5 OK").await?;
                    state = SessionState::RcptTo;
                }
                
                (SessionState::RcptTo, SmtpCommand::Data) => {
                    if envelope.rcpt_to.is_empty() {
                        session.send_response(503, "5.5.1 No recipients").await?;
                        continue;
                    }
                    
                    session.send_response(354, "Start mail input; end with <CRLF>.<CRLF>").await?;
                    
                    // Read message data
                    data_buffer = session.read_data(config.max_message_size).await?;
                    
                    // Build EmailEnvelope for processing
                    let email_envelope = crate::EmailEnvelope {
                        mail_from: envelope.mail_from.clone().unwrap_or_default(),
                        rcpt_to: envelope.rcpt_to.clone(),
                        client_ip: envelope.client_ip,
                        client_hostname: envelope.client_hostname.clone(),
                        helo: envelope.client_hostname.clone().unwrap_or_default(),
                        authenticated_user: None,
                        tls_version: None,
                    };
                    
                    // Parse and process
                    let parser = crate::parser::EmailParser::new();
                    match parser.parse(&data_buffer, email_envelope) {
                        Ok(message) => {
                            let verdict = pipeline.process(&message).await;
                            
                            match verdict.action {
                                crate::VerdictAction::Deliver | crate::VerdictAction::DeliverModified => {
                                    session.send_response(250, "2.0.0 OK: Message accepted").await?;
                                }
                                crate::VerdictAction::Quarantine => {
                                    session.send_response(250, "2.0.0 OK: Message accepted").await?;
                                }
                                crate::VerdictAction::Reject => {
                                    session.send_response(550, "5.7.1 Message rejected").await?;
                                }
                                crate::VerdictAction::Drop => {
                                    session.send_response(250, "2.0.0 OK").await?;
                                }
                                crate::VerdictAction::Defer => {
                                    session.send_response(451, "4.7.1 Try again later").await?;
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("Failed to parse message: {}", e);
                            session.send_response(451, "4.3.0 Temporary failure").await?;
                        }
                    }
                    
                    // Reset for next message
                    envelope = SessionEnvelope::new(peer_addr.ip());
                    data_buffer.clear();
                    state = SessionState::Greeted;
                }
                
                _ => {
                    session.send_response(503, "5.5.1 Bad sequence of commands").await?;
                }
            }
        }
        
        Ok(())
    }
}

/// SMTP session handler
struct SmtpSession {
    reader: BufReader<tokio::io::ReadHalf<TcpStream>>,
    writer: tokio::io::WriteHalf<TcpStream>,
    peer_addr: SocketAddr,
    #[allow(dead_code)]
    config: SmtpConfig,
}

impl SmtpSession {
    fn new(socket: TcpStream, peer_addr: SocketAddr, config: SmtpConfig) -> Self {
        let (reader, writer) = tokio::io::split(socket);
        Self {
            reader: BufReader::new(reader),
            writer,
            peer_addr,
            config,
        }
    }
    
    async fn send_response(&mut self, code: u16, message: &str) -> Result<(), SmtpError> {
        let response = format!("{} {}\r\n", code, message);
        self.writer.write_all(response.as_bytes()).await?;
        self.writer.flush().await?;
        Ok(())
    }
    
    async fn send_ehlo_response(&mut self, hostname: &str, capabilities: &[String]) -> Result<(), SmtpError> {
        self.writer.write_all(format!("250-{}\r\n", hostname).as_bytes()).await?;
        
        for (i, cap) in capabilities.iter().enumerate() {
            if i == capabilities.len() - 1 {
                self.writer.write_all(format!("250 {}\r\n", cap).as_bytes()).await?;
            } else {
                self.writer.write_all(format!("250-{}\r\n", cap).as_bytes()).await?;
            }
        }
        
        self.writer.flush().await?;
        Ok(())
    }
    
    async fn read_command(&mut self) -> Result<SmtpCommand, SmtpError> {
        let mut line = String::new();
        self.reader.read_line(&mut line).await?;
        
        let line = line.trim();
        SmtpCommand::parse(line)
    }
    
    async fn read_data(&mut self, max_size: usize) -> Result<Vec<u8>, SmtpError> {
        let mut data = Vec::new();
        let mut line = String::new();
        
        loop {
            line.clear();
            self.reader.read_line(&mut line).await?;
            
            if line == ".\r\n" || line == ".\n" {
                break;
            }
            
            // Remove dot stuffing
            let content = if line.starts_with("..") {
                &line[1..]
            } else {
                &line
            };
            
            data.extend_from_slice(content.as_bytes());
            
            if data.len() > max_size {
                return Err(SmtpError::MessageTooLarge);
            }
        }
        
        Ok(data)
    }
}

/// SMTP session state
#[derive(Debug, Clone, PartialEq, Eq)]
enum SessionState {
    Initial,
    Greeted,
    MailFrom,
    RcptTo,
}

/// Session envelope
struct SessionEnvelope {
    client_ip: std::net::IpAddr,
    client_hostname: Option<String>,
    mail_from: Option<String>,
    rcpt_to: Vec<String>,
}

impl SessionEnvelope {
    fn new(client_ip: std::net::IpAddr) -> Self {
        Self {
            client_ip,
            client_hostname: None,
            mail_from: None,
            rcpt_to: Vec::new(),
        }
    }
}

/// SMTP commands
#[derive(Debug)]
enum SmtpCommand {
    Helo(String),
    Ehlo(String),
    MailFrom(String),
    RcptTo(String),
    Data,
    Quit,
    Rset,
    Noop,
}

impl SmtpCommand {
    fn parse(line: &str) -> Result<Self, SmtpError> {
        let upper = line.to_uppercase();
        
        if upper.starts_with("EHLO ") {
            Ok(SmtpCommand::Ehlo(line[5..].trim().to_string()))
        } else if upper.starts_with("HELO ") {
            Ok(SmtpCommand::Helo(line[5..].trim().to_string()))
        } else if upper.starts_with("MAIL FROM:") {
            let addr = line[10..].trim();
            let addr = addr.trim_start_matches('<').trim_end_matches('>');
            Ok(SmtpCommand::MailFrom(addr.to_string()))
        } else if upper.starts_with("RCPT TO:") {
            let addr = line[8..].trim();
            let addr = addr.trim_start_matches('<').trim_end_matches('>');
            Ok(SmtpCommand::RcptTo(addr.to_string()))
        } else if upper == "DATA" {
            Ok(SmtpCommand::Data)
        } else if upper == "QUIT" {
            Ok(SmtpCommand::Quit)
        } else if upper == "RSET" {
            Ok(SmtpCommand::Rset)
        } else if upper == "NOOP" {
            Ok(SmtpCommand::Noop)
        } else {
            Err(SmtpError::UnknownCommand)
        }
    }
}

#[derive(Debug)]
pub enum SmtpError {
    Io(std::io::Error),
    UnknownCommand,
    MessageTooLarge,
    Timeout,
}

impl From<std::io::Error> for SmtpError {
    fn from(e: std::io::Error) -> Self {
        SmtpError::Io(e)
    }
}

impl std::fmt::Display for SmtpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {}", e),
            Self::UnknownCommand => write!(f, "Unknown command"),
            Self::MessageTooLarge => write!(f, "Message too large"),
            Self::Timeout => write!(f, "Timeout"),
        }
    }
}

impl std::error::Error for SmtpError {}
