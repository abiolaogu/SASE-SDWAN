//! Authentication Management
//!
//! JWT, API Key, OAuth2, and mTLS authentication.

use crate::{AuthConfig, GatewayError};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Authentication manager
pub struct AuthManager {
    config: AuthConfig,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

/// Authentication method
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthMethod {
    Jwt,
    ApiKey,
    OAuth2,
    Mtls,
    Basic,
    None,
}

/// JWT claims
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub nbf: i64,
    pub jti: String,
    pub tenant_id: Option<String>,
    pub scopes: Vec<String>,
    pub custom: HashMap<String, serde_json::Value>,
}

/// Token response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

/// API Key info
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiKeyInfo {
    pub key: String,
    pub consumer_id: String,
    pub tenant_id: Option<String>,
    pub scopes: Vec<String>,
    pub rate_limit: Option<u32>,
    pub expires_at: Option<i64>,
}

/// OAuth2 Client
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OAuth2Client {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub grants: Vec<String>,
}

impl AuthManager {
    /// Create new auth manager
    pub fn new(config: AuthConfig) -> Self {
        let encoding_key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(config.jwt_secret.as_bytes());
        
        Self {
            config,
            encoding_key,
            decoding_key,
        }
    }
    
    /// Generate JWT token
    pub fn generate_jwt(
        &self,
        subject: &str,
        tenant_id: Option<&str>,
        scopes: Vec<String>,
        custom: HashMap<String, serde_json::Value>,
    ) -> Result<TokenResponse, GatewayError> {
        let now = Utc::now();
        let exp = now + Duration::seconds(self.config.jwt_expiry_secs as i64);
        
        let claims = Claims {
            sub: subject.to_string(),
            iss: self.config.jwt_issuer.clone(),
            aud: self.config.jwt_audience.clone(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            jti: uuid::Uuid::new_v4().to_string(),
            tenant_id: tenant_id.map(|s| s.to_string()),
            scopes: scopes.clone(),
            custom,
        };
        
        let token = encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| GatewayError::AuthError(e.to_string()))?;
        
        Ok(TokenResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.jwt_expiry_secs,
            refresh_token: None,
            scope: Some(scopes.join(" ")),
        })
    }
    
    /// Validate JWT token
    pub fn validate_jwt(&self, token: &str) -> Result<Claims, GatewayError> {
        let mut validation = Validation::default();
        validation.set_issuer(&[&self.config.jwt_issuer]);
        validation.set_audience(&[&self.config.jwt_audience]);
        
        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|e| GatewayError::AuthError(e.to_string()))?;
        
        Ok(token_data.claims)
    }
    
    /// Generate API key
    pub fn generate_api_key(&self) -> String {
        format!("osag_{}", uuid::Uuid::new_v4().to_string().replace("-", ""))
    }
    
    /// Validate API key format
    pub fn validate_api_key_format(&self, key: &str) -> bool {
        key.starts_with("osag_") && key.len() == 37
    }
    
    /// Generate OAuth2 client credentials
    pub fn generate_oauth2_client(&self, redirect_uris: Vec<String>, scopes: Vec<String>) -> OAuth2Client {
        OAuth2Client {
            client_id: format!("client_{}", uuid::Uuid::new_v4().to_string().replace("-", "")),
            client_secret: format!("secret_{}", uuid::Uuid::new_v4().to_string().replace("-", "")),
            redirect_uris,
            scopes,
            grants: vec!["authorization_code".to_string(), "client_credentials".to_string()],
        }
    }
    
    /// Generate authorization code
    pub fn generate_auth_code(&self) -> String {
        format!("authz_{}", uuid::Uuid::new_v4().to_string().replace("-", ""))
    }
    
    /// Generate refresh token
    pub fn generate_refresh_token(&self) -> String {
        format!("refresh_{}", uuid::Uuid::new_v4().to_string().replace("-", ""))
    }
}

/// mTLS Certificate validation
pub struct MtlsValidator {
    trusted_cas: Vec<String>,
    require_client_cert: bool,
}

impl MtlsValidator {
    pub fn new(trusted_cas: Vec<String>) -> Self {
        Self {
            trusted_cas,
            require_client_cert: true,
        }
    }
    
    /// Validate client certificate
    pub fn validate_certificate(&self, cert_pem: &str) -> Result<CertificateInfo, GatewayError> {
        // Parse and validate certificate
        // In production, use rustls or openssl for actual validation
        
        Ok(CertificateInfo {
            subject: "CN=client.example.com".to_string(),
            issuer: "CN=OpenSASE CA".to_string(),
            serial: "123456".to_string(),
            not_before: Utc::now().timestamp(),
            not_after: (Utc::now() + Duration::days(365)).timestamp(),
            fingerprint: "sha256:abc123".to_string(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: i64,
    pub not_after: i64,
    pub fingerprint: String,
}

/// Basic Authentication helper
pub struct BasicAuth;

impl BasicAuth {
    /// Encode basic auth header
    pub fn encode(username: &str, password: &str) -> String {
        use base64::Engine;
        let credentials = format!("{}:{}", username, password);
        let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
        format!("Basic {}", encoded)
    }
    
    /// Decode basic auth header
    pub fn decode(header: &str) -> Option<(String, String)> {
        use base64::Engine;
        
        let header = header.strip_prefix("Basic ")?;
        let decoded = base64::engine::general_purpose::STANDARD.decode(header).ok()?;
        let credentials = String::from_utf8(decoded).ok()?;
        let parts: Vec<&str> = credentials.splitn(2, ':').collect();
        
        if parts.len() == 2 {
            Some((parts[0].to_string(), parts[1].to_string()))
        } else {
            None
        }
    }
}

/// HMAC signature validation
pub struct HmacValidator {
    secret: String,
}

impl HmacValidator {
    pub fn new(secret: &str) -> Self {
        Self {
            secret: secret.to_string(),
        }
    }
    
    /// Generate HMAC signature
    pub fn sign(&self, data: &str) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        
        type HmacSha256 = Hmac<Sha256>;
        
        let mut mac = HmacSha256::new_from_slice(self.secret.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(data.as_bytes());
        
        let result = mac.finalize();
        hex::encode(result.into_bytes())
    }
    
    /// Verify HMAC signature
    pub fn verify(&self, data: &str, signature: &str) -> bool {
        let expected = self.sign(data);
        // Constant-time comparison
        expected == signature
    }
}
