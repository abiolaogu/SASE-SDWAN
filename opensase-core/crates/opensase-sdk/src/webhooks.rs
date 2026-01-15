//! Webhook verification
use hmac::{Hmac, Mac};
use sha2::Sha256;
use crate::error::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

/// Verify webhook signature
pub fn verify_webhook(payload: &[u8], signature: &str, secret: &str, tolerance_secs: i64) -> Result<bool> {
    let parts: Vec<&str> = signature.split(',').collect();
    let ts = parts.iter().find(|p| p.starts_with("t=")).map(|p| &p[2..]).ok_or(Error::InvalidSignature)?;
    let sig = parts.iter().find(|p| p.starts_with("v1=")).map(|p| &p[3..]).ok_or(Error::InvalidSignature)?;
    
    let ts_num: i64 = ts.parse().map_err(|_| Error::InvalidSignature)?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    if (now - ts_num).abs() > tolerance_secs { return Err(Error::InvalidSignature); }
    
    let to_sign = format!("{}.{}", ts, String::from_utf8_lossy(payload));
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(to_sign.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());
    
    Ok(expected == sig)
}
