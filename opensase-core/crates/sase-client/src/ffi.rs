//! FFI Bindings
//!
//! C-compatible bindings for mobile and desktop UI integration.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

/// Initialize the client library
#[no_mangle]
pub extern "C" fn oscs_init(server_url: *const c_char, tenant_id: *const c_char) -> *mut crate::SaseClient {
    let server_url = unsafe {
        if server_url.is_null() { return std::ptr::null_mut(); }
        CStr::from_ptr(server_url).to_string_lossy().to_string()
    };
    
    let tenant_id = unsafe {
        if tenant_id.is_null() { return std::ptr::null_mut(); }
        CStr::from_ptr(tenant_id).to_string_lossy().to_string()
    };
    
    let config = crate::ClientConfig {
        server_url,
        tenant_id,
        device_id: uuid::Uuid::new_v4().to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        features: crate::ClientFeatures::default(),
        connection: crate::ConnectionSettings::default(),
    };
    
    let client = crate::SaseClient::new(config);
    Box::into_raw(Box::new(client))
}

/// Free the client instance
#[no_mangle]
pub extern "C" fn oscs_free(client: *mut crate::SaseClient) {
    if !client.is_null() {
        unsafe { drop(Box::from_raw(client)); }
    }
}

/// Connect to SASE network (async via callback)
#[no_mangle]
pub extern "C" fn oscs_connect(
    client: *mut crate::SaseClient,
    callback: extern "C" fn(success: bool, error: *const c_char),
) {
    if client.is_null() {
        let error = CString::new("Null client").unwrap();
        callback(false, error.as_ptr());
        return;
    }
    
    let client = unsafe { &*client };
    
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(client.connect());
        
        match result {
            Ok(_) => callback(true, std::ptr::null()),
            Err(e) => {
                let error = CString::new(e.to_string()).unwrap();
                callback(false, error.as_ptr());
            }
        }
    });
}

/// Disconnect from SASE network
#[no_mangle]
pub extern "C" fn oscs_disconnect(
    client: *mut crate::SaseClient,
    callback: extern "C" fn(success: bool, error: *const c_char),
) {
    if client.is_null() {
        let error = CString::new("Null client").unwrap();
        callback(false, error.as_ptr());
        return;
    }
    
    let client = unsafe { &*client };
    
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(client.disconnect());
        
        match result {
            Ok(_) => callback(true, std::ptr::null()),
            Err(e) => {
                let error = CString::new(e.to_string()).unwrap();
                callback(false, error.as_ptr());
            }
        }
    });
}

/// Get current connection state
#[no_mangle]
pub extern "C" fn oscs_get_state(client: *const crate::SaseClient) -> i32 {
    if client.is_null() { return -1; }
    
    let client = unsafe { &*client };
    match client.state() {
        crate::ClientState::Disconnected => 0,
        crate::ClientState::Connecting => 1,
        crate::ClientState::Authenticating => 2,
        crate::ClientState::PostureCheck => 3,
        crate::ClientState::Connected => 4,
        crate::ClientState::Reconnecting => 5,
        crate::ClientState::Error => 6,
    }
}

/// Get connection status as JSON
#[no_mangle]
pub extern "C" fn oscs_get_status_json(client: *const crate::SaseClient) -> *mut c_char {
    if client.is_null() { return std::ptr::null_mut(); }
    
    let client = unsafe { &*client };
    let status = client.status();
    
    match serde_json::to_string(&status) {
        Ok(json) => CString::new(json).unwrap().into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free a string returned by the library
#[no_mangle]
pub extern "C" fn oscs_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe { drop(CString::from_raw(s)); }
    }
}

/// Get posture as JSON
#[no_mangle]
pub extern "C" fn oscs_get_posture_json(
    client: *mut crate::SaseClient,
    callback: extern "C" fn(json: *const c_char),
) {
    if client.is_null() {
        callback(std::ptr::null());
        return;
    }
    
    let client = unsafe { &*client };
    
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(client.refresh_posture());
        
        match serde_json::to_string(&result) {
            Ok(json) => {
                let s = CString::new(json).unwrap();
                callback(s.as_ptr());
            }
            Err(_) => callback(std::ptr::null()),
        }
    });
}

/// Set event callback
#[no_mangle]
pub extern "C" fn oscs_set_event_callback(
    client: *mut crate::SaseClient,
    callback: extern "C" fn(event_json: *const c_char),
) {
    if client.is_null() { return; }
    
    let client = unsafe { &*client };
    let mut rx = client.subscribe();
    
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            while let Ok(event) = rx.recv().await {
                if let Ok(json) = serde_json::to_string(&event) {
                    let s = CString::new(json).unwrap();
                    callback(s.as_ptr());
                }
            }
        });
    });
}
