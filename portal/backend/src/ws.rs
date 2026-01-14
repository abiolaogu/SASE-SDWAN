//! WebSocket handling for real-time updates

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::time::{interval, Duration};
use crate::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct WsMessage {
    pub msg_type: String,
    pub data: serde_json::Value,
}

pub async fn handle_socket(mut socket: WebSocket, state: AppState) {
    // Send initial connection success
    let welcome = WsMessage {
        msg_type: "connected".into(),
        data: serde_json::json!({ "status": "ok" }),
    };
    
    if socket.send(Message::Text(serde_json::to_string(&welcome).unwrap())).await.is_err() {
        return;
    }

    // Start sending periodic updates
    let mut ticker = interval(Duration::from_secs(5));
    
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                // Send status update
                let update = WsMessage {
                    msg_type: "status_update".into(),
                    data: serde_json::json!({
                        "sites_online": 23,
                        "sites_warning": 1,
                        "sites_offline": 0,
                        "active_users": 1847,
                        "bandwidth_mbps": 4200,
                        "threats_blocked": 45,
                    }),
                };
                
                if socket.send(Message::Text(serde_json::to_string(&update).unwrap())).await.is_err() {
                    break;
                }
            }
            
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        // Handle incoming message
                        if let Ok(parsed) = serde_json::from_str::<WsMessage>(&text) {
                            match parsed.msg_type.as_str() {
                                "ping" => {
                                    let pong = WsMessage {
                                        msg_type: "pong".into(),
                                        data: serde_json::json!({}),
                                    };
                                    let _ = socket.send(Message::Text(serde_json::to_string(&pong).unwrap())).await;
                                }
                                "subscribe" => {
                                    // Subscribe to specific updates
                                    let ack = WsMessage {
                                        msg_type: "subscribed".into(),
                                        data: parsed.data,
                                    };
                                    let _ = socket.send(Message::Text(serde_json::to_string(&ack).unwrap())).await;
                                }
                                _ => {}
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }
}
