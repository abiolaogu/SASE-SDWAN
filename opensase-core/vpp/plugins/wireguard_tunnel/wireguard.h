/*
 * OpenSASE WireGuard Tunnel Plugin
 *
 * Copyright (c) 2026 OpenSASE Project
 * Licensed under Apache 2.0
 *
 * High-performance WireGuard implementation for VPP.
 * Uses ChaCha20-Poly1305 for encryption with hardware acceleration.
 */

#ifndef __included_wireguard_tunnel_h__
#define __included_wireguard_tunnel_h__

#include <vnet/ip/ip.h>
#include <vnet/vnet.h>

/* WireGuard constants */
#define WG_KEY_LEN 32
#define WG_HASH_LEN 32
#define WG_MAC_LEN 16
#define WG_NONCE_LEN 8
#define WG_AEAD_LEN 16
#define WG_TIMESTAMP_LEN 12
#define WG_COOKIE_LEN 16

/* Maximum peers per tunnel */
#define WG_MAX_PEERS 256

/* Handshake timeout */
#define WG_REKEY_TIMEOUT 120
#define WG_REKEY_AFTER_MESSAGES ((1ULL << 60) - 1)
#define WG_REJECT_AFTER_MESSAGES ((1ULL << 64) - (1ULL << 13) - 1)
#define WG_REKEY_AFTER_TIME 120
#define WG_REJECT_AFTER_TIME 180
#define WG_KEEPALIVE_TIMEOUT 10

/* Message types */
typedef enum {
  WG_MSG_HANDSHAKE_INITIATION = 1,
  WG_MSG_HANDSHAKE_RESPONSE = 2,
  WG_MSG_HANDSHAKE_COOKIE = 3,
  WG_MSG_DATA = 4,
} wg_message_type_t;

/* WireGuard peer state */
typedef enum {
  WG_PEER_STATE_NEW = 0,
  WG_PEER_STATE_HANDSHAKE_SENT,
  WG_PEER_STATE_HANDSHAKE_RECEIVED,
  WG_PEER_STATE_ESTABLISHED,
  WG_PEER_STATE_EXPIRED,
} wg_peer_state_t;

/* Noise protocol keypair */
typedef struct {
  u8 private_key[WG_KEY_LEN];
  u8 public_key[WG_KEY_LEN];
} wg_keypair_t;

/* Ephemeral keypair for handshake */
typedef struct {
  u8 ephemeral_private[WG_KEY_LEN];
  u8 ephemeral_public[WG_KEY_LEN];
} wg_ephemeral_keys_t;

/* Session keys derived from Noise */
typedef struct {
  u8 sending_key[WG_KEY_LEN];
  u8 receiving_key[WG_KEY_LEN];
  u64 sending_counter;
  u64 receiving_counter;
  u32 sending_key_id;
  u32 receiving_key_id;
  f64 created_at;
  f64 last_sent;
  f64 last_received;
} wg_session_t;

/* WireGuard peer */
typedef struct {
  CLIB_CACHE_LINE_ALIGN_MARK(cache_line0);

  /* Peer identity */
  u8 public_key[WG_KEY_LEN];
  u8 preshared_key[WG_KEY_LEN]; /* Optional PSK */
  u8 has_preshared_key;

  /* Endpoint */
  ip46_address_t endpoint_addr;
  u16 endpoint_port;
  u8 endpoint_set;

  /* Allowed IPs (simplified - just one for now) */
  ip46_address_t allowed_ip;
  u8 allowed_ip_prefix;

  /* Session state */
  wg_peer_state_t state;
  wg_session_t current_session;
  wg_session_t previous_session;
  wg_ephemeral_keys_t ephemeral;

  /* Timers */
  f64 last_handshake_attempt;
  f64 last_handshake_complete;
  u32 handshake_attempts;

  /* Statistics */
  u64 tx_packets;
  u64 tx_bytes;
  u64 rx_packets;
  u64 rx_bytes;

  /* Local interface index */
  u32 if_index;
} wg_peer_t;

/* WireGuard tunnel interface */
typedef struct {
  CLIB_CACHE_LINE_ALIGN_MARK(cache_line0);

  /* Interface identity */
  u32 sw_if_index;
  u32 hw_if_index;

  /* Local keys */
  wg_keypair_t keypair;

  /* Listen port */
  u16 listen_port;

  /* Peers */
  wg_peer_t *peers;
  u32 n_peers;
  uword *peer_by_pubkey; /* Hash: pubkey -> peer index */

  /* UDP socket for handshakes */
  u32 udp_socket_index;

  /* Statistics */
  u64 total_tx_packets;
  u64 total_tx_bytes;
  u64 total_rx_packets;
  u64 total_rx_bytes;
} wg_tunnel_t;

/* Main WireGuard plugin data */
typedef struct {
  /* Tunnel interfaces */
  wg_tunnel_t *tunnels;
  uword *tunnel_by_sw_if_index;

  /* Convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /* API message base */
  u16 msg_id_base;

  /* Timer wheel for rekey */
  void *timer_wheel;
} wg_main_t;

extern wg_main_t wg_main;

/* Function declarations */
clib_error_t *wg_tunnel_init(vlib_main_t *vm);
int wg_tunnel_create(wg_keypair_t *keypair, u16 listen_port, u32 *sw_if_index);
int wg_tunnel_delete(u32 sw_if_index);
int wg_peer_add(u32 sw_if_index, u8 *public_key, ip46_address_t *endpoint,
                u16 port, ip46_address_t *allowed_ip, u8 prefix_len);
int wg_peer_remove(u32 sw_if_index, u8 *public_key);

/* Crypto operations */
void wg_noise_handshake_init(wg_peer_t *peer, wg_keypair_t *local);
void wg_noise_handshake_respond(wg_peer_t *peer, wg_keypair_t *local, u8 *msg,
                                u32 msg_len);
int wg_encrypt_packet(wg_session_t *session, vlib_buffer_t *b);
int wg_decrypt_packet(wg_session_t *session, vlib_buffer_t *b);

/* Node registration */
extern vlib_node_registration_t wg_input_node;
extern vlib_node_registration_t wg_output_node;
extern vlib_node_registration_t wg_handshake_node;

#endif /* __included_wireguard_tunnel_h__ */
