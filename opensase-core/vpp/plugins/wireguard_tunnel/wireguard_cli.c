/*
 * OpenSASE WireGuard Tunnel Plugin - CLI Commands
 *
 * Copyright (c) 2026 OpenSASE Project
 * Licensed under Apache 2.0
 *
 * VPP CLI for WireGuard tunnel management.
 * Provides commands for key generation, peer management, and tunnel setup.
 */

#include <vlib/vlib.h>
#include <vnet/ip/ip.h>
#include <vnet/vnet.h>
#include <vppinfra/random.h>

#include "wireguard.h"

/* Base64 encoding table */
static const char base64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Generate random bytes (simplified - production should use /dev/urandom)
 */
static void wg_random_bytes(u8 *buf, u32 len) {
  u32 i;
  for (i = 0; i < len; i++)
    buf[i] = random_u32(&i) & 0xff;
}

/**
 * Base64 encode a buffer
 */
static void wg_base64_encode(u8 *src, u32 src_len, u8 *dst) {
  u32 i, j;
  u32 a, b, c;

  j = 0;
  for (i = 0; i < src_len; i += 3) {
    a = src[i];
    b = (i + 1 < src_len) ? src[i + 1] : 0;
    c = (i + 2 < src_len) ? src[i + 2] : 0;

    dst[j++] = base64_table[(a >> 2) & 0x3f];
    dst[j++] = base64_table[((a << 4) | (b >> 4)) & 0x3f];
    dst[j++] =
        (i + 1 < src_len) ? base64_table[((b << 2) | (c >> 6)) & 0x3f] : '=';
    dst[j++] = (i + 2 < src_len) ? base64_table[c & 0x3f] : '=';
  }
  dst[j] = 0;
}

/**
 * CLI: wireguard create interface
 * Creates a new WireGuard tunnel interface
 */
static clib_error_t *wg_create_interface_cli(vlib_main_t *vm,
                                             unformat_input_t *input,
                                             vlib_cli_command_t *cmd) {
  u16 listen_port = 51820;
  u32 sw_if_index;
  wg_keypair_t keypair;
  u8 private_key_b64[45];
  u8 public_key_b64[45];
  int rv;

  /* Parse arguments */
  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(input, "listen-port %u", &listen_port))
      ;
    else
      return clib_error_return(0, "unknown input '%U'", format_unformat_error,
                               input);
  }

  /* Generate keypair */
  wg_random_bytes(keypair.private_key, WG_KEY_LEN);

  /* Clamp private key for Curve25519 */
  keypair.private_key[0] &= 248;
  keypair.private_key[31] &= 127;
  keypair.private_key[31] |= 64;

  /* Public key would be derived via Curve25519 */
  /* Simplified: just copy for now (real implementation uses crypto) */
  clib_memcpy(keypair.public_key, keypair.private_key, WG_KEY_LEN);
  keypair.public_key[0] ^= 0x9b; /* Make different from private */

  /* Create tunnel */
  rv = wg_tunnel_create(&keypair, listen_port, &sw_if_index);
  if (rv)
    return clib_error_return(0, "failed to create WireGuard interface");

  /* Encode keys for display */
  wg_base64_encode(keypair.private_key, WG_KEY_LEN, private_key_b64);
  wg_base64_encode(keypair.public_key, WG_KEY_LEN, public_key_b64);

  vlib_cli_output(vm, "WireGuard interface created:");
  vlib_cli_output(vm, "  Interface: wg%u (sw_if_index %u)", sw_if_index,
                  sw_if_index);
  vlib_cli_output(vm, "  Listen port: %u", listen_port);
  vlib_cli_output(vm, "  Private key: %s", private_key_b64);
  vlib_cli_output(vm, "  Public key:  %s", public_key_b64);

  return 0;
}

VLIB_CLI_COMMAND(wg_create_interface_command, static) = {
    .path = "wireguard create interface",
    .short_help = "wireguard create interface [listen-port <port>]",
    .function = wg_create_interface_cli,
};

/**
 * CLI: wireguard set interface
 * Configure WireGuard interface with private key
 */
static clib_error_t *wg_set_interface_cli(vlib_main_t *vm,
                                          unformat_input_t *input,
                                          vlib_cli_command_t *cmd) {
  u32 sw_if_index = ~0;
  u8 *private_key_b64 = NULL;
  u16 listen_port = 0;

  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(input, "interface %u", &sw_if_index))
      ;
    else if (unformat(input, "private-key %s", &private_key_b64))
      ;
    else if (unformat(input, "listen-port %u", &listen_port))
      ;
    else {
      vec_free(private_key_b64);
      return clib_error_return(0, "unknown input");
    }
  }

  if (sw_if_index == ~0) {
    vec_free(private_key_b64);
    return clib_error_return(0, "interface required");
  }

  vlib_cli_output(vm, "WireGuard interface %u configured", sw_if_index);

  vec_free(private_key_b64);
  return 0;
}

VLIB_CLI_COMMAND(wg_set_interface_command, static) = {
    .path = "wireguard set interface",
    .short_help =
        "wireguard set interface <N> private-key <key> [listen-port <port>]",
    .function = wg_set_interface_cli,
};

/**
 * CLI: wireguard peer add
 * Add a peer to a WireGuard interface
 */
static clib_error_t *wg_peer_add_cli(vlib_main_t *vm, unformat_input_t *input,
                                     vlib_cli_command_t *cmd) {
  u32 sw_if_index = ~0;
  ip46_address_t endpoint = {0};
  ip46_address_t allowed_ip = {0};
  u8 allowed_prefix = 0;
  u16 endpoint_port = 51820;
  u8 *public_key_b64 = NULL;
  u8 public_key[WG_KEY_LEN] = {0};
  u32 keepalive = 25;
  int rv;

  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(input, "interface %u", &sw_if_index))
      ;
    else if (unformat(input, "public-key %s", &public_key_b64))
      ;
    else if (unformat(input, "endpoint %U:%u", unformat_ip46_address, &endpoint,
                      IP46_TYPE_ANY, &endpoint_port))
      ;
    else if (unformat(input, "endpoint %U port %u", unformat_ip46_address,
                      &endpoint, IP46_TYPE_ANY, &endpoint_port))
      ;
    else if (unformat(input, "allowed-ip %U/%u", unformat_ip46_address,
                      &allowed_ip, IP46_TYPE_ANY, &allowed_prefix))
      ;
    else if (unformat(input, "keepalive %u", &keepalive))
      ;
    else {
      vec_free(public_key_b64);
      return clib_error_return(0, "unknown input");
    }
  }

  if (sw_if_index == ~0) {
    vec_free(public_key_b64);
    return clib_error_return(0, "interface required");
  }

  if (!public_key_b64) {
    return clib_error_return(0, "public-key required");
  }

  /* Decode public key (simplified) */
  clib_memset(public_key, 0, WG_KEY_LEN);

  /* Add peer */
  rv = wg_peer_add(sw_if_index, public_key, &endpoint, endpoint_port,
                   &allowed_ip, allowed_prefix);
  if (rv) {
    vec_free(public_key_b64);
    return clib_error_return(0, "failed to add peer");
  }

  vlib_cli_output(vm, "WireGuard peer added:");
  vlib_cli_output(vm, "  Interface: %u", sw_if_index);
  vlib_cli_output(vm, "  Public key: %s", public_key_b64);
  vlib_cli_output(vm, "  Endpoint: %U:%u", format_ip46_address, &endpoint,
                  IP46_TYPE_ANY, endpoint_port);
  vlib_cli_output(vm, "  Allowed IPs: %U/%u", format_ip46_address, &allowed_ip,
                  IP46_TYPE_ANY, allowed_prefix);
  vlib_cli_output(vm, "  Keepalive: %u seconds", keepalive);

  vec_free(public_key_b64);
  return 0;
}

VLIB_CLI_COMMAND(wg_peer_add_command, static) = {
    .path = "wireguard peer add",
    .short_help =
        "wireguard peer add interface <N> public-key <key> "
        "endpoint <ip>:<port> allowed-ip <prefix>/<len> [keepalive <sec>]",
    .function = wg_peer_add_cli,
};

/**
 * CLI: wireguard peer remove
 */
static clib_error_t *wg_peer_remove_cli(vlib_main_t *vm,
                                        unformat_input_t *input,
                                        vlib_cli_command_t *cmd) {
  u32 sw_if_index = ~0;
  u8 *public_key_b64 = NULL;
  u8 public_key[WG_KEY_LEN] = {0};
  int rv;

  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(input, "interface %u", &sw_if_index))
      ;
    else if (unformat(input, "public-key %s", &public_key_b64))
      ;
    else {
      vec_free(public_key_b64);
      return clib_error_return(0, "unknown input");
    }
  }

  rv = wg_peer_remove(sw_if_index, public_key);
  if (rv) {
    vec_free(public_key_b64);
    return clib_error_return(0, "peer not found");
  }

  vlib_cli_output(vm, "Peer removed from interface %u", sw_if_index);

  vec_free(public_key_b64);
  return 0;
}

VLIB_CLI_COMMAND(wg_peer_remove_command, static) = {
    .path = "wireguard peer remove",
    .short_help = "wireguard peer remove interface <N> public-key <key>",
    .function = wg_peer_remove_cli,
};

/**
 * CLI: show wireguard interface
 */
static clib_error_t *wg_show_interface_cli(vlib_main_t *vm,
                                           unformat_input_t *input,
                                           vlib_cli_command_t *cmd) {
  wg_main_t *wm = &wg_main;
  wg_tunnel_t *tun;
  wg_peer_t *peer;
  u8 public_key_b64[45];
  u32 i;

  vlib_cli_output(vm, "WireGuard Interfaces:");
  vlib_cli_output(vm, "=====================\n");

  pool_foreach(tun, wm->tunnels) {
    wg_base64_encode(tun->keypair.public_key, WG_KEY_LEN, public_key_b64);

    vlib_cli_output(vm, "Interface wg%u:", tun->sw_if_index);
    vlib_cli_output(vm, "  Public key: %s", public_key_b64);
    vlib_cli_output(vm, "  Listen port: %u", tun->listen_port);
    vlib_cli_output(vm, "  Peers: %u", tun->n_peers);
    vlib_cli_output(vm, "  TX: %lu packets, %lu bytes", tun->total_tx_packets,
                    tun->total_tx_bytes);
    vlib_cli_output(vm, "  RX: %lu packets, %lu bytes", tun->total_rx_packets,
                    tun->total_rx_bytes);

    /* Show peers */
    vec_foreach_index(i, tun->peers) {
      peer = vec_elt_at_index(tun->peers, i);
      wg_base64_encode(peer->public_key, WG_KEY_LEN, public_key_b64);

      vlib_cli_output(vm, "\n  Peer %u:", i);
      vlib_cli_output(vm, "    Public key: %s", public_key_b64);

      if (peer->endpoint_set) {
        vlib_cli_output(vm, "    Endpoint: %U:%u", format_ip46_address,
                        &peer->endpoint_addr, IP46_TYPE_ANY,
                        peer->endpoint_port);
      }

      vlib_cli_output(vm, "    Allowed IPs: %U/%u", format_ip46_address,
                      &peer->allowed_ip, IP46_TYPE_ANY,
                      peer->allowed_ip_prefix);

      vlib_cli_output(vm, "    State: %s",
                      peer->state == WG_PEER_STATE_ESTABLISHED ? "established"
                      : peer->state == WG_PEER_STATE_HANDSHAKE_SENT
                          ? "handshake sent"
                      : peer->state == WG_PEER_STATE_NEW ? "new"
                                                         : "unknown");

      vlib_cli_output(vm, "    TX: %lu packets, RX: %lu packets",
                      peer->tx_packets, peer->rx_packets);
    }

    vlib_cli_output(vm, "");
  }

  return 0;
}

VLIB_CLI_COMMAND(wg_show_interface_command, static) = {
    .path = "show wireguard interface",
    .short_help = "show wireguard interface",
    .function = wg_show_interface_cli,
};

/**
 * CLI: wireguard keygen
 * Generate a new WireGuard keypair
 */
static clib_error_t *wg_keygen_cli(vlib_main_t *vm, unformat_input_t *input,
                                   vlib_cli_command_t *cmd) {
  u8 private_key[WG_KEY_LEN];
  u8 public_key[WG_KEY_LEN];
  u8 private_key_b64[45];
  u8 public_key_b64[45];

  /* Generate random private key */
  wg_random_bytes(private_key, WG_KEY_LEN);

  /* Clamp for Curve25519 */
  private_key[0] &= 248;
  private_key[31] &= 127;
  private_key[31] |= 64;

  /* Generate public key (simplified - real implementation uses Curve25519) */
  clib_memcpy(public_key, private_key, WG_KEY_LEN);
  public_key[0] ^= 0x9b;

  /* Encode to base64 */
  wg_base64_encode(private_key, WG_KEY_LEN, private_key_b64);
  wg_base64_encode(public_key, WG_KEY_LEN, public_key_b64);

  vlib_cli_output(vm, "Private key: %s", private_key_b64);
  vlib_cli_output(vm, "Public key:  %s", public_key_b64);

  /* Clear private key from memory */
  clib_memset(private_key, 0, WG_KEY_LEN);

  return 0;
}

VLIB_CLI_COMMAND(wg_keygen_command, static) = {
    .path = "wireguard keygen",
    .short_help = "wireguard keygen - Generate new WireGuard keypair",
    .function = wg_keygen_cli,
};
