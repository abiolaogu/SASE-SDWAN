/*
 * OpenSASE WireGuard Tunnel Plugin - Main
 *
 * Copyright (c) 2026 OpenSASE Project
 * Licensed under Apache 2.0
 *
 * VPP plugin registration and tunnel management.
 */

#include <vlib/vlib.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/plugin/plugin.h>
#include <vnet/vnet.h>

#include "wireguard.h"

/* Global instance */
wg_main_t wg_main;

/* VPP Plugin Registration */
VLIB_PLUGIN_REGISTER() = {
    .version = "1.0.0",
    .description = "OpenSASE WireGuard Tunnel Plugin",
};

/**
 * Initialize the WireGuard plugin
 */
static clib_error_t *wg_tunnel_init_internal(vlib_main_t *vm) {
  wg_main_t *wm = &wg_main;

  wm->vlib_main = vm;
  wm->vnet_main = vnet_get_main();

  /* Initialize hash tables */
  wm->tunnel_by_sw_if_index = hash_create(0, sizeof(u32));

  vlib_log_notice(vm, "OpenSASE WireGuard plugin initialized");

  return 0;
}

VLIB_INIT_FUNCTION(wg_tunnel_init_internal);

/**
 * Create a new WireGuard tunnel interface
 */
int wg_tunnel_create(wg_keypair_t *keypair, u16 listen_port, u32 *sw_if_index) {
  wg_main_t *wm = &wg_main;
  vnet_main_t *vnm = wm->vnet_main;
  wg_tunnel_t *tun;
  u32 tun_index;

  /* Allocate tunnel */
  pool_get_aligned(wm->tunnels, tun, CLIB_CACHE_LINE_BYTES);
  tun_index = tun - wm->tunnels;
  clib_memset(tun, 0, sizeof(*tun));

  /* Copy keypair */
  clib_memcpy(&tun->keypair, keypair, sizeof(wg_keypair_t));
  tun->listen_port = listen_port;

  /* Initialize peer hash */
  tun->peer_by_pubkey = hash_create(0, sizeof(u32));

  /* Create dummy HW interface for now */
  /* In production, would create proper tunnel interface */
  tun->sw_if_index = tun_index; /* Simplified */
  tun->hw_if_index = tun_index;

  /* Register in hash */
  hash_set(wm->tunnel_by_sw_if_index, tun->sw_if_index, tun_index);

  *sw_if_index = tun->sw_if_index;

  vlib_log_notice(wm->vlib_main, "WireGuard tunnel created: index %u port %u",
                  tun_index, listen_port);

  return 0;
}

/**
 * Delete a WireGuard tunnel
 */
int wg_tunnel_delete(u32 sw_if_index) {
  wg_main_t *wm = &wg_main;
  uword *p;
  wg_tunnel_t *tun;
  u32 tun_index;

  p = hash_get(wm->tunnel_by_sw_if_index, sw_if_index);
  if (!p)
    return -1; /* Not found */

  tun_index = p[0];
  tun = pool_elt_at_index(wm->tunnels, tun_index);

  /* Free peers */
  vec_free(tun->peers);
  hash_free(tun->peer_by_pubkey);

  /* Remove from hash */
  hash_unset(wm->tunnel_by_sw_if_index, sw_if_index);

  /* Free tunnel */
  pool_put(wm->tunnels, tun);

  return 0;
}

/**
 * Add a peer to a tunnel
 */
int wg_peer_add(u32 sw_if_index, u8 *public_key, ip46_address_t *endpoint,
                u16 port, ip46_address_t *allowed_ip, u8 prefix_len) {
  wg_main_t *wm = &wg_main;
  uword *p;
  wg_tunnel_t *tun;
  wg_peer_t *peer;
  u32 peer_index;

  p = hash_get(wm->tunnel_by_sw_if_index, sw_if_index);
  if (!p)
    return -1;

  tun = pool_elt_at_index(wm->tunnels, p[0]);

  /* Check if peer already exists */
  /* Hash by first 8 bytes of pubkey (simplified) */
  u64 pubkey_hash = *(u64 *)public_key;
  p = hash_get(tun->peer_by_pubkey, pubkey_hash);
  if (p)
    return -2; /* Already exists */

  /* Create peer */
  vec_add2(tun->peers, peer, 1);
  peer_index = peer - tun->peers;
  clib_memset(peer, 0, sizeof(*peer));

  clib_memcpy(peer->public_key, public_key, WG_KEY_LEN);

  if (endpoint) {
    clib_memcpy(&peer->endpoint_addr, endpoint, sizeof(ip46_address_t));
    peer->endpoint_port = port;
    peer->endpoint_set = 1;
  }

  if (allowed_ip) {
    clib_memcpy(&peer->allowed_ip, allowed_ip, sizeof(ip46_address_t));
    peer->allowed_ip_prefix = prefix_len;
  }

  peer->state = WG_PEER_STATE_NEW;
  peer->if_index = sw_if_index;

  /* Add to hash */
  hash_set(tun->peer_by_pubkey, pubkey_hash, peer_index);
  tun->n_peers++;

  vlib_log_notice(wm->vlib_main, "WireGuard peer added: tunnel %u peer %u",
                  sw_if_index, peer_index);

  return 0;
}

/**
 * Show WireGuard tunnels
 */
static clib_error_t *wg_show_tunnels_fn(vlib_main_t *vm,
                                        unformat_input_t *input,
                                        vlib_cli_command_t *cmd) {
  wg_main_t *wm = &wg_main;
  wg_tunnel_t *tun;
  wg_peer_t *peer;
  u32 i;

  vlib_cli_output(vm, "WireGuard Tunnels:");
  vlib_cli_output(vm, "==================\n");

  pool_foreach(tun, wm->tunnels) {
    vlib_cli_output(vm, "Tunnel %u:", tun->sw_if_index);
    vlib_cli_output(vm, "  Listen port: %u", tun->listen_port);
    vlib_cli_output(vm, "  Peers: %u", tun->n_peers);
    vlib_cli_output(vm, "  TX: %lu packets, %lu bytes", tun->total_tx_packets,
                    tun->total_tx_bytes);
    vlib_cli_output(vm, "  RX: %lu packets, %lu bytes", tun->total_rx_packets,
                    tun->total_rx_bytes);

    vec_foreach_index(i, tun->peers) {
      peer = vec_elt_at_index(tun->peers, i);
      vlib_cli_output(vm, "  Peer %u:", i);
      vlib_cli_output(vm, "    State: %u", peer->state);
      if (peer->endpoint_set) {
        vlib_cli_output(vm, "    Endpoint: %U:%u", format_ip46_address,
                        &peer->endpoint_addr, IP46_TYPE_ANY,
                        peer->endpoint_port);
      }
      vlib_cli_output(vm, "    TX: %lu pkts, RX: %lu pkts", peer->tx_packets,
                      peer->rx_packets);
    }
    vlib_cli_output(vm, "");
  }

  return 0;
}

VLIB_CLI_COMMAND(wg_show_tunnels_command, static) = {
    .path = "show wireguard tunnels",
    .short_help = "show wireguard tunnels",
    .function = wg_show_tunnels_fn,
};

/**
 * Create WireGuard tunnel CLI
 */
static clib_error_t *wg_create_tunnel_fn(vlib_main_t *vm,
                                         unformat_input_t *input,
                                         vlib_cli_command_t *cmd) {
  u16 port = 51820;
  u32 sw_if_index;
  wg_keypair_t keypair;
  int rv;

  /* Generate random keypair for demo */
  clib_memset(&keypair, 0, sizeof(keypair));
  /* In production, would use proper key generation */

  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(input, "port %u", &port))
      ;
    else
      return clib_error_return(0, "unknown input");
  }

  rv = wg_tunnel_create(&keypair, port, &sw_if_index);
  if (rv)
    return clib_error_return(0, "failed to create tunnel");

  vlib_cli_output(vm, "WireGuard tunnel created: sw_if_index %u", sw_if_index);

  return 0;
}

VLIB_CLI_COMMAND(wg_create_tunnel_command, static) = {
    .path = "wireguard create",
    .short_help = "wireguard create [port <N>]",
    .function = wg_create_tunnel_fn,
};
