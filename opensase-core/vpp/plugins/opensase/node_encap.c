/*
 * OpenSASE VPP Plugin - Encapsulation Node
 *
 * Copyright (c) 2026 OpenSASE Project
 * Licensed under Apache 2.0
 *
 * WireGuard/VXLAN/GRE encapsulation for tunnel output.
 * Target: <500ns per packet
 */

#include <vlib/vlib.h>
#include <vnet/ip/ip4.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/vnet.h>

#include "opensase.h"

typedef enum {
  OPENSASE_ENCAP_NEXT_OUTPUT, /* To interface output */
  OPENSASE_ENCAP_NEXT_DROP,   /* Drop */
  OPENSASE_ENCAP_N_NEXT,
} opensase_encap_next_t;

typedef struct {
  u8 encap_type;
  u32 tunnel_id;
  u16 outer_len;
} opensase_encap_trace_t;

/* Encapsulation types */
typedef enum {
  ENCAP_NONE = 0,
  ENCAP_WIREGUARD,
  ENCAP_VXLAN,
  ENCAP_GRE,
  ENCAP_GENEVE,
} encap_type_t;

/* Pre-built tunnel headers (cache-line aligned) */
typedef struct {
  CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);

  u8 encap_type;
  u8 header_len;
  u16 tunnel_id;

  /* Outer IP header */
  ip4_header_t ip4;

  /* UDP header (for WG/VXLAN/Geneve) */
  udp_header_t udp;

  /* WireGuard data header */
  u8 wg_type;
  u8 wg_reserved[3];
  u32 wg_receiver_index;
  u64 wg_counter;

  /* Destination for output */
  u32 output_sw_if_index;
} encap_tunnel_t;

/* Tunnel table */
#define MAX_TUNNELS 4096
static encap_tunnel_t tunnels[MAX_TUNNELS];
static u32 n_tunnels = 0;

static u8 *format_opensase_encap_trace(u8 *s, va_list *args) {
  CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
  CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
  opensase_encap_trace_t *t = va_arg(*args, opensase_encap_trace_t *);

  s = format(s, "opensase-encap: type %u tunnel %u outer_len %u", t->encap_type,
             t->tunnel_id, t->outer_len);
  return s;
}

/**
 * Apply WireGuard encapsulation
 * Prepends: IP + UDP + WG header
 */
always_inline void encap_wireguard(vlib_main_t *vm, vlib_buffer_t *b,
                                   encap_tunnel_t *tun) {
  ip4_header_t *inner_ip4 = vlib_buffer_get_current(b);
  u32 inner_len = clib_net_to_host_u16(inner_ip4->length);

  /* Calculate outer lengths */
  u32 outer_len = inner_len + sizeof(ip4_header_t) + sizeof(udp_header_t) + 16;

  /* Prepend outer headers */
  vlib_buffer_advance(b, -(sizeof(ip4_header_t) + sizeof(udp_header_t) + 16));

  ip4_header_t *outer_ip4 = vlib_buffer_get_current(b);
  udp_header_t *udp = (udp_header_t *)(outer_ip4 + 1);
  u8 *wg_hdr = (u8 *)(udp + 1);

  /* Copy pre-built headers */
  *outer_ip4 = tun->ip4;
  *udp = tun->udp;

  /* Set lengths */
  outer_ip4->length = clib_host_to_net_u16(outer_len);
  udp->length = clib_host_to_net_u16(outer_len - sizeof(ip4_header_t));

  /* WireGuard data message header */
  wg_hdr[0] = 4; /* Type: data */
  wg_hdr[1] = wg_hdr[2] = wg_hdr[3] = 0;
  *(u32 *)(wg_hdr + 4) = tun->wg_receiver_index;
  *(u64 *)(wg_hdr + 8) = tun->wg_counter++;

  /* Update IP checksum */
  outer_ip4->checksum = ip4_header_checksum(outer_ip4);

  /* Mark buffer for output interface */
  vnet_buffer(b)->sw_if_index[VLIB_TX] = tun->output_sw_if_index;
}

/**
 * Apply VXLAN encapsulation
 */
always_inline void encap_vxlan(vlib_main_t *vm, vlib_buffer_t *b,
                               encap_tunnel_t *tun) {
  ip4_header_t *inner_ip4 = vlib_buffer_get_current(b);
  u32 inner_len = clib_net_to_host_u16(inner_ip4->length);

  /* VXLAN header is 8 bytes */
  u32 outer_len = inner_len + sizeof(ip4_header_t) + sizeof(udp_header_t) + 8;

  /* Prepend headers */
  vlib_buffer_advance(b, -(sizeof(ip4_header_t) + sizeof(udp_header_t) + 8));

  ip4_header_t *outer_ip4 = vlib_buffer_get_current(b);
  udp_header_t *udp = (udp_header_t *)(outer_ip4 + 1);
  u8 *vxlan_hdr = (u8 *)(udp + 1);

  /* Copy pre-built headers */
  *outer_ip4 = tun->ip4;
  *udp = tun->udp;

  /* Set lengths */
  outer_ip4->length = clib_host_to_net_u16(outer_len);
  udp->length = clib_host_to_net_u16(outer_len - sizeof(ip4_header_t));

  /* VXLAN header: flags + VNI */
  *(u32 *)vxlan_hdr = clib_host_to_net_u32(0x08000000); /* I flag */
  *(u32 *)(vxlan_hdr + 4) = clib_host_to_net_u32(tun->tunnel_id << 8);

  outer_ip4->checksum = ip4_header_checksum(outer_ip4);
  vnet_buffer(b)->sw_if_index[VLIB_TX] = tun->output_sw_if_index;
}

/**
 * Get tunnel for session
 */
always_inline encap_tunnel_t *
get_tunnel_for_session(opensase_buffer_opaque_t *op) {
  /* Simple mapping: use tenant_id as tunnel index (simplified) */
  u32 tun_idx = op->tenant_id % (n_tunnels ? n_tunnels : 1);
  return &tunnels[tun_idx];
}

/**
 * Encapsulation node - main processing
 */
VLIB_NODE_FN(opensase_encap_node)(vlib_main_t *vm, vlib_node_runtime_t *node,
                                  vlib_frame_t *frame) {
  u32 n_left_from, *from;

  from = vlib_frame_vector_args(frame);
  n_left_from = frame->n_vectors;

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;

  vlib_get_buffers(vm, from, bufs, n_left_from);

  /* Process 4 at a time */
  while (n_left_from >= 4) {
    if (n_left_from >= 8) {
      vlib_prefetch_buffer_header(b[4], STORE);
      vlib_prefetch_buffer_header(b[5], STORE);
      CLIB_PREFETCH(b[4]->data - 64, 128, STORE);
      CLIB_PREFETCH(b[5]->data - 64, 128, STORE);
    }

    {
      opensase_buffer_opaque_t *op0, *op1, *op2, *op3;
      encap_tunnel_t *tun0, *tun1, *tun2, *tun3;

      op0 = opensase_buffer_opaque(b[0]);
      op1 = opensase_buffer_opaque(b[1]);
      op2 = opensase_buffer_opaque(b[2]);
      op3 = opensase_buffer_opaque(b[3]);

      tun0 = get_tunnel_for_session(op0);
      tun1 = get_tunnel_for_session(op1);
      tun2 = get_tunnel_for_session(op2);
      tun3 = get_tunnel_for_session(op3);

      /* Apply encapsulation based on type */
      switch (tun0->encap_type) {
      case ENCAP_WIREGUARD:
        encap_wireguard(vm, b[0], tun0);
        break;
      case ENCAP_VXLAN:
        encap_vxlan(vm, b[0], tun0);
        break;
      default:
        /* No encapsulation */
        break;
      }

      switch (tun1->encap_type) {
      case ENCAP_WIREGUARD:
        encap_wireguard(vm, b[1], tun1);
        break;
      case ENCAP_VXLAN:
        encap_vxlan(vm, b[1], tun1);
        break;
      default:
        break;
      }

      switch (tun2->encap_type) {
      case ENCAP_WIREGUARD:
        encap_wireguard(vm, b[2], tun2);
        break;
      case ENCAP_VXLAN:
        encap_vxlan(vm, b[2], tun2);
        break;
      default:
        break;
      }

      switch (tun3->encap_type) {
      case ENCAP_WIREGUARD:
        encap_wireguard(vm, b[3], tun3);
        break;
      case ENCAP_VXLAN:
        encap_vxlan(vm, b[3], tun3);
        break;
      default:
        break;
      }

      next[0] = next[1] = next[2] = next[3] = OPENSASE_ENCAP_NEXT_OUTPUT;
    }

    b += 4;
    next += 4;
    n_left_from -= 4;
  }

  /* Single packet */
  while (n_left_from > 0) {
    opensase_buffer_opaque_t *op0 = opensase_buffer_opaque(b[0]);
    encap_tunnel_t *tun0 = get_tunnel_for_session(op0);

    switch (tun0->encap_type) {
    case ENCAP_WIREGUARD:
      encap_wireguard(vm, b[0], tun0);
      break;
    case ENCAP_VXLAN:
      encap_vxlan(vm, b[0], tun0);
      break;
    default:
      break;
    }

    next[0] = OPENSASE_ENCAP_NEXT_OUTPUT;

    b += 1;
    next += 1;
    n_left_from -= 1;
  }

  vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE(opensase_encap_node) = {
    .name = "opensase-encap",
    .vector_size = sizeof(u32),
    .format_trace = format_opensase_encap_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_next_nodes = OPENSASE_ENCAP_N_NEXT,
    .next_nodes =
        {
            [OPENSASE_ENCAP_NEXT_OUTPUT] = "interface-output",
            [OPENSASE_ENCAP_NEXT_DROP] = "error-drop",
        },
};

/* CLI to create tunnel */
static clib_error_t *opensase_tunnel_create_fn(vlib_main_t *vm,
                                               unformat_input_t *input,
                                               vlib_cli_command_t *cmd) {
  ip4_address_t local, remote;
  u16 local_port = 51820, remote_port = 51820;
  u32 sw_if_index = 0;
  u8 type = ENCAP_WIREGUARD;
  encap_tunnel_t *tun;

  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(input, "local %U", unformat_ip4_address, &local))
      ;
    else if (unformat(input, "remote %U", unformat_ip4_address, &remote))
      ;
    else if (unformat(input, "local-port %u", &local_port))
      ;
    else if (unformat(input, "remote-port %u", &remote_port))
      ;
    else if (unformat(input, "interface %u", &sw_if_index))
      ;
    else if (unformat(input, "wireguard"))
      type = ENCAP_WIREGUARD;
    else if (unformat(input, "vxlan"))
      type = ENCAP_VXLAN;
    else
      return clib_error_return(0, "unknown input");
  }

  if (n_tunnels >= MAX_TUNNELS)
    return clib_error_return(0, "tunnel table full");

  tun = &tunnels[n_tunnels++];
  clib_memset(tun, 0, sizeof(*tun));

  tun->encap_type = type;
  tun->tunnel_id = n_tunnels - 1;
  tun->output_sw_if_index = sw_if_index;

  /* Build outer IP header */
  tun->ip4.ip_version_and_header_length = 0x45;
  tun->ip4.ttl = 64;
  tun->ip4.protocol = IP_PROTOCOL_UDP;
  tun->ip4.src_address = local;
  tun->ip4.dst_address = remote;

  /* Build UDP header */
  tun->udp.src_port = clib_host_to_net_u16(local_port);
  tun->udp.dst_port = clib_host_to_net_u16(remote_port);

  vlib_cli_output(vm, "Tunnel %u created: %U -> %U type %s", tun->tunnel_id,
                  format_ip4_address, &local, format_ip4_address, &remote,
                  type == ENCAP_WIREGUARD ? "wireguard" : "vxlan");

  return 0;
}

VLIB_CLI_COMMAND(opensase_tunnel_create_command, static) = {
    .path = "opensase tunnel create",
    .short_help = "opensase tunnel create local <ip> remote <ip> "
                  "[wireguard|vxlan] interface <N>",
    .function = opensase_tunnel_create_fn,
};
