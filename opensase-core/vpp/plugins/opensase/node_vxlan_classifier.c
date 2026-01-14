/*
 * OpenSASE VPP Plugin - Tenant Classifier Node
 *
 * Copyright (c) 2026 OpenSASE Project
 * Licensed under Apache 2.0
 *
 * Extracts tenant ID from VXLAN VNI for multi-tenant isolation.
 * Optimized for single-pass processing at 100 Gbps.
 */

#include <vlib/vlib.h>
#include <vnet/ip/ip4.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/vnet.h>
#include <vnet/vxlan/vxlan.h>
#include <vppinfra/xxhash.h>

#include "opensase.h"

typedef enum {
  TENANT_CLASSIFIER_NEXT_ACL,      /* Continue to ACL input */
  TENANT_CLASSIFIER_NEXT_SECURITY, /* Skip ACL, go to security */
  TENANT_CLASSIFIER_NEXT_DROP,     /* Unknown tenant - drop */
  TENANT_CLASSIFIER_N_NEXT,
} tenant_classifier_next_t;

typedef struct {
  u32 vxlan_vni;
  u32 tenant_id;
  u8 is_vxlan;
} tenant_classifier_trace_t;

/* VNI to tenant mapping table */
#define VNI_TENANT_TABLE_SIZE 65536
#define VNI_TENANT_TABLE_MASK (VNI_TENANT_TABLE_SIZE - 1)

typedef struct {
  u32 vni;
  u32 tenant_id;
  u32 vrf_id;
  u8 valid;
  u8 acl_bypass; /* Skip ACL for trusted VNIs */
} vni_tenant_entry_t;

/* Direct-mapped table for O(1) VNI lookup */
static vni_tenant_entry_t vni_tenant_table[VNI_TENANT_TABLE_SIZE];

/* VXLAN header structure */
typedef struct {
  u8 flags;
  u8 reserved1[3];
  u8 vni[3];
  u8 reserved2;
} vxlan_header_t;

static u8 *format_tenant_classifier_trace(u8 *s, va_list *args) {
  CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
  CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
  tenant_classifier_trace_t *t = va_arg(*args, tenant_classifier_trace_t *);

  s = format(s, "tenant-classifier: vxlan=%u vni=%u tenant=%u", t->is_vxlan,
             t->vxlan_vni, t->tenant_id);
  return s;
}

/**
 * Extract VNI from VXLAN header
 */
always_inline u32 extract_vxlan_vni(vxlan_header_t *vxlan) {
  return (vxlan->vni[0] << 16) | (vxlan->vni[1] << 8) | vxlan->vni[2];
}

/**
 * Check if packet is VXLAN encapsulated (UDP dst port 4789)
 */
always_inline int is_vxlan_packet(ip4_header_t *ip4) {
  if (ip4->protocol != IP_PROTOCOL_UDP)
    return 0;

  udp_header_t *udp = (udp_header_t *)(ip4 + 1);
  return clib_net_to_host_u16(udp->dst_port) == 4789;
}

/**
 * Get tenant from VNI
 */
always_inline vni_tenant_entry_t *lookup_tenant_by_vni(u32 vni) {
  u32 idx = vni & VNI_TENANT_TABLE_MASK;
  vni_tenant_entry_t *entry = &vni_tenant_table[idx];

  if (entry->valid && entry->vni == vni)
    return entry;

  return NULL;
}

/**
 * Get tenant from source IP (fallback for non-VXLAN)
 */
always_inline u32 lookup_tenant_by_ip(ip4_address_t *src_ip) {
  /* Use hash-based lookup (simplified - would use radix tree in production) */
  u64 hash = clib_xxhash(src_ip->as_u32);
  /* Return default tenant for non-VXLAN traffic */
  return 0;
}

/**
 * Tenant classifier node function
 */
VLIB_NODE_FN(tenant_classifier_node)(vlib_main_t *vm, vlib_node_runtime_t *node,
                                     vlib_frame_t *frame) {
  u32 n_left_from, *from;

  from = vlib_frame_vector_args(frame);
  n_left_from = frame->n_vectors;

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;

  vlib_get_buffers(vm, from, bufs, n_left_from);

  /* Process 4 packets at a time */
  while (n_left_from >= 4) {
    /* Prefetch next iteration */
    if (n_left_from >= 8) {
      vlib_prefetch_buffer_header(b[4], LOAD);
      vlib_prefetch_buffer_header(b[5], LOAD);
      CLIB_PREFETCH(b[4]->data, CLIB_CACHE_LINE_BYTES, LOAD);
      CLIB_PREFETCH(b[5]->data, CLIB_CACHE_LINE_BYTES, LOAD);
    }

    {
      ip4_header_t *ip0, *ip1, *ip2, *ip3;
      opensase_buffer_opaque_t *op0, *op1, *op2, *op3;
      u32 vni0 = 0, vni1 = 0, vni2 = 0, vni3 = 0;
      vni_tenant_entry_t *te0, *te1, *te2, *te3;

      ip0 = vlib_buffer_get_current(b[0]);
      ip1 = vlib_buffer_get_current(b[1]);
      ip2 = vlib_buffer_get_current(b[2]);
      ip3 = vlib_buffer_get_current(b[3]);

      op0 = opensase_buffer_opaque(b[0]);
      op1 = opensase_buffer_opaque(b[1]);
      op2 = opensase_buffer_opaque(b[2]);
      op3 = opensase_buffer_opaque(b[3]);

      /* Check for VXLAN and extract VNI */
      if (is_vxlan_packet(ip0)) {
        udp_header_t *udp0 = (udp_header_t *)(ip0 + 1);
        vxlan_header_t *vxlan0 = (vxlan_header_t *)(udp0 + 1);
        vni0 = extract_vxlan_vni(vxlan0);
        te0 = lookup_tenant_by_vni(vni0);

        /* Decapsulate - advance past outer headers */
        vlib_buffer_advance(b[0], sizeof(ip4_header_t) + sizeof(udp_header_t) +
                                      sizeof(vxlan_header_t));
      } else {
        te0 = NULL;
      }

      if (is_vxlan_packet(ip1)) {
        udp_header_t *udp1 = (udp_header_t *)(ip1 + 1);
        vxlan_header_t *vxlan1 = (vxlan_header_t *)(udp1 + 1);
        vni1 = extract_vxlan_vni(vxlan1);
        te1 = lookup_tenant_by_vni(vni1);
        vlib_buffer_advance(b[1], sizeof(ip4_header_t) + sizeof(udp_header_t) +
                                      sizeof(vxlan_header_t));
      } else {
        te1 = NULL;
      }

      if (is_vxlan_packet(ip2)) {
        udp_header_t *udp2 = (udp_header_t *)(ip2 + 1);
        vxlan_header_t *vxlan2 = (vxlan_header_t *)(udp2 + 1);
        vni2 = extract_vxlan_vni(vxlan2);
        te2 = lookup_tenant_by_vni(vni2);
        vlib_buffer_advance(b[2], sizeof(ip4_header_t) + sizeof(udp_header_t) +
                                      sizeof(vxlan_header_t));
      } else {
        te2 = NULL;
      }

      if (is_vxlan_packet(ip3)) {
        udp_header_t *udp3 = (udp_header_t *)(ip3 + 1);
        vxlan_header_t *vxlan3 = (vxlan_header_t *)(udp3 + 1);
        vni3 = extract_vxlan_vni(vxlan3);
        te3 = lookup_tenant_by_vni(vni3);
        vlib_buffer_advance(b[3], sizeof(ip4_header_t) + sizeof(udp_header_t) +
                                      sizeof(vxlan_header_t));
      } else {
        te3 = NULL;
      }

      /* Set tenant IDs and next nodes */
      if (te0) {
        op0->tenant_id = te0->tenant_id;
        next[0] = te0->acl_bypass ? TENANT_CLASSIFIER_NEXT_SECURITY
                                  : TENANT_CLASSIFIER_NEXT_ACL;
      } else {
        op0->tenant_id = lookup_tenant_by_ip(&ip0->src_address);
        next[0] = TENANT_CLASSIFIER_NEXT_ACL;
      }

      if (te1) {
        op1->tenant_id = te1->tenant_id;
        next[1] = te1->acl_bypass ? TENANT_CLASSIFIER_NEXT_SECURITY
                                  : TENANT_CLASSIFIER_NEXT_ACL;
      } else {
        op1->tenant_id = lookup_tenant_by_ip(&ip1->src_address);
        next[1] = TENANT_CLASSIFIER_NEXT_ACL;
      }

      if (te2) {
        op2->tenant_id = te2->tenant_id;
        next[2] = te2->acl_bypass ? TENANT_CLASSIFIER_NEXT_SECURITY
                                  : TENANT_CLASSIFIER_NEXT_ACL;
      } else {
        op2->tenant_id = lookup_tenant_by_ip(&ip2->src_address);
        next[2] = TENANT_CLASSIFIER_NEXT_ACL;
      }

      if (te3) {
        op3->tenant_id = te3->tenant_id;
        next[3] = te3->acl_bypass ? TENANT_CLASSIFIER_NEXT_SECURITY
                                  : TENANT_CLASSIFIER_NEXT_ACL;
      } else {
        op3->tenant_id = lookup_tenant_by_ip(&ip3->src_address);
        next[3] = TENANT_CLASSIFIER_NEXT_ACL;
      }
    }

    b += 4;
    next += 4;
    n_left_from -= 4;
  }

  /* Single packet processing */
  while (n_left_from > 0) {
    ip4_header_t *ip0 = vlib_buffer_get_current(b[0]);
    opensase_buffer_opaque_t *op0 = opensase_buffer_opaque(b[0]);
    vni_tenant_entry_t *te0 = NULL;

    if (is_vxlan_packet(ip0)) {
      udp_header_t *udp0 = (udp_header_t *)(ip0 + 1);
      vxlan_header_t *vxlan0 = (vxlan_header_t *)(udp0 + 1);
      u32 vni0 = extract_vxlan_vni(vxlan0);
      te0 = lookup_tenant_by_vni(vni0);
      vlib_buffer_advance(b[0], sizeof(ip4_header_t) + sizeof(udp_header_t) +
                                    sizeof(vxlan_header_t));
    }

    if (te0) {
      op0->tenant_id = te0->tenant_id;
      next[0] = te0->acl_bypass ? TENANT_CLASSIFIER_NEXT_SECURITY
                                : TENANT_CLASSIFIER_NEXT_ACL;
    } else {
      op0->tenant_id = lookup_tenant_by_ip(&ip0->src_address);
      next[0] = TENANT_CLASSIFIER_NEXT_ACL;
    }

    b += 1;
    next += 1;
    n_left_from -= 1;
  }

  vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

/* Node registration */
VLIB_REGISTER_NODE(tenant_classifier_node) = {
    .name = "tenant-classifier",
    .vector_size = sizeof(u32),
    .format_trace = format_tenant_classifier_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_next_nodes = TENANT_CLASSIFIER_N_NEXT,
    .next_nodes =
        {
            [TENANT_CLASSIFIER_NEXT_ACL] = "acl-plugin-in-ip4-fa",
            [TENANT_CLASSIFIER_NEXT_SECURITY] = "security-inspect",
            [TENANT_CLASSIFIER_NEXT_DROP] = "error-drop",
        },
};

/* CLI: Add VNI to tenant mapping */
static clib_error_t *tenant_vni_add_fn(vlib_main_t *vm, unformat_input_t *input,
                                       vlib_cli_command_t *cmd) {
  u32 vni = 0;
  u32 tenant_id = 0;
  u32 vrf_id = 0;
  u8 acl_bypass = 0;
  u32 idx;

  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(input, "vni %u", &vni))
      ;
    else if (unformat(input, "tenant %u", &tenant_id))
      ;
    else if (unformat(input, "vrf %u", &vrf_id))
      ;
    else if (unformat(input, "acl-bypass"))
      acl_bypass = 1;
    else
      return clib_error_return(0, "unknown input");
  }

  if (vni == 0)
    return clib_error_return(0, "VNI required");

  idx = vni & VNI_TENANT_TABLE_MASK;
  vni_tenant_table[idx].vni = vni;
  vni_tenant_table[idx].tenant_id = tenant_id;
  vni_tenant_table[idx].vrf_id = vrf_id;
  vni_tenant_table[idx].acl_bypass = acl_bypass;
  vni_tenant_table[idx].valid = 1;

  vlib_cli_output(vm, "VNI %u -> tenant %u (vrf %u%s)", vni, tenant_id, vrf_id,
                  acl_bypass ? ", acl-bypass" : "");
  return 0;
}

VLIB_CLI_COMMAND(tenant_vni_add_command, static) = {
    .path = "opensase tenant vni add",
    .short_help =
        "opensase tenant vni add vni <N> tenant <id> [vrf <id>] [acl-bypass]",
    .function = tenant_vni_add_fn,
};

/* CLI: Show VNI mappings */
static clib_error_t *tenant_vni_show_fn(vlib_main_t *vm,
                                        unformat_input_t *input,
                                        vlib_cli_command_t *cmd) {
  u32 i;

  vlib_cli_output(vm, "VNI to Tenant Mappings:");
  vlib_cli_output(vm, "%-10s %-10s %-10s %s", "VNI", "Tenant", "VRF", "Flags");

  for (i = 0; i < VNI_TENANT_TABLE_SIZE; i++) {
    if (vni_tenant_table[i].valid) {
      vlib_cli_output(vm, "%-10u %-10u %-10u %s", vni_tenant_table[i].vni,
                      vni_tenant_table[i].tenant_id, vni_tenant_table[i].vrf_id,
                      vni_tenant_table[i].acl_bypass ? "acl-bypass" : "");
    }
  }

  return 0;
}

VLIB_CLI_COMMAND(tenant_vni_show_command, static) = {
    .path = "show opensase tenant vni",
    .short_help = "show opensase tenant vni",
    .function = tenant_vni_show_fn,
};
