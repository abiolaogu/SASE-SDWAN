/*
 * OpenSASE VPP Plugin - Tenant Lookup Node
 *
 * Copyright (c) 2026 OpenSASE Project
 * Licensed under Apache 2.0
 *
 * Ultra-fast tenant identification using perfect hashing.
 * Target: <500ns per packet
 */

#include <vlib/vlib.h>
#include <vnet/ip/ip4.h>
#include <vnet/vnet.h>
#include <vppinfra/xxhash.h>

#include "opensase.h"

typedef enum {
  OPENSASE_TENANT_NEXT_SECURITY, /* Continue to security graph */
  OPENSASE_TENANT_NEXT_DROP,     /* Unknown tenant - drop */
  OPENSASE_TENANT_N_NEXT,
} opensase_tenant_next_t;

typedef struct {
  u32 tenant_id;
  u32 vrf_id;
} opensase_tenant_trace_t;

/* Tenant lookup table - prefilled at startup */
#define TENANT_HASH_BUCKETS 65536
#define TENANT_HASH_MASK (TENANT_HASH_BUCKETS - 1)

typedef struct {
  ip4_address_t src_prefix;
  u8 prefix_len;
  u32 tenant_id;
  u32 vrf_id;
  u8 valid;
} tenant_entry_t;

/* Hash bucket with 4 entries per bucket (cache-line optimized) */
typedef struct {
  CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);
  tenant_entry_t entries[4];
} tenant_bucket_t;

static tenant_bucket_t tenant_hash[TENANT_HASH_BUCKETS];

static u8 *format_opensase_tenant_trace(u8 *s, va_list *args) {
  CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
  CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
  opensase_tenant_trace_t *t = va_arg(*args, opensase_tenant_trace_t *);

  s = format(s, "opensase-tenant: tenant %u vrf %u", t->tenant_id, t->vrf_id);
  return s;
}

/**
 * Fast tenant lookup using source IP prefix
 * Uses cuckoo-style hashing for O(1) lookup
 */
always_inline u32 tenant_lookup_fast(ip4_address_t *src_ip, u32 *vrf_id) {
  u32 hash = clib_xxhash(src_ip->as_u32) & TENANT_HASH_MASK;
  tenant_bucket_t *bucket = &tenant_hash[hash];
  u32 i;

  /* Prefetch bucket */
  CLIB_PREFETCH(bucket, CLIB_CACHE_LINE_BYTES, LOAD);

  /* Check all 4 entries in bucket */
  for (i = 0; i < 4; i++) {
    tenant_entry_t *e = &bucket->entries[i];
    if (PREDICT_TRUE(e->valid)) {
      u32 mask = ~0 << (32 - e->prefix_len);
      if ((src_ip->as_u32 & clib_host_to_net_u32(mask)) ==
          (e->src_prefix.as_u32 & clib_host_to_net_u32(mask))) {
        *vrf_id = e->vrf_id;
        return e->tenant_id;
      }
    }
  }

  *vrf_id = 0;
  return 0; /* Default tenant */
}

/**
 * Tenant lookup node - optimized for <500ns latency
 */
VLIB_NODE_FN(opensase_tenant_node)(vlib_main_t *vm, vlib_node_runtime_t *node,
                                   vlib_frame_t *frame) {
  u32 n_left_from, *from;

  from = vlib_frame_vector_args(frame);
  n_left_from = frame->n_vectors;

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;

  vlib_get_buffers(vm, from, bufs, n_left_from);

  /* Process 8 packets at a time for maximum throughput */
  while (PREDICT_TRUE(n_left_from >= 8)) {
    /* Aggressive prefetching for low latency */
    {
      vlib_prefetch_buffer_header(b[8], LOAD);
      vlib_prefetch_buffer_header(b[9], LOAD);
      vlib_prefetch_buffer_header(b[10], LOAD);
      vlib_prefetch_buffer_header(b[11], LOAD);

      CLIB_PREFETCH(b[8]->data, CLIB_CACHE_LINE_BYTES, LOAD);
      CLIB_PREFETCH(b[9]->data, CLIB_CACHE_LINE_BYTES, LOAD);
      CLIB_PREFETCH(b[10]->data, CLIB_CACHE_LINE_BYTES, LOAD);
      CLIB_PREFETCH(b[11]->data, CLIB_CACHE_LINE_BYTES, LOAD);
    }

    /* Process 8 packets */
    {
      ip4_header_t *ip0, *ip1, *ip2, *ip3;
      ip4_header_t *ip4, *ip5, *ip6, *ip7;
      opensase_buffer_opaque_t *op0, *op1, *op2, *op3;
      opensase_buffer_opaque_t *op4, *op5, *op6, *op7;
      u32 tenant0, tenant1, tenant2, tenant3;
      u32 tenant4, tenant5, tenant6, tenant7;
      u32 vrf0, vrf1, vrf2, vrf3;
      u32 vrf4, vrf5, vrf6, vrf7;

      ip0 = vlib_buffer_get_current(b[0]);
      ip1 = vlib_buffer_get_current(b[1]);
      ip2 = vlib_buffer_get_current(b[2]);
      ip3 = vlib_buffer_get_current(b[3]);
      ip4 = vlib_buffer_get_current(b[4]);
      ip5 = vlib_buffer_get_current(b[5]);
      ip6 = vlib_buffer_get_current(b[6]);
      ip7 = vlib_buffer_get_current(b[7]);

      op0 = opensase_buffer_opaque(b[0]);
      op1 = opensase_buffer_opaque(b[1]);
      op2 = opensase_buffer_opaque(b[2]);
      op3 = opensase_buffer_opaque(b[3]);
      op4 = opensase_buffer_opaque(b[4]);
      op5 = opensase_buffer_opaque(b[5]);
      op6 = opensase_buffer_opaque(b[6]);
      op7 = opensase_buffer_opaque(b[7]);

      /* Parallel tenant lookups */
      tenant0 = tenant_lookup_fast(&ip0->src_address, &vrf0);
      tenant1 = tenant_lookup_fast(&ip1->src_address, &vrf1);
      tenant2 = tenant_lookup_fast(&ip2->src_address, &vrf2);
      tenant3 = tenant_lookup_fast(&ip3->src_address, &vrf3);
      tenant4 = tenant_lookup_fast(&ip4->src_address, &vrf4);
      tenant5 = tenant_lookup_fast(&ip5->src_address, &vrf5);
      tenant6 = tenant_lookup_fast(&ip6->src_address, &vrf6);
      tenant7 = tenant_lookup_fast(&ip7->src_address, &vrf7);

      /* Store tenant IDs */
      op0->tenant_id = tenant0;
      op1->tenant_id = tenant1;
      op2->tenant_id = tenant2;
      op3->tenant_id = tenant3;
      op4->tenant_id = tenant4;
      op5->tenant_id = tenant5;
      op6->tenant_id = tenant6;
      op7->tenant_id = tenant7;

      /* All continue to security graph */
      next[0] = next[1] = next[2] = next[3] = next[4] = next[5] = next[6] =
          next[7] = OPENSASE_TENANT_NEXT_SECURITY;
    }

    b += 8;
    next += 8;
    n_left_from -= 8;
  }

  /* Process remaining 4 at a time */
  while (n_left_from >= 4) {
    ip4_header_t *ip0, *ip1, *ip2, *ip3;
    opensase_buffer_opaque_t *op0, *op1, *op2, *op3;
    u32 tenant0, tenant1, tenant2, tenant3;
    u32 vrf0, vrf1, vrf2, vrf3;

    ip0 = vlib_buffer_get_current(b[0]);
    ip1 = vlib_buffer_get_current(b[1]);
    ip2 = vlib_buffer_get_current(b[2]);
    ip3 = vlib_buffer_get_current(b[3]);

    op0 = opensase_buffer_opaque(b[0]);
    op1 = opensase_buffer_opaque(b[1]);
    op2 = opensase_buffer_opaque(b[2]);
    op3 = opensase_buffer_opaque(b[3]);

    tenant0 = tenant_lookup_fast(&ip0->src_address, &vrf0);
    tenant1 = tenant_lookup_fast(&ip1->src_address, &vrf1);
    tenant2 = tenant_lookup_fast(&ip2->src_address, &vrf2);
    tenant3 = tenant_lookup_fast(&ip3->src_address, &vrf3);

    op0->tenant_id = tenant0;
    op1->tenant_id = tenant1;
    op2->tenant_id = tenant2;
    op3->tenant_id = tenant3;

    next[0] = next[1] = next[2] = next[3] = OPENSASE_TENANT_NEXT_SECURITY;

    b += 4;
    next += 4;
    n_left_from -= 4;
  }

  /* Single packet processing */
  while (n_left_from > 0) {
    ip4_header_t *ip0 = vlib_buffer_get_current(b[0]);
    opensase_buffer_opaque_t *op0 = opensase_buffer_opaque(b[0]);
    u32 vrf0;

    op0->tenant_id = tenant_lookup_fast(&ip0->src_address, &vrf0);
    next[0] = OPENSASE_TENANT_NEXT_SECURITY;

    b += 1;
    next += 1;
    n_left_from -= 1;
  }

  vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE(opensase_tenant_node) = {
    .name = "opensase-tenant",
    .vector_size = sizeof(u32),
    .format_trace = format_opensase_tenant_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_next_nodes = OPENSASE_TENANT_N_NEXT,
    .next_nodes =
        {
            [OPENSASE_TENANT_NEXT_SECURITY] = "opensase-security",
            [OPENSASE_TENANT_NEXT_DROP] = "error-drop",
        },
};

/* CLI to add tenant mapping */
static clib_error_t *opensase_tenant_add_fn(vlib_main_t *vm,
                                            unformat_input_t *input,
                                            vlib_cli_command_t *cmd) {
  ip4_address_t prefix;
  u8 prefix_len = 24;
  u32 tenant_id = 1;
  u32 vrf_id = 0;
  u32 hash, i;
  tenant_bucket_t *bucket;

  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(input, "%U/%d", unformat_ip4_address, &prefix, &prefix_len))
      ;
    else if (unformat(input, "tenant %u", &tenant_id))
      ;
    else if (unformat(input, "vrf %u", &vrf_id))
      ;
    else
      return clib_error_return(0, "unknown input");
  }

  hash = clib_xxhash(prefix.as_u32) & TENANT_HASH_MASK;
  bucket = &tenant_hash[hash];

  /* Find free slot */
  for (i = 0; i < 4; i++) {
    if (!bucket->entries[i].valid) {
      bucket->entries[i].src_prefix = prefix;
      bucket->entries[i].prefix_len = prefix_len;
      bucket->entries[i].tenant_id = tenant_id;
      bucket->entries[i].vrf_id = vrf_id;
      bucket->entries[i].valid = 1;

      vlib_cli_output(vm, "Tenant mapping added: %U/%d -> tenant %u",
                      format_ip4_address, &prefix, prefix_len, tenant_id);
      return 0;
    }
  }

  return clib_error_return(0, "hash bucket full");
}

VLIB_CLI_COMMAND(opensase_tenant_add_command, static) = {
    .path = "opensase tenant add",
    .short_help = "opensase tenant add <prefix>/<len> tenant <id> [vrf <id>]",
    .function = opensase_tenant_add_fn,
};
