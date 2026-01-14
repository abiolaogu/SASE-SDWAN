/*
 * OpenSASE VPP Plugin - NAT/PAT Node
 *
 * Copyright (c) 2026 OpenSASE Project
 * Licensed under Apache 2.0
 *
 * Per-tenant NAT with carrier-grade port allocation.
 * Target: <800ns per packet with connection tracking.
 */

#include <vlib/vlib.h>
#include <vnet/ip/ip4.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/vnet.h>
#include <vppinfra/xxhash.h>

#include "opensase.h"

typedef enum {
  OPENSASE_NAT_NEXT_ENCRYPT, /* Continue to WireGuard encrypt */
  OPENSASE_NAT_NEXT_OUTPUT,  /* Direct to output (local traffic) */
  OPENSASE_NAT_NEXT_DROP,    /* Drop */
  OPENSASE_NAT_N_NEXT,
} opensase_nat_next_t;

typedef struct {
  ip4_address_t orig_src;
  ip4_address_t nat_src;
  u16 orig_port;
  u16 nat_port;
} opensase_nat_trace_t;

/* NAT mapping entry - 32 bytes */
typedef struct {
  ip4_address_t internal_addr;
  ip4_address_t external_addr;
  u16 internal_port;
  u16 external_port;
  u8 protocol;
  u8 flags;
  u16 tenant_id;
  u32 session_idx;
  f64 expire_time;
} nat_mapping_t;

/* Per-tenant NAT pool */
typedef struct {
  ip4_address_t external_addr; /* Public IP for this tenant */
  u16 port_start;              /* Port range start */
  u16 port_end;                /* Port range end */
  u16 next_port;               /* Next port to allocate */
  u16 pad;
} nat_pool_t;

/* NAT state - per worker */
#define NAT_TABLE_SIZE (1 << 20) /* 1M mappings */
#define NAT_TABLE_MASK (NAT_TABLE_SIZE - 1)

typedef struct {
  nat_mapping_t *mappings;
  uword *mapping_hash; /* 5-tuple -> mapping index */
  u32 n_mappings;

  /* Per-tenant pools (simplified - 256 tenants max) */
  nat_pool_t tenant_pools[256];
} nat_worker_t;

static nat_worker_t *nat_workers;

static u8 *format_opensase_nat_trace(u8 *s, va_list *args) {
  CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
  CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
  opensase_nat_trace_t *t = va_arg(*args, opensase_nat_trace_t *);

  s = format(s, "opensase-nat: %U:%u -> %U:%u", format_ip4_address,
             &t->orig_src, t->orig_port, format_ip4_address, &t->nat_src,
             t->nat_port);
  return s;
}

/**
 * Compute NAT hash from 5-tuple
 */
always_inline u64 nat_hash_key(ip4_address_t *src, ip4_address_t *dst,
                               u16 src_port, u16 dst_port, u8 proto) {
  u64 key = ((u64)src->as_u32 << 32) | dst->as_u32;
  key ^= ((u64)src_port << 48) | ((u64)dst_port << 32) | proto;
  return clib_xxhash(key);
}

/**
 * Lookup existing NAT mapping
 */
always_inline nat_mapping_t *nat_lookup(nat_worker_t *w, ip4_address_t *src,
                                        ip4_address_t *dst, u16 src_port,
                                        u16 dst_port, u8 proto) {
  u64 key = nat_hash_key(src, dst, src_port, dst_port, proto);
  uword *p = hash_get(w->mapping_hash, key);

  if (p)
    return vec_elt_at_index(w->mappings, p[0]);

  return NULL;
}

/**
 * Create new NAT mapping
 */
always_inline nat_mapping_t *
nat_create_mapping(nat_worker_t *w, u32 tenant_id, ip4_address_t *internal_addr,
                   u16 internal_port, ip4_address_t *dst, u16 dst_port,
                   u8 proto, f64 now) {
  nat_pool_t *pool;
  nat_mapping_t *m;
  u32 mapping_idx;
  u64 key;

  /* Get tenant pool */
  if (tenant_id >= 256)
    tenant_id = 0;
  pool = &w->tenant_pools[tenant_id];

  /* Check if pool is configured */
  if (pool->external_addr.as_u32 == 0) {
    /* Use default pool */
    pool = &w->tenant_pools[0];
  }

  /* Allocate port */
  u16 nat_port = pool->next_port++;
  if (pool->next_port > pool->port_end)
    pool->next_port = pool->port_start;

  /* Create mapping */
  vec_add2(w->mappings, m, 1);
  mapping_idx = m - w->mappings;

  m->internal_addr = *internal_addr;
  m->external_addr = pool->external_addr;
  m->internal_port = internal_port;
  m->external_port = nat_port;
  m->protocol = proto;
  m->tenant_id = tenant_id;
  m->expire_time = now + 300.0; /* 5 minute timeout */

  /* Add to hash */
  key = nat_hash_key(internal_addr, dst, internal_port, dst_port, proto);
  hash_set(w->mapping_hash, key, mapping_idx);

  w->n_mappings++;

  return m;
}

/**
 * Apply NAT translation to packet
 */
always_inline void nat_translate(ip4_header_t *ip4, nat_mapping_t *m) {
  /* Update source address */
  ip4->src_address = m->external_addr;

  /* Update L4 port */
  if (ip4->protocol == IP_PROTOCOL_TCP) {
    tcp_header_t *tcp = (tcp_header_t *)(ip4 + 1);
    tcp->src_port = clib_host_to_net_u16(m->external_port);
    tcp->checksum = 0; /* Recompute or use HW offload */
  } else if (ip4->protocol == IP_PROTOCOL_UDP) {
    udp_header_t *udp = (udp_header_t *)(ip4 + 1);
    udp->src_port = clib_host_to_net_u16(m->external_port);
    udp->checksum = 0; /* Optional for UDP */
  }

  /* Recompute IP checksum (incremental would be faster) */
  ip4->checksum = ip4_header_checksum(ip4);
}

/**
 * NAT node - main processing function
 */
VLIB_NODE_FN(opensase_nat_node)(vlib_main_t *vm, vlib_node_runtime_t *node,
                                vlib_frame_t *frame) {
  u32 thread_index = vlib_get_thread_index();
  nat_worker_t *w = vec_elt_at_index(nat_workers, thread_index);
  u32 n_left_from, *from;
  f64 now = vlib_time_now(vm);

  from = vlib_frame_vector_args(frame);
  n_left_from = frame->n_vectors;

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;

  vlib_get_buffers(vm, from, bufs, n_left_from);

  /* Process 4 packets at a time */
  while (n_left_from >= 4) {
    if (n_left_from >= 8) {
      vlib_prefetch_buffer_header(b[4], LOAD);
      vlib_prefetch_buffer_header(b[5], LOAD);
      CLIB_PREFETCH(b[4]->data, CLIB_CACHE_LINE_BYTES, STORE);
      CLIB_PREFETCH(b[5]->data, CLIB_CACHE_LINE_BYTES, STORE);
    }

    {
      ip4_header_t *ip0, *ip1, *ip2, *ip3;
      opensase_buffer_opaque_t *op0, *op1, *op2, *op3;
      nat_mapping_t *m0, *m1, *m2, *m3;
      u16 src_port0, dst_port0, src_port1, dst_port1;
      u16 src_port2, dst_port2, src_port3, dst_port3;

      ip0 = vlib_buffer_get_current(b[0]);
      ip1 = vlib_buffer_get_current(b[1]);
      ip2 = vlib_buffer_get_current(b[2]);
      ip3 = vlib_buffer_get_current(b[3]);

      op0 = opensase_buffer_opaque(b[0]);
      op1 = opensase_buffer_opaque(b[1]);
      op2 = opensase_buffer_opaque(b[2]);
      op3 = opensase_buffer_opaque(b[3]);

      /* Extract ports */
      u16 *ports0 = (u16 *)(ip0 + 1);
      u16 *ports1 = (u16 *)(ip1 + 1);
      u16 *ports2 = (u16 *)(ip2 + 1);
      u16 *ports3 = (u16 *)(ip3 + 1);

      src_port0 = clib_net_to_host_u16(ports0[0]);
      dst_port0 = clib_net_to_host_u16(ports0[1]);
      src_port1 = clib_net_to_host_u16(ports1[0]);
      dst_port1 = clib_net_to_host_u16(ports1[1]);
      src_port2 = clib_net_to_host_u16(ports2[0]);
      dst_port2 = clib_net_to_host_u16(ports2[1]);
      src_port3 = clib_net_to_host_u16(ports3[0]);
      dst_port3 = clib_net_to_host_u16(ports3[1]);

      /* Lookup or create NAT mappings */
      m0 = nat_lookup(w, &ip0->src_address, &ip0->dst_address, src_port0,
                      dst_port0, ip0->protocol);
      if (!m0)
        m0 = nat_create_mapping(w, op0->tenant_id, &ip0->src_address, src_port0,
                                &ip0->dst_address, dst_port0, ip0->protocol,
                                now);

      m1 = nat_lookup(w, &ip1->src_address, &ip1->dst_address, src_port1,
                      dst_port1, ip1->protocol);
      if (!m1)
        m1 = nat_create_mapping(w, op1->tenant_id, &ip1->src_address, src_port1,
                                &ip1->dst_address, dst_port1, ip1->protocol,
                                now);

      m2 = nat_lookup(w, &ip2->src_address, &ip2->dst_address, src_port2,
                      dst_port2, ip2->protocol);
      if (!m2)
        m2 = nat_create_mapping(w, op2->tenant_id, &ip2->src_address, src_port2,
                                &ip2->dst_address, dst_port2, ip2->protocol,
                                now);

      m3 = nat_lookup(w, &ip3->src_address, &ip3->dst_address, src_port3,
                      dst_port3, ip3->protocol);
      if (!m3)
        m3 = nat_create_mapping(w, op3->tenant_id, &ip3->src_address, src_port3,
                                &ip3->dst_address, dst_port3, ip3->protocol,
                                now);

      /* Apply translations */
      if (m0)
        nat_translate(ip0, m0);
      if (m1)
        nat_translate(ip1, m1);
      if (m2)
        nat_translate(ip2, m2);
      if (m3)
        nat_translate(ip3, m3);

      /* Next node - encrypt for tunnel */
      next[0] = m0 ? OPENSASE_NAT_NEXT_ENCRYPT : OPENSASE_NAT_NEXT_DROP;
      next[1] = m1 ? OPENSASE_NAT_NEXT_ENCRYPT : OPENSASE_NAT_NEXT_DROP;
      next[2] = m2 ? OPENSASE_NAT_NEXT_ENCRYPT : OPENSASE_NAT_NEXT_DROP;
      next[3] = m3 ? OPENSASE_NAT_NEXT_ENCRYPT : OPENSASE_NAT_NEXT_DROP;
    }

    b += 4;
    next += 4;
    n_left_from -= 4;
  }

  /* Single packet processing */
  while (n_left_from > 0) {
    ip4_header_t *ip0 = vlib_buffer_get_current(b[0]);
    opensase_buffer_opaque_t *op0 = opensase_buffer_opaque(b[0]);
    nat_mapping_t *m0;
    u16 *ports0 = (u16 *)(ip0 + 1);
    u16 src_port0 = clib_net_to_host_u16(ports0[0]);
    u16 dst_port0 = clib_net_to_host_u16(ports0[1]);

    m0 = nat_lookup(w, &ip0->src_address, &ip0->dst_address, src_port0,
                    dst_port0, ip0->protocol);
    if (!m0)
      m0 = nat_create_mapping(w, op0->tenant_id, &ip0->src_address, src_port0,
                              &ip0->dst_address, dst_port0, ip0->protocol, now);

    if (m0) {
      nat_translate(ip0, m0);
      next[0] = OPENSASE_NAT_NEXT_ENCRYPT;
    } else {
      next[0] = OPENSASE_NAT_NEXT_DROP;
    }

    b += 1;
    next += 1;
    n_left_from -= 1;
  }

  vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE(opensase_nat_node) = {
    .name = "opensase-nat",
    .vector_size = sizeof(u32),
    .format_trace = format_opensase_nat_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_next_nodes = OPENSASE_NAT_N_NEXT,
    .next_nodes =
        {
            [OPENSASE_NAT_NEXT_ENCRYPT] = "opensase-encap",
            [OPENSASE_NAT_NEXT_OUTPUT] = "ip4-lookup",
            [OPENSASE_NAT_NEXT_DROP] = "error-drop",
        },
};

/* Initialize NAT worker state */
static clib_error_t *opensase_nat_init(vlib_main_t *vm) {
  u32 n_workers = vlib_num_workers();
  u32 i, j;

  if (n_workers == 0)
    n_workers = 1;

  vec_validate(nat_workers, n_workers - 1);

  for (i = 0; i < n_workers; i++) {
    nat_worker_t *w = vec_elt_at_index(nat_workers, i);

    vec_validate(w->mappings, NAT_TABLE_SIZE - 1);
    w->mapping_hash = hash_create(0, sizeof(u32));

    /* Initialize default pool */
    w->tenant_pools[0].external_addr.as_u32 = 0;
    w->tenant_pools[0].port_start = 10000;
    w->tenant_pools[0].port_end = 65000;
    w->tenant_pools[0].next_port = 10000;
  }

  vlib_log_notice(vm, "NAT initialized: %u workers, %u mappings/worker",
                  n_workers, NAT_TABLE_SIZE);
  return 0;
}

VLIB_INIT_FUNCTION(opensase_nat_init);

/* CLI to configure NAT pool */
static clib_error_t *opensase_nat_pool_fn(vlib_main_t *vm,
                                          unformat_input_t *input,
                                          vlib_cli_command_t *cmd) {
  ip4_address_t addr;
  u32 tenant_id = 0;
  u32 port_start = 10000;
  u32 port_end = 65000;
  u32 i;

  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(input, "tenant %u", &tenant_id))
      ;
    else if (unformat(input, "address %U", unformat_ip4_address, &addr))
      ;
    else if (unformat(input, "ports %u-%u", &port_start, &port_end))
      ;
    else
      return clib_error_return(0, "unknown input");
  }

  if (tenant_id >= 256)
    return clib_error_return(0, "tenant_id must be < 256");

  /* Configure all workers */
  vec_foreach_index(i, nat_workers) {
    nat_worker_t *w = vec_elt_at_index(nat_workers, i);
    w->tenant_pools[tenant_id].external_addr = addr;
    w->tenant_pools[tenant_id].port_start = port_start;
    w->tenant_pools[tenant_id].port_end = port_end;
    w->tenant_pools[tenant_id].next_port = port_start;
  }

  vlib_cli_output(vm, "NAT pool configured: tenant %u -> %U ports %u-%u",
                  tenant_id, format_ip4_address, &addr, port_start, port_end);
  return 0;
}

VLIB_CLI_COMMAND(opensase_nat_pool_command, static) = {
    .path = "opensase nat pool",
    .short_help =
        "opensase nat pool tenant <id> address <ip> ports <start>-<end>",
    .function = opensase_nat_pool_fn,
};
