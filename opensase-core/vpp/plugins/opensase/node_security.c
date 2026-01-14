/*
 * OpenSASE VPP Plugin - Security Node (Entry Point)
 *
 * Copyright (c) 2026 OpenSASE Project
 * Licensed under Apache 2.0
 *
 * Entry point graph node for all SASE processing.
 * Performs session lookup/creation and routes to subsequent nodes.
 */

#include <vlib/vlib.h>
#include <vnet/ip/ip4.h>
#include <vnet/vnet.h>
#include <vppinfra/xxhash.h>

#include "opensase.h"

typedef enum {
  OPENSASE_SECURITY_NEXT_POLICY,     /* Continue to policy node */
  OPENSASE_SECURITY_NEXT_DROP,       /* Drop packet */
  OPENSASE_SECURITY_NEXT_IP4_LOOKUP, /* Bypass SASE, normal forwarding */
  OPENSASE_SECURITY_N_NEXT,
} opensase_security_next_t;

typedef struct {
  u32 session_idx;
  u32 tenant_id;
  u8 is_new_session;
} opensase_security_trace_t;

static u8 *format_opensase_security_trace(u8 *s, va_list *args) {
  CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
  CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
  opensase_security_trace_t *t = va_arg(*args, opensase_security_trace_t *);

  s = format(s, "opensase-security: session %u tenant %u %s", t->session_idx,
             t->tenant_id, t->is_new_session ? "(new)" : "");
  return s;
}

/**
 * Compute 5-tuple hash for session lookup
 */
always_inline u64 opensase_session_hash(ip4_header_t *ip4, u16 src_port,
                                        u16 dst_port) {
  u64 key[2];

  key[0] = ((u64)ip4->src_address.as_u32 << 32) | ip4->dst_address.as_u32;
  key[1] = ((u64)src_port << 48) | ((u64)dst_port << 32) | ip4->protocol;

  return clib_xxhash(key[0] ^ key[1]);
}

/**
 * Lookup or create session
 */
always_inline opensase_session_t *
opensase_session_lookup_or_create(opensase_worker_t *w, ip4_header_t *ip4,
                                  u16 src_port, u16 dst_port, u32 *session_idx,
                                  u8 *is_new) {
  u64 hash = opensase_session_hash(ip4, src_port, dst_port);
  uword *p;
  opensase_session_t *s;

  /* Lookup existing session */
  p = hash_get(w->session_hash, hash);
  if (p) {
    *session_idx = p[0];
    *is_new = 0;
    return vec_elt_at_index(w->sessions, *session_idx);
  }

  /* Create new session */
  if (w->n_sessions >= vec_len(w->sessions)) {
    /* Table full - should trigger cleanup */
    *session_idx = ~0;
    *is_new = 0;
    return NULL;
  }

  *session_idx = w->n_sessions++;
  *is_new = 1;

  s = vec_elt_at_index(w->sessions, *session_idx);
  clib_memset(s, 0, sizeof(*s));

  /* Initialize session */
  ip46_address_set_ip4(&s->src_addr, &ip4->src_address);
  ip46_address_set_ip4(&s->dst_addr, &ip4->dst_address);
  s->src_port = src_port;
  s->dst_port = dst_port;
  s->protocol = ip4->protocol;
  s->state = OPENSASE_SESSION_NEW;
  s->last_active = vlib_time_now(vlib_get_main());

  /* Add to hash */
  hash_set(w->session_hash, hash, *session_idx);
  w->sessions_created++;

  return s;
}

/**
 * Security node - main processing function
 * Processes packets in vectors for maximum performance
 */
VLIB_NODE_FN(opensase_security_node)(vlib_main_t *vm, vlib_node_runtime_t *node,
                                     vlib_frame_t *frame) {
  opensase_main_t *osm = &opensase_main;
  u32 thread_index = vlib_get_thread_index();
  opensase_worker_t *w = vec_elt_at_index(osm->workers, thread_index);
  u32 n_left_from, *from;
  u32 pkts_processed = 0;

  from = vlib_frame_vector_args(frame);
  n_left_from = frame->n_vectors;

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;

  vlib_get_buffers(vm, from, bufs, n_left_from);

  /* Process 4 packets at a time for better pipelining */
  while (n_left_from >= 4) {
    /* Prefetch next iteration */
    if (n_left_from >= 8) {
      vlib_prefetch_buffer_header(b[4], LOAD);
      vlib_prefetch_buffer_header(b[5], LOAD);
      vlib_prefetch_buffer_header(b[6], LOAD);
      vlib_prefetch_buffer_header(b[7], LOAD);

      CLIB_PREFETCH(b[4]->data, CLIB_CACHE_LINE_BYTES, LOAD);
      CLIB_PREFETCH(b[5]->data, CLIB_CACHE_LINE_BYTES, LOAD);
      CLIB_PREFETCH(b[6]->data, CLIB_CACHE_LINE_BYTES, LOAD);
      CLIB_PREFETCH(b[7]->data, CLIB_CACHE_LINE_BYTES, LOAD);
    }

    /* Process 4 packets */
    {
      ip4_header_t *ip4_0, *ip4_1, *ip4_2, *ip4_3;
      opensase_buffer_opaque_t *op0, *op1, *op2, *op3;
      opensase_session_t *s0, *s1, *s2, *s3;
      u16 src_port0, dst_port0, src_port1, dst_port1;
      u16 src_port2, dst_port2, src_port3, dst_port3;
      u32 session_idx0, session_idx1, session_idx2, session_idx3;
      u8 is_new0, is_new1, is_new2, is_new3;

      /* Get IP headers */
      ip4_0 = vlib_buffer_get_current(b[0]);
      ip4_1 = vlib_buffer_get_current(b[1]);
      ip4_2 = vlib_buffer_get_current(b[2]);
      ip4_3 = vlib_buffer_get_current(b[3]);

      /* Extract ports (assuming TCP/UDP) */
      if (ip4_0->protocol == IP_PROTOCOL_TCP ||
          ip4_0->protocol == IP_PROTOCOL_UDP) {
        u16 *ports = (u16 *)(ip4_0 + 1);
        src_port0 = clib_net_to_host_u16(ports[0]);
        dst_port0 = clib_net_to_host_u16(ports[1]);
      } else {
        src_port0 = dst_port0 = 0;
      }

      if (ip4_1->protocol == IP_PROTOCOL_TCP ||
          ip4_1->protocol == IP_PROTOCOL_UDP) {
        u16 *ports = (u16 *)(ip4_1 + 1);
        src_port1 = clib_net_to_host_u16(ports[0]);
        dst_port1 = clib_net_to_host_u16(ports[1]);
      } else {
        src_port1 = dst_port1 = 0;
      }

      if (ip4_2->protocol == IP_PROTOCOL_TCP ||
          ip4_2->protocol == IP_PROTOCOL_UDP) {
        u16 *ports = (u16 *)(ip4_2 + 1);
        src_port2 = clib_net_to_host_u16(ports[0]);
        dst_port2 = clib_net_to_host_u16(ports[1]);
      } else {
        src_port2 = dst_port2 = 0;
      }

      if (ip4_3->protocol == IP_PROTOCOL_TCP ||
          ip4_3->protocol == IP_PROTOCOL_UDP) {
        u16 *ports = (u16 *)(ip4_3 + 1);
        src_port3 = clib_net_to_host_u16(ports[0]);
        dst_port3 = clib_net_to_host_u16(ports[1]);
      } else {
        src_port3 = dst_port3 = 0;
      }

      /* Session lookup/creation */
      s0 = opensase_session_lookup_or_create(w, ip4_0, src_port0, dst_port0,
                                             &session_idx0, &is_new0);
      s1 = opensase_session_lookup_or_create(w, ip4_1, src_port1, dst_port1,
                                             &session_idx1, &is_new1);
      s2 = opensase_session_lookup_or_create(w, ip4_2, src_port2, dst_port2,
                                             &session_idx2, &is_new2);
      s3 = opensase_session_lookup_or_create(w, ip4_3, src_port3, dst_port3,
                                             &session_idx3, &is_new3);

      /* Store metadata in buffer opaque */
      op0 = opensase_buffer_opaque(b[0]);
      op1 = opensase_buffer_opaque(b[1]);
      op2 = opensase_buffer_opaque(b[2]);
      op3 = opensase_buffer_opaque(b[3]);

      op0->session_idx = session_idx0;
      op1->session_idx = session_idx1;
      op2->session_idx = session_idx2;
      op3->session_idx = session_idx3;

      /* Update session stats */
      if (s0) {
        s0->packets_fwd++;
        s0->bytes_fwd += vlib_buffer_length_in_chain(vm, b[0]);
        s0->last_active = vlib_time_now(vm);
      }
      if (s1) {
        s1->packets_fwd++;
        s1->bytes_fwd += vlib_buffer_length_in_chain(vm, b[1]);
        s1->last_active = vlib_time_now(vm);
      }
      if (s2) {
        s2->packets_fwd++;
        s2->bytes_fwd += vlib_buffer_length_in_chain(vm, b[2]);
        s2->last_active = vlib_time_now(vm);
      }
      if (s3) {
        s3->packets_fwd++;
        s3->bytes_fwd += vlib_buffer_length_in_chain(vm, b[3]);
        s3->last_active = vlib_time_now(vm);
      }

      /* Determine next node */
      next[0] =
          (s0) ? OPENSASE_SECURITY_NEXT_POLICY : OPENSASE_SECURITY_NEXT_DROP;
      next[1] =
          (s1) ? OPENSASE_SECURITY_NEXT_POLICY : OPENSASE_SECURITY_NEXT_DROP;
      next[2] =
          (s2) ? OPENSASE_SECURITY_NEXT_POLICY : OPENSASE_SECURITY_NEXT_DROP;
      next[3] =
          (s3) ? OPENSASE_SECURITY_NEXT_POLICY : OPENSASE_SECURITY_NEXT_DROP;

      /* Tracing */
      if (PREDICT_FALSE(b[0]->flags & VLIB_BUFFER_IS_TRACED)) {
        opensase_security_trace_t *t =
            vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->session_idx = session_idx0;
        t->tenant_id = op0->tenant_id;
        t->is_new_session = is_new0;
      }
    }

    b += 4;
    next += 4;
    n_left_from -= 4;
    pkts_processed += 4;
  }

  /* Process remaining packets one at a time */
  while (n_left_from > 0) {
    ip4_header_t *ip4_0;
    opensase_buffer_opaque_t *op0;
    opensase_session_t *s0;
    u16 src_port0, dst_port0;
    u32 session_idx0;
    u8 is_new0;

    ip4_0 = vlib_buffer_get_current(b[0]);

    if (ip4_0->protocol == IP_PROTOCOL_TCP ||
        ip4_0->protocol == IP_PROTOCOL_UDP) {
      u16 *ports = (u16 *)(ip4_0 + 1);
      src_port0 = clib_net_to_host_u16(ports[0]);
      dst_port0 = clib_net_to_host_u16(ports[1]);
    } else {
      src_port0 = dst_port0 = 0;
    }

    s0 = opensase_session_lookup_or_create(w, ip4_0, src_port0, dst_port0,
                                           &session_idx0, &is_new0);

    op0 = opensase_buffer_opaque(b[0]);
    op0->session_idx = session_idx0;

    if (s0) {
      s0->packets_fwd++;
      s0->bytes_fwd += vlib_buffer_length_in_chain(vm, b[0]);
      s0->last_active = vlib_time_now(vm);
    }

    next[0] =
        (s0) ? OPENSASE_SECURITY_NEXT_POLICY : OPENSASE_SECURITY_NEXT_DROP;

    b += 1;
    next += 1;
    n_left_from -= 1;
    pkts_processed += 1;
  }

  /* Update statistics */
  w->packets_processed += pkts_processed;

  /* Enqueue to next nodes */
  vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

/* Node registration */
VLIB_REGISTER_NODE(opensase_security_node) = {
    .name = "opensase-security",
    .vector_size = sizeof(u32),
    .format_trace = format_opensase_security_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_errors = 0,

    .n_next_nodes = OPENSASE_SECURITY_N_NEXT,
    .next_nodes =
        {
            [OPENSASE_SECURITY_NEXT_POLICY] = "opensase-policy",
            [OPENSASE_SECURITY_NEXT_DROP] = "error-drop",
            [OPENSASE_SECURITY_NEXT_IP4_LOOKUP] = "ip4-lookup",
        },
};
