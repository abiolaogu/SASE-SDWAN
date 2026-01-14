/*
 * OpenSASE VPP Plugin - Policy Enforcement Node
 *
 * Copyright (c) 2026 OpenSASE Project
 * Licensed under Apache 2.0
 *
 * High-performance policy lookup using radix tree and hash tables.
 * Processes 256-packet vectors for maximum throughput.
 */

#include <vlib/vlib.h>
#include <vnet/ip/ip4.h>
#include <vnet/vnet.h>

#include "opensase.h"

typedef enum {
  OPENSASE_POLICY_NEXT_DLP,        /* Continue to DLP inspection */
  OPENSASE_POLICY_NEXT_CLASSIFY,   /* Skip DLP, go to classify */
  OPENSASE_POLICY_NEXT_DROP,       /* Policy denies */
  OPENSASE_POLICY_NEXT_IP4_LOOKUP, /* Bypass all SASE */
  OPENSASE_POLICY_N_NEXT,
} opensase_policy_next_t;

typedef struct {
  u32 policy_id;
  u8 action;
  u8 qos_class;
} opensase_policy_trace_t;

static u8 *format_opensase_policy_trace(u8 *s, va_list *args) {
  CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
  CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
  opensase_policy_trace_t *t = va_arg(*args, opensase_policy_trace_t *);

  s = format(s, "opensase-policy: policy %u action %u qos %u", t->policy_id,
             t->action, t->qos_class);
  return s;
}

/**
 * Match packet against policy
 * Returns policy index or ~0 if no match
 */
always_inline u32 opensase_policy_match(opensase_main_t *osm, ip4_header_t *ip4,
                                        u16 src_port, u16 dst_port,
                                        u32 tenant_id) {
  opensase_policy_t *p;
  u32 i;
  u32 best_match = ~0;
  u32 best_priority = ~0;

  /* Simple linear search for now - will be optimized with radix tree */
  vec_foreach_index(i, osm->policies) {
    p = vec_elt_at_index(osm->policies, i);

    /* Skip empty/unused policies */
    if (p->policy_id == 0 && p->priority == 0)
      continue;

    /* Check tenant (0 = global) */
    if (p->tenant_id != 0 && p->tenant_id != tenant_id)
      continue;

    /* Check source prefix */
    if (p->src_prefix_len > 0) {
      u32 mask = ~0 << (32 - p->src_prefix_len);
      if ((ip4->src_address.as_u32 & clib_host_to_net_u32(mask)) !=
          (p->src_prefix.ip4.as_u32 & clib_host_to_net_u32(mask)))
        continue;
    }

    /* Check destination prefix */
    if (p->dst_prefix_len > 0) {
      u32 mask = ~0 << (32 - p->dst_prefix_len);
      if ((ip4->dst_address.as_u32 & clib_host_to_net_u32(mask)) !=
          (p->dst_prefix.ip4.as_u32 & clib_host_to_net_u32(mask)))
        continue;
    }

    /* Check protocol */
    if (p->protocol != 0 && p->protocol != ip4->protocol)
      continue;

    /* Check source port range */
    if (p->src_port_min != 0 || p->src_port_max != 0) {
      if (src_port < p->src_port_min || src_port > p->src_port_max)
        continue;
    }

    /* Check destination port range */
    if (p->dst_port_min != 0 || p->dst_port_max != 0) {
      if (dst_port < p->dst_port_min || dst_port > p->dst_port_max)
        continue;
    }

    /* Match found - check if better priority */
    if (p->priority < best_priority) {
      best_priority = p->priority;
      best_match = i;
    }
  }

  return best_match;
}

/**
 * Policy node - main processing function
 */
VLIB_NODE_FN(opensase_policy_node)(vlib_main_t *vm, vlib_node_runtime_t *node,
                                   vlib_frame_t *frame) {
  opensase_main_t *osm = &opensase_main;
  u32 thread_index = vlib_get_thread_index();
  opensase_worker_t *w = vec_elt_at_index(osm->workers, thread_index);
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
      vlib_prefetch_buffer_header(b[6], LOAD);
      vlib_prefetch_buffer_header(b[7], LOAD);
    }

    /* Process 4 packets */
    {
      ip4_header_t *ip4_0, *ip4_1, *ip4_2, *ip4_3;
      opensase_buffer_opaque_t *op0, *op1, *op2, *op3;
      opensase_policy_t *p0, *p1, *p2, *p3;
      u32 policy_idx0, policy_idx1, policy_idx2, policy_idx3;
      u16 src_port0, dst_port0, src_port1, dst_port1;
      u16 src_port2, dst_port2, src_port3, dst_port3;

      ip4_0 = vlib_buffer_get_current(b[0]);
      ip4_1 = vlib_buffer_get_current(b[1]);
      ip4_2 = vlib_buffer_get_current(b[2]);
      ip4_3 = vlib_buffer_get_current(b[3]);

      op0 = opensase_buffer_opaque(b[0]);
      op1 = opensase_buffer_opaque(b[1]);
      op2 = opensase_buffer_opaque(b[2]);
      op3 = opensase_buffer_opaque(b[3]);

      /* Extract ports */
      if (ip4_0->protocol == IP_PROTOCOL_TCP ||
          ip4_0->protocol == IP_PROTOCOL_UDP) {
        u16 *ports = (u16 *)(ip4_0 + 1);
        src_port0 = clib_net_to_host_u16(ports[0]);
        dst_port0 = clib_net_to_host_u16(ports[1]);
      } else
        src_port0 = dst_port0 = 0;

      if (ip4_1->protocol == IP_PROTOCOL_TCP ||
          ip4_1->protocol == IP_PROTOCOL_UDP) {
        u16 *ports = (u16 *)(ip4_1 + 1);
        src_port1 = clib_net_to_host_u16(ports[0]);
        dst_port1 = clib_net_to_host_u16(ports[1]);
      } else
        src_port1 = dst_port1 = 0;

      if (ip4_2->protocol == IP_PROTOCOL_TCP ||
          ip4_2->protocol == IP_PROTOCOL_UDP) {
        u16 *ports = (u16 *)(ip4_2 + 1);
        src_port2 = clib_net_to_host_u16(ports[0]);
        dst_port2 = clib_net_to_host_u16(ports[1]);
      } else
        src_port2 = dst_port2 = 0;

      if (ip4_3->protocol == IP_PROTOCOL_TCP ||
          ip4_3->protocol == IP_PROTOCOL_UDP) {
        u16 *ports = (u16 *)(ip4_3 + 1);
        src_port3 = clib_net_to_host_u16(ports[0]);
        dst_port3 = clib_net_to_host_u16(ports[1]);
      } else
        src_port3 = dst_port3 = 0;

      /* Policy lookup */
      policy_idx0 = opensase_policy_match(osm, ip4_0, src_port0, dst_port0,
                                          op0->tenant_id);
      policy_idx1 = opensase_policy_match(osm, ip4_1, src_port1, dst_port1,
                                          op1->tenant_id);
      policy_idx2 = opensase_policy_match(osm, ip4_2, src_port2, dst_port2,
                                          op2->tenant_id);
      policy_idx3 = opensase_policy_match(osm, ip4_3, src_port3, dst_port3,
                                          op3->tenant_id);

      /* Apply policy actions */
      if (policy_idx0 != ~0) {
        p0 = vec_elt_at_index(osm->policies, policy_idx0);
        op0->policy_id = p0->policy_id;
        op0->qos_class = p0->qos_class;
        w->policy_hits[p0->action]++;

        switch (p0->action) {
        case OPENSASE_ACTION_DENY:
          next[0] = OPENSASE_POLICY_NEXT_DROP;
          break;
        case OPENSASE_ACTION_INSPECT_DLP:
          next[0] = OPENSASE_POLICY_NEXT_DLP;
          break;
        default:
          next[0] = OPENSASE_POLICY_NEXT_CLASSIFY;
          break;
        }
      } else {
        /* No matching policy - default allow with DLP */
        next[0] = osm->dlp_enabled ? OPENSASE_POLICY_NEXT_DLP
                                   : OPENSASE_POLICY_NEXT_CLASSIFY;
      }

      /* Same for packets 1, 2, 3 */
      if (policy_idx1 != ~0) {
        p1 = vec_elt_at_index(osm->policies, policy_idx1);
        op1->policy_id = p1->policy_id;
        op1->qos_class = p1->qos_class;
        w->policy_hits[p1->action]++;
        next[1] = (p1->action == OPENSASE_ACTION_DENY)
                      ? OPENSASE_POLICY_NEXT_DROP
                  : (p1->action == OPENSASE_ACTION_INSPECT_DLP)
                      ? OPENSASE_POLICY_NEXT_DLP
                      : OPENSASE_POLICY_NEXT_CLASSIFY;
      } else
        next[1] = osm->dlp_enabled ? OPENSASE_POLICY_NEXT_DLP
                                   : OPENSASE_POLICY_NEXT_CLASSIFY;

      if (policy_idx2 != ~0) {
        p2 = vec_elt_at_index(osm->policies, policy_idx2);
        op2->policy_id = p2->policy_id;
        op2->qos_class = p2->qos_class;
        w->policy_hits[p2->action]++;
        next[2] = (p2->action == OPENSASE_ACTION_DENY)
                      ? OPENSASE_POLICY_NEXT_DROP
                  : (p2->action == OPENSASE_ACTION_INSPECT_DLP)
                      ? OPENSASE_POLICY_NEXT_DLP
                      : OPENSASE_POLICY_NEXT_CLASSIFY;
      } else
        next[2] = osm->dlp_enabled ? OPENSASE_POLICY_NEXT_DLP
                                   : OPENSASE_POLICY_NEXT_CLASSIFY;

      if (policy_idx3 != ~0) {
        p3 = vec_elt_at_index(osm->policies, policy_idx3);
        op3->policy_id = p3->policy_id;
        op3->qos_class = p3->qos_class;
        w->policy_hits[p3->action]++;
        next[3] = (p3->action == OPENSASE_ACTION_DENY)
                      ? OPENSASE_POLICY_NEXT_DROP
                  : (p3->action == OPENSASE_ACTION_INSPECT_DLP)
                      ? OPENSASE_POLICY_NEXT_DLP
                      : OPENSASE_POLICY_NEXT_CLASSIFY;
      } else
        next[3] = osm->dlp_enabled ? OPENSASE_POLICY_NEXT_DLP
                                   : OPENSASE_POLICY_NEXT_CLASSIFY;

      /* Tracing */
      if (PREDICT_FALSE(b[0]->flags & VLIB_BUFFER_IS_TRACED)) {
        opensase_policy_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->policy_id = op0->policy_id;
        t->action = (policy_idx0 != ~0) ? osm->policies[policy_idx0].action : 0;
        t->qos_class = op0->qos_class;
      }
    }

    b += 4;
    next += 4;
    n_left_from -= 4;
  }

  /* Process remaining packets */
  while (n_left_from > 0) {
    ip4_header_t *ip4_0;
    opensase_buffer_opaque_t *op0;
    opensase_policy_t *p0;
    u32 policy_idx0;
    u16 src_port0, dst_port0;

    ip4_0 = vlib_buffer_get_current(b[0]);
    op0 = opensase_buffer_opaque(b[0]);

    if (ip4_0->protocol == IP_PROTOCOL_TCP ||
        ip4_0->protocol == IP_PROTOCOL_UDP) {
      u16 *ports = (u16 *)(ip4_0 + 1);
      src_port0 = clib_net_to_host_u16(ports[0]);
      dst_port0 = clib_net_to_host_u16(ports[1]);
    } else
      src_port0 = dst_port0 = 0;

    policy_idx0 =
        opensase_policy_match(osm, ip4_0, src_port0, dst_port0, op0->tenant_id);

    if (policy_idx0 != ~0) {
      p0 = vec_elt_at_index(osm->policies, policy_idx0);
      op0->policy_id = p0->policy_id;
      op0->qos_class = p0->qos_class;
      w->policy_hits[p0->action]++;

      switch (p0->action) {
      case OPENSASE_ACTION_DENY:
        next[0] = OPENSASE_POLICY_NEXT_DROP;
        break;
      case OPENSASE_ACTION_INSPECT_DLP:
        next[0] = OPENSASE_POLICY_NEXT_DLP;
        break;
      default:
        next[0] = OPENSASE_POLICY_NEXT_CLASSIFY;
        break;
      }
    } else {
      next[0] = osm->dlp_enabled ? OPENSASE_POLICY_NEXT_DLP
                                 : OPENSASE_POLICY_NEXT_CLASSIFY;
    }

    b += 1;
    next += 1;
    n_left_from -= 1;
  }

  vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

/* Node registration */
VLIB_REGISTER_NODE(opensase_policy_node) = {
    .name = "opensase-policy",
    .vector_size = sizeof(u32),
    .format_trace = format_opensase_policy_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_errors = 0,

    .n_next_nodes = OPENSASE_POLICY_N_NEXT,
    .next_nodes =
        {
            [OPENSASE_POLICY_NEXT_DLP] = "opensase-dlp",
            [OPENSASE_POLICY_NEXT_CLASSIFY] = "opensase-classify",
            [OPENSASE_POLICY_NEXT_DROP] = "error-drop",
            [OPENSASE_POLICY_NEXT_IP4_LOOKUP] = "ip4-lookup",
        },
};
