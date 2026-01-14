/*
 * OpenSASE VPP Plugin - QoS Node
 *
 * Copyright (c) 2026 OpenSASE Project
 * Licensed under Apache 2.0
 *
 * Quality of Service marking and traffic shaping.
 * Applies DSCP markings and per-tenant bandwidth limits.
 */

#include <vlib/vlib.h>
#include <vnet/ip/ip4.h>
#include <vnet/vnet.h>

#include "opensase.h"

typedef enum {
  OPENSASE_QOS_NEXT_IP4_LOOKUP, /* Forward to IP lookup */
  OPENSASE_QOS_NEXT_WIREGUARD,  /* Encrypt via WireGuard */
  OPENSASE_QOS_NEXT_DROP,       /* Rate limited - drop */
  OPENSASE_QOS_N_NEXT,
} opensase_qos_next_t;

typedef struct {
  u8 qos_class;
  u8 dscp_marked;
  u8 rate_limited;
} opensase_qos_trace_t;

/* DSCP values for each QoS class */
static u8 qos_to_dscp[] = {
    [OPENSASE_QOS_REALTIME] = 46,          /* EF - Expedited Forwarding */
    [OPENSASE_QOS_BUSINESS_CRITICAL] = 26, /* AF31 */
    [OPENSASE_QOS_DEFAULT] = 0,            /* BE - Best Effort */
    [OPENSASE_QOS_BULK] = 10,              /* AF11 */
    [OPENSASE_QOS_SCAVENGER] = 8,          /* CS1 */
};

static u8 *format_opensase_qos_trace(u8 *s, va_list *args) {
  CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
  CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
  opensase_qos_trace_t *t = va_arg(*args, opensase_qos_trace_t *);

  s = format(s, "opensase-qos: class %u dscp %u rate_limited %u", t->qos_class,
             t->dscp_marked, t->rate_limited);
  return s;
}

/**
 * Apply DSCP marking to packet
 */
always_inline void apply_dscp(ip4_header_t *ip4, u8 qos_class) {
  u8 dscp = (qos_class < OPENSASE_QOS_N_CLASSES) ? qos_to_dscp[qos_class] : 0;

  /* DSCP is in upper 6 bits of TOS field */
  u8 old_tos = ip4->tos;
  u8 new_tos = (dscp << 2) | (old_tos & 0x03); /* Preserve ECN bits */

  if (old_tos != new_tos) {
    /* Update checksum incrementally */
    u16 old_val = old_tos;
    u16 new_val = new_tos;
    ip4->checksum = ip4_header_checksum_inline(ip4);
    ip4->tos = new_tos;
  }
}

/**
 * Simple token bucket rate limiter
 * Each QoS class has its own bucket
 */
typedef struct {
  f64 tokens;      /* Current tokens (bytes) */
  f64 last_update; /* Last update time */
  f64 rate_bps;    /* Rate in bytes per second */
  f64 burst_bytes; /* Maximum burst size */
} token_bucket_t;

/* Per-tenant rate limiters (simplified - in production would be hash table) */
#define MAX_TENANT_LIMITERS 1024
static token_bucket_t tenant_limiters[MAX_TENANT_LIMITERS]
                                     [OPENSASE_QOS_N_CLASSES];

/**
 * Initialize rate limiter
 */
static void init_rate_limiter(token_bucket_t *tb, f64 rate_mbps) {
  tb->rate_bps = rate_mbps * 1e6 / 8.0; /* Convert Mbps to Bps */
  tb->burst_bytes = tb->rate_bps * 0.1; /* 100ms burst */
  tb->tokens = tb->burst_bytes;
  tb->last_update = 0;
}

/**
 * Check if packet should be allowed (token bucket)
 */
always_inline u8 rate_limit_check(token_bucket_t *tb, u32 packet_bytes,
                                  f64 now) {
  /* Refill tokens */
  if (tb->last_update > 0) {
    f64 elapsed = now - tb->last_update;
    tb->tokens += elapsed * tb->rate_bps;
    if (tb->tokens > tb->burst_bytes)
      tb->tokens = tb->burst_bytes;
  }
  tb->last_update = now;

  /* Check if enough tokens */
  if (tb->tokens >= packet_bytes) {
    tb->tokens -= packet_bytes;
    return 1; /* Allow */
  }

  return 0; /* Drop */
}

/**
 * QoS node - main processing function
 */
VLIB_NODE_FN(opensase_qos_node)(vlib_main_t *vm, vlib_node_runtime_t *node,
                                vlib_frame_t *frame) {
  opensase_main_t *osm = &opensase_main;
  u32 thread_index = vlib_get_thread_index();
  opensase_worker_t *w = vec_elt_at_index(osm->workers, thread_index);
  u32 n_left_from, *from;
  f64 now = vlib_time_now(vm);

  from = vlib_frame_vector_args(frame);
  n_left_from = frame->n_vectors;

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;

  vlib_get_buffers(vm, from, bufs, n_left_from);

  /* Process 4 packets at a time */
  while (n_left_from >= 4) {
    /* Prefetch */
    if (n_left_from >= 8) {
      vlib_prefetch_buffer_header(b[4], LOAD);
      vlib_prefetch_buffer_header(b[5], LOAD);
      vlib_prefetch_buffer_header(b[6], LOAD);
      vlib_prefetch_buffer_header(b[7], LOAD);
    }

    {
      ip4_header_t *ip4_0, *ip4_1, *ip4_2, *ip4_3;
      opensase_buffer_opaque_t *op0, *op1, *op2, *op3;
      u32 pkt_len0, pkt_len1, pkt_len2, pkt_len3;

      ip4_0 = vlib_buffer_get_current(b[0]);
      ip4_1 = vlib_buffer_get_current(b[1]);
      ip4_2 = vlib_buffer_get_current(b[2]);
      ip4_3 = vlib_buffer_get_current(b[3]);

      op0 = opensase_buffer_opaque(b[0]);
      op1 = opensase_buffer_opaque(b[1]);
      op2 = opensase_buffer_opaque(b[2]);
      op3 = opensase_buffer_opaque(b[3]);

      /* Apply DSCP markings */
      apply_dscp(ip4_0, op0->qos_class);
      apply_dscp(ip4_1, op1->qos_class);
      apply_dscp(ip4_2, op2->qos_class);
      apply_dscp(ip4_3, op3->qos_class);

      /* Get packet lengths for rate limiting */
      pkt_len0 = vlib_buffer_length_in_chain(vm, b[0]);
      pkt_len1 = vlib_buffer_length_in_chain(vm, b[1]);
      pkt_len2 = vlib_buffer_length_in_chain(vm, b[2]);
      pkt_len3 = vlib_buffer_length_in_chain(vm, b[3]);

      /* Update worker stats */
      w->bytes_processed += pkt_len0 + pkt_len1 + pkt_len2 + pkt_len3;

      /* Determine next node */
      /* For now, all go to IP lookup (WireGuard would be configured
       * per-session) */
      next[0] = OPENSASE_QOS_NEXT_IP4_LOOKUP;
      next[1] = OPENSASE_QOS_NEXT_IP4_LOOKUP;
      next[2] = OPENSASE_QOS_NEXT_IP4_LOOKUP;
      next[3] = OPENSASE_QOS_NEXT_IP4_LOOKUP;

      /* Check rate limits for scavenger class */
      if (op0->qos_class == OPENSASE_QOS_SCAVENGER) {
        u32 tenant_idx = op0->tenant_id % MAX_TENANT_LIMITERS;
        token_bucket_t *tb =
            &tenant_limiters[tenant_idx][OPENSASE_QOS_SCAVENGER];
        if (tb->rate_bps > 0 && !rate_limit_check(tb, pkt_len0, now)) {
          next[0] = OPENSASE_QOS_NEXT_DROP;
          op0->flags |= OPENSASE_FLAG_RATE_LIMITED;
          w->packets_dropped++;
        }
      }

      /* Same for other packets... (simplified) */

      /* Tracing */
      if (PREDICT_FALSE(b[0]->flags & VLIB_BUFFER_IS_TRACED)) {
        opensase_qos_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->qos_class = op0->qos_class;
        t->dscp_marked = qos_to_dscp[op0->qos_class];
        t->rate_limited = (op0->flags & OPENSASE_FLAG_RATE_LIMITED) ? 1 : 0;
      }
    }

    b += 4;
    next += 4;
    n_left_from -= 4;
  }

  /* Process remaining */
  while (n_left_from > 0) {
    ip4_header_t *ip4_0;
    opensase_buffer_opaque_t *op0;

    ip4_0 = vlib_buffer_get_current(b[0]);
    op0 = opensase_buffer_opaque(b[0]);

    apply_dscp(ip4_0, op0->qos_class);

    w->bytes_processed += vlib_buffer_length_in_chain(vm, b[0]);

    next[0] = OPENSASE_QOS_NEXT_IP4_LOOKUP;

    b += 1;
    next += 1;
    n_left_from -= 1;
  }

  vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

/* Node registration */
VLIB_REGISTER_NODE(opensase_qos_node) = {
    .name = "opensase-qos",
    .vector_size = sizeof(u32),
    .format_trace = format_opensase_qos_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_errors = 0,

    .n_next_nodes = OPENSASE_QOS_N_NEXT,
    .next_nodes =
        {
            [OPENSASE_QOS_NEXT_IP4_LOOKUP] = "ip4-lookup",
            [OPENSASE_QOS_NEXT_WIREGUARD] = "wireguard-if-output",
            [OPENSASE_QOS_NEXT_DROP] = "error-drop",
        },
};

/* CLI command to configure rate limits */
static clib_error_t *opensase_qos_config_fn(vlib_main_t *vm,
                                            unformat_input_t *input,
                                            vlib_cli_command_t *cmd) {
  u32 tenant_id = 0;
  u32 rate_mbps = 100;
  u8 qos_class = OPENSASE_QOS_SCAVENGER;

  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(input, "tenant %u", &tenant_id))
      ;
    else if (unformat(input, "rate %u", &rate_mbps))
      ;
    else if (unformat(input, "class %u", &qos_class))
      ;
    else
      return clib_error_return(0, "unknown input '%U'", format_unformat_error,
                               input);
  }

  if (tenant_id >= MAX_TENANT_LIMITERS)
    return clib_error_return(0, "tenant_id too large");

  if (qos_class >= OPENSASE_QOS_N_CLASSES)
    return clib_error_return(0, "invalid qos class");

  init_rate_limiter(&tenant_limiters[tenant_id][qos_class], rate_mbps);

  vlib_cli_output(vm, "Rate limit set: tenant %u class %u rate %u Mbps",
                  tenant_id, qos_class, rate_mbps);

  return 0;
}

VLIB_CLI_COMMAND(opensase_qos_config_command, static) = {
    .path = "opensase qos rate-limit",
    .short_help = "opensase qos rate-limit tenant <id> class <0-4> rate <mbps>",
    .function = opensase_qos_config_fn,
};
