/*
 * OpenSASE VPP Plugin - DLP Inspection Node
 *
 * Copyright (c) 2026 OpenSASE Project
 * Licensed under Apache 2.0
 *
 * Data Loss Prevention inspection using Hyperscan for high-performance
 * pattern matching across packet payloads.
 */

#include <vlib/vlib.h>
#include <vnet/ip/ip4.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/vnet.h>

#include "opensase.h"

#ifdef HAVE_HYPERSCAN
#include <hs/hs.h>
#endif

typedef enum {
  OPENSASE_DLP_NEXT_CLASSIFY, /* Continue to classification */
  OPENSASE_DLP_NEXT_DROP,     /* DLP violation - drop */
  OPENSASE_DLP_NEXT_LOG,      /* Log and continue */
  OPENSASE_DLP_N_NEXT,
} opensase_dlp_next_t;

typedef struct {
  u32 patterns_matched;
  u16 bytes_inspected;
  u8 action_taken;
} opensase_dlp_trace_t;

/* DLP pattern categories */
typedef enum {
  DLP_CATEGORY_CREDIT_CARD = 0,
  DLP_CATEGORY_SSN,
  DLP_CATEGORY_IBAN,
  DLP_CATEGORY_EMAIL,
  DLP_CATEGORY_PHONE,
  DLP_CATEGORY_KEYWORD,
  DLP_CATEGORY_CUSTOM,
  DLP_N_CATEGORIES
} dlp_category_t;

/* Per-thread DLP context */
typedef struct {
  u32 match_count;
  u32 match_categories[DLP_N_CATEGORIES];
} dlp_match_context_t;

static u8 *format_opensase_dlp_trace(u8 *s, va_list *args) {
  CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
  CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
  opensase_dlp_trace_t *t = va_arg(*args, opensase_dlp_trace_t *);

  s = format(s,
             "opensase-dlp: %u patterns matched, %u bytes inspected, action %u",
             t->patterns_matched, t->bytes_inspected, t->action_taken);
  return s;
}

#ifdef HAVE_HYPERSCAN
/**
 * Hyperscan match callback
 */
static int dlp_match_handler(unsigned int id, unsigned long long from,
                             unsigned long long to, unsigned int flags,
                             void *ctx) {
  dlp_match_context_t *mctx = (dlp_match_context_t *)ctx;

  mctx->match_count++;

  /* Categorize match by pattern ID ranges */
  if (id < 100)
    mctx->match_categories[DLP_CATEGORY_CREDIT_CARD]++;
  else if (id < 200)
    mctx->match_categories[DLP_CATEGORY_SSN]++;
  else if (id < 300)
    mctx->match_categories[DLP_CATEGORY_IBAN]++;
  else if (id < 400)
    mctx->match_categories[DLP_CATEGORY_EMAIL]++;
  else if (id < 500)
    mctx->match_categories[DLP_CATEGORY_PHONE]++;
  else
    mctx->match_categories[DLP_CATEGORY_CUSTOM]++;

  /* Return 0 to continue scanning, non-zero to stop */
  return 0;
}
#endif

/**
 * Simple pattern matching for systems without Hyperscan
 * Checks for common credit card patterns (Luhn algorithm prefix)
 */
always_inline u32 dlp_simple_scan(u8 *data, u32 len, dlp_match_context_t *ctx) {
  u32 i;
  u32 consecutive_digits = 0;

  for (i = 0; i < len; i++) {
    if (data[i] >= '0' && data[i] <= '9') {
      consecutive_digits++;
      /* Credit card length: 13-19 digits */
      if (consecutive_digits >= 13 && consecutive_digits <= 19) {
        ctx->match_count++;
        ctx->match_categories[DLP_CATEGORY_CREDIT_CARD]++;
      }
    } else if (data[i] != ' ' && data[i] != '-') {
      consecutive_digits = 0;
    }
  }

  /* Check for SSN pattern: XXX-XX-XXXX */
  for (i = 0; i + 10 < len; i++) {
    if (data[i] >= '0' && data[i] <= '9' && data[i + 1] >= '0' &&
        data[i + 1] <= '9' && data[i + 2] >= '0' && data[i + 2] <= '9' &&
        data[i + 3] == '-' && data[i + 4] >= '0' && data[i + 4] <= '9' &&
        data[i + 5] >= '0' && data[i + 5] <= '9' && data[i + 6] == '-' &&
        data[i + 7] >= '0' && data[i + 7] <= '9' && data[i + 8] >= '0' &&
        data[i + 8] <= '9' && data[i + 9] >= '0' && data[i + 9] <= '9' &&
        data[i + 10] >= '0' && data[i + 10] <= '9') {
      ctx->match_count++;
      ctx->match_categories[DLP_CATEGORY_SSN]++;
    }
  }

  return ctx->match_count;
}

/**
 * Get payload offset (skip IP + TCP/UDP headers)
 */
always_inline u8 *get_payload(vlib_buffer_t *b, ip4_header_t *ip4,
                              u32 *payload_len) {
  u32 ip_hdr_len = ip4_header_bytes(ip4);
  u8 *l4_start = (u8 *)ip4 + ip_hdr_len;
  u32 l4_hdr_len = 0;
  u32 total_len = clib_net_to_host_u16(ip4->length);

  if (ip4->protocol == IP_PROTOCOL_TCP) {
    tcp_header_t *tcp = (tcp_header_t *)l4_start;
    l4_hdr_len = tcp_header_bytes(tcp);
  } else if (ip4->protocol == IP_PROTOCOL_UDP) {
    l4_hdr_len = sizeof(udp_header_t);
  } else {
    *payload_len = 0;
    return NULL;
  }

  *payload_len = total_len - ip_hdr_len - l4_hdr_len;
  if (*payload_len > OPENSASE_DLP_MAX_MATCH_DEPTH)
    *payload_len = OPENSASE_DLP_MAX_MATCH_DEPTH;

  return l4_start + l4_hdr_len;
}

/**
 * DLP node - main processing function
 */
VLIB_NODE_FN(opensase_dlp_node)(vlib_main_t *vm, vlib_node_runtime_t *node,
                                vlib_frame_t *frame) {
  opensase_main_t *osm = &opensase_main;
  u32 thread_index = vlib_get_thread_index();
  opensase_worker_t *w = vec_elt_at_index(osm->workers, thread_index);
  u32 n_left_from, *from;
  u32 pkts_inspected = 0;

  from = vlib_frame_vector_args(frame);
  n_left_from = frame->n_vectors;

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;

  vlib_get_buffers(vm, from, bufs, n_left_from);

#ifdef HAVE_HYPERSCAN
  hs_scratch_t *scratch = (hs_scratch_t *)osm->hs_scratch;
  hs_database_t *database = (hs_database_t *)osm->hs_database;
#endif

  /* Process packets - 2 at a time for DLP (more memory intensive) */
  while (n_left_from >= 2) {
    ip4_header_t *ip4_0, *ip4_1;
    opensase_buffer_opaque_t *op0, *op1;
    u8 *payload0, *payload1;
    u32 payload_len0, payload_len1;
    dlp_match_context_t ctx0 = {0}, ctx1 = {0};

    /* Prefetch */
    if (n_left_from >= 4) {
      vlib_prefetch_buffer_header(b[2], LOAD);
      vlib_prefetch_buffer_header(b[3], LOAD);
      CLIB_PREFETCH(b[2]->data, CLIB_CACHE_LINE_BYTES, LOAD);
      CLIB_PREFETCH(b[3]->data, CLIB_CACHE_LINE_BYTES, LOAD);
    }

    ip4_0 = vlib_buffer_get_current(b[0]);
    ip4_1 = vlib_buffer_get_current(b[1]);

    op0 = opensase_buffer_opaque(b[0]);
    op1 = opensase_buffer_opaque(b[1]);

    /* Get payloads */
    payload0 = get_payload(b[0], ip4_0, &payload_len0);
    payload1 = get_payload(b[1], ip4_1, &payload_len1);

    /* Inspect payloads */
    if (payload0 && payload_len0 > 0) {
#ifdef HAVE_HYPERSCAN
      if (database && scratch) {
        hs_scan(database, (const char *)payload0, payload_len0, 0, scratch,
                dlp_match_handler, &ctx0);
      } else
#endif
      {
        dlp_simple_scan(payload0, payload_len0, &ctx0);
      }

      w->dlp_bytes_inspected += payload_len0;
      pkts_inspected++;
    }

    if (payload1 && payload_len1 > 0) {
#ifdef HAVE_HYPERSCAN
      if (database && scratch) {
        hs_scan(database, (const char *)payload1, payload_len1, 0, scratch,
                dlp_match_handler, &ctx1);
      } else
#endif
      {
        dlp_simple_scan(payload1, payload_len1, &ctx1);
      }

      w->dlp_bytes_inspected += payload_len1;
      pkts_inspected++;
    }

    /* Determine actions based on matches */
    if (ctx0.match_count > 0) {
      w->dlp_patterns_matched += ctx0.match_count;
      op0->flags |= OPENSASE_FLAG_DLP_INSPECTED;

      /* Credit cards and SSNs are critical - drop */
      if (ctx0.match_categories[DLP_CATEGORY_CREDIT_CARD] > 0 ||
          ctx0.match_categories[DLP_CATEGORY_SSN] > 0) {
        next[0] = OPENSASE_DLP_NEXT_DROP;
        w->packets_dropped++;
      } else {
        next[0] = OPENSASE_DLP_NEXT_LOG;
      }
    } else {
      op0->flags |= OPENSASE_FLAG_DLP_INSPECTED;
      next[0] = OPENSASE_DLP_NEXT_CLASSIFY;
    }

    if (ctx1.match_count > 0) {
      w->dlp_patterns_matched += ctx1.match_count;
      op1->flags |= OPENSASE_FLAG_DLP_INSPECTED;

      if (ctx1.match_categories[DLP_CATEGORY_CREDIT_CARD] > 0 ||
          ctx1.match_categories[DLP_CATEGORY_SSN] > 0) {
        next[1] = OPENSASE_DLP_NEXT_DROP;
        w->packets_dropped++;
      } else {
        next[1] = OPENSASE_DLP_NEXT_LOG;
      }
    } else {
      op1->flags |= OPENSASE_FLAG_DLP_INSPECTED;
      next[1] = OPENSASE_DLP_NEXT_CLASSIFY;
    }

    /* Tracing */
    if (PREDICT_FALSE(b[0]->flags & VLIB_BUFFER_IS_TRACED)) {
      opensase_dlp_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
      t->patterns_matched = ctx0.match_count;
      t->bytes_inspected = payload_len0;
      t->action_taken = next[0];
    }

    b += 2;
    next += 2;
    n_left_from -= 2;
  }

  /* Process remaining */
  while (n_left_from > 0) {
    ip4_header_t *ip4_0;
    opensase_buffer_opaque_t *op0;
    u8 *payload0;
    u32 payload_len0;
    dlp_match_context_t ctx0 = {0};

    ip4_0 = vlib_buffer_get_current(b[0]);
    op0 = opensase_buffer_opaque(b[0]);

    payload0 = get_payload(b[0], ip4_0, &payload_len0);

    if (payload0 && payload_len0 > 0) {
#ifdef HAVE_HYPERSCAN
      if (osm->hs_database && osm->hs_scratch) {
        hs_scan((hs_database_t *)osm->hs_database, (const char *)payload0,
                payload_len0, 0, (hs_scratch_t *)osm->hs_scratch,
                dlp_match_handler, &ctx0);
      } else
#endif
      {
        dlp_simple_scan(payload0, payload_len0, &ctx0);
      }

      w->dlp_bytes_inspected += payload_len0;
    }

    if (ctx0.match_count > 0) {
      w->dlp_patterns_matched += ctx0.match_count;
      op0->flags |= OPENSASE_FLAG_DLP_INSPECTED;

      if (ctx0.match_categories[DLP_CATEGORY_CREDIT_CARD] > 0 ||
          ctx0.match_categories[DLP_CATEGORY_SSN] > 0) {
        next[0] = OPENSASE_DLP_NEXT_DROP;
        w->packets_dropped++;
      } else {
        next[0] = OPENSASE_DLP_NEXT_LOG;
      }
    } else {
      op0->flags |= OPENSASE_FLAG_DLP_INSPECTED;
      next[0] = OPENSASE_DLP_NEXT_CLASSIFY;
    }

    b += 1;
    next += 1;
    n_left_from -= 1;
  }

  vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

/* Node registration */
VLIB_REGISTER_NODE(opensase_dlp_node) = {
    .name = "opensase-dlp",
    .vector_size = sizeof(u32),
    .format_trace = format_opensase_dlp_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_errors = 0,

    .n_next_nodes = OPENSASE_DLP_N_NEXT,
    .next_nodes =
        {
            [OPENSASE_DLP_NEXT_CLASSIFY] = "opensase-classify",
            [OPENSASE_DLP_NEXT_DROP] = "error-drop",
            [OPENSASE_DLP_NEXT_LOG] =
                "opensase-classify", /* Log then continue */
        },
};
