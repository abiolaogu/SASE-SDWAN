/*
 * OpenSASE VPP Plugin - Security Inspect Node (IPS)
 *
 * Copyright (c) 2026 OpenSASE Project
 * Licensed under Apache 2.0
 *
 * Intrusion Prevention System using Hyperscan for high-speed
 * signature matching at 100 Gbps.
 */

#include <vlib/vlib.h>
#include <vnet/ip/ip4.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/vnet.h>

#include "opensase.h"

#ifdef HAVE_HYPERSCAN
#include <hs/hs.h>
#endif

typedef enum {
  SECURITY_INSPECT_NEXT_NAT,  /* Continue to NAT */
  SECURITY_INSPECT_NEXT_DROP, /* IPS block - drop */
  SECURITY_INSPECT_NEXT_LOG,  /* Log and continue */
  SECURITY_INSPECT_N_NEXT,
} security_inspect_next_t;

typedef struct {
  u32 signature_id;
  u8 action;
  u16 bytes_scanned;
} security_inspect_trace_t;

/* IPS signature categories */
typedef enum {
  IPS_CAT_MALWARE = 0,
  IPS_CAT_EXPLOIT,
  IPS_CAT_BOTNET,
  IPS_CAT_CVE,
  IPS_CAT_POLICY,
  IPS_CAT_N_CATEGORIES,
} ips_category_t;

/* IPS action */
typedef enum {
  IPS_ACTION_ALERT = 0,
  IPS_ACTION_DROP,
  IPS_ACTION_REJECT,
} ips_action_t;

/* Signature match result (per thread) */
typedef struct {
  u32 signature_id;
  ips_action_t action;
  ips_category_t category;
  u8 matched;
} ips_match_result_t;

/* Per-worker IPS state */
typedef struct {
  CLIB_CACHE_LINE_ALIGN_MARK(cache_line0);

#ifdef HAVE_HYPERSCAN
  hs_scratch_t *scratch;
#endif

  /* Match result for current packet */
  ips_match_result_t current_match;

  /* Statistics */
  u64 packets_scanned;
  u64 bytes_scanned;
  u64 signatures_matched;
  u64 packets_blocked;
  u64 category_hits[IPS_CAT_N_CATEGORIES];
} ips_worker_t;

static ips_worker_t *ips_workers;

#ifdef HAVE_HYPERSCAN
static hs_database_t *ips_database;
#endif

/* Signature definitions (simplified - would load from file) */
typedef struct {
  u32 id;
  const char *pattern;
  ips_category_t category;
  ips_action_t action;
} ips_signature_t;

static const ips_signature_t default_signatures[] = {
    /* Malware patterns */
    {1001, "(?i)x-malware-signature", IPS_CAT_MALWARE, IPS_ACTION_DROP},
    {1002, "eval\\s*\\(\\s*base64_decode", IPS_CAT_MALWARE, IPS_ACTION_DROP},
    {1003, "(?i)powershell.*-enc", IPS_CAT_MALWARE, IPS_ACTION_DROP},

    /* Exploit patterns */
    {2001, "\\x00\\x00\\x00\\x00.{0,4}\\xff\\xff\\xff\\xff", IPS_CAT_EXPLOIT,
     IPS_ACTION_DROP},
    {2002, "(?i)select.*from.*information_schema", IPS_CAT_EXPLOIT,
     IPS_ACTION_DROP},
    {2003, "(?i)union.*select.*from", IPS_CAT_EXPLOIT, IPS_ACTION_DROP},

    /* Botnet C2 patterns */
    {3001, "(?i)bot.*command", IPS_CAT_BOTNET, IPS_ACTION_DROP},
    {3002, "\\x89PNG.{0,100}\\x00\\x00\\x00\\x00", IPS_CAT_BOTNET,
     IPS_ACTION_ALERT},

    /* CVE-specific patterns */
    {4001, "(?i)log4j.*\\$\\{jndi:", IPS_CAT_CVE, IPS_ACTION_DROP},
    {4002, "(?i)\\$\\{.*\\$\\{.*\\}", IPS_CAT_CVE, IPS_ACTION_DROP},

    /* Policy patterns */
    {5001, "(?i)password\\s*[:=]", IPS_CAT_POLICY, IPS_ACTION_ALERT},

    {0, NULL, 0, 0} /* Sentinel */
};

static u8 *format_security_inspect_trace(u8 *s, va_list *args) {
  CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
  CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
  security_inspect_trace_t *t = va_arg(*args, security_inspect_trace_t *);

  s = format(s, "security-inspect: sig=%u action=%u scanned=%u bytes",
             t->signature_id, t->action, t->bytes_scanned);
  return s;
}

#ifdef HAVE_HYPERSCAN
/**
 * Hyperscan match callback
 */
static int hs_match_handler(unsigned int id, unsigned long long from,
                            unsigned long long to, unsigned int flags,
                            void *ctx) {
  ips_match_result_t *result = (ips_match_result_t *)ctx;

  /* Find signature by ID */
  for (const ips_signature_t *sig = default_signatures; sig->pattern; sig++) {
    if (sig->id == id) {
      /* Only update if higher severity action */
      if (!result->matched || sig->action > result->action) {
        result->signature_id = id;
        result->action = sig->action;
        result->category = sig->category;
        result->matched = 1;
      }
      break;
    }
  }

  /* Continue scanning (return 0) or stop (return non-zero) */
  return (result->action == IPS_ACTION_DROP) ? 1 : 0;
}
#endif

/**
 * Simple pattern scanner (fallback if no Hyperscan)
 */
always_inline void simple_pattern_scan(const u8 *data, u32 len,
                                       ips_match_result_t *result) {
  /* Very basic scanning - check for known bad patterns */

  /* Log4j JNDI injection */
  if (len >= 10) {
    for (u32 i = 0; i < len - 10; i++) {
      if (data[i] == '$' && data[i + 1] == '{' &&
          (data[i + 2] == 'j' || data[i + 2] == 'J')) {
        result->signature_id = 4001;
        result->action = IPS_ACTION_DROP;
        result->category = IPS_CAT_CVE;
        result->matched = 1;
        return;
      }
    }
  }

  /* SQL injection */
  if (len >= 6) {
    for (u32 i = 0; i < len - 6; i++) {
      if ((data[i] == 'U' || data[i] == 'u') &&
          (data[i + 1] == 'N' || data[i + 1] == 'n') &&
          (data[i + 2] == 'I' || data[i + 2] == 'i') &&
          (data[i + 3] == 'O' || data[i + 3] == 'o') &&
          (data[i + 4] == 'N' || data[i + 4] == 'n')) {
        result->signature_id = 2003;
        result->action = IPS_ACTION_DROP;
        result->category = IPS_CAT_EXPLOIT;
        result->matched = 1;
        return;
      }
    }
  }
}

/**
 * Scan packet payload for IPS signatures
 */
always_inline void ips_scan_packet(ips_worker_t *w, vlib_buffer_t *b,
                                   ip4_header_t *ip4,
                                   ips_match_result_t *result) {
  u8 *payload;
  u32 payload_len;
  u32 ip_len = clib_net_to_host_u16(ip4->length);
  u32 ip_hdr_len = (ip4->ip_version_and_header_length & 0x0f) << 2;

  /* Initialize result */
  result->matched = 0;
  result->signature_id = 0;
  result->action = IPS_ACTION_ALERT;

  /* Get payload based on protocol */
  if (ip4->protocol == IP_PROTOCOL_TCP) {
    tcp_header_t *tcp = (tcp_header_t *)((u8 *)ip4 + ip_hdr_len);
    u32 tcp_hdr_len = (tcp->data_offset_and_reserved >> 4) << 2;
    payload = (u8 *)tcp + tcp_hdr_len;
    payload_len = ip_len - ip_hdr_len - tcp_hdr_len;
  } else if (ip4->protocol == IP_PROTOCOL_UDP) {
    udp_header_t *udp = (udp_header_t *)((u8 *)ip4 + ip_hdr_len);
    payload = (u8 *)(udp + 1);
    payload_len = clib_net_to_host_u16(udp->length) - sizeof(udp_header_t);
  } else {
    /* Skip other protocols */
    return;
  }

  /* Sanity check */
  if (payload_len == 0 || payload_len > 65535)
    return;

  /* Limit scan to first 1500 bytes for performance */
  if (payload_len > 1500)
    payload_len = 1500;

  w->bytes_scanned += payload_len;

#ifdef HAVE_HYPERSCAN
  if (ips_database && w->scratch) {
    hs_scan(ips_database, (const char *)payload, payload_len, 0, w->scratch,
            hs_match_handler, result);
  } else
#endif
  {
    /* Fallback to simple scanner */
    simple_pattern_scan(payload, payload_len, result);
  }
}

/**
 * Security inspect node - main processing function
 */
VLIB_NODE_FN(security_inspect_node)(vlib_main_t *vm, vlib_node_runtime_t *node,
                                    vlib_frame_t *frame) {
  u32 thread_index = vlib_get_thread_index();
  ips_worker_t *w = vec_elt_at_index(ips_workers, thread_index);
  u32 n_left_from, *from;

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
      CLIB_PREFETCH(b[4]->data, CLIB_CACHE_LINE_BYTES, LOAD);
      CLIB_PREFETCH(b[5]->data, CLIB_CACHE_LINE_BYTES, LOAD);
    }

    {
      ip4_header_t *ip0, *ip1, *ip2, *ip3;
      ips_match_result_t res0, res1, res2, res3;

      ip0 = vlib_buffer_get_current(b[0]);
      ip1 = vlib_buffer_get_current(b[1]);
      ip2 = vlib_buffer_get_current(b[2]);
      ip3 = vlib_buffer_get_current(b[3]);

      /* Scan packets */
      ips_scan_packet(w, b[0], ip0, &res0);
      ips_scan_packet(w, b[1], ip1, &res1);
      ips_scan_packet(w, b[2], ip2, &res2);
      ips_scan_packet(w, b[3], ip3, &res3);

      w->packets_scanned += 4;

      /* Determine next node based on match result */
      if (res0.matched) {
        w->signatures_matched++;
        w->category_hits[res0.category]++;

        if (res0.action == IPS_ACTION_DROP) {
          next[0] = SECURITY_INSPECT_NEXT_DROP;
          w->packets_blocked++;
        } else {
          next[0] = SECURITY_INSPECT_NEXT_LOG;
        }
      } else {
        next[0] = SECURITY_INSPECT_NEXT_NAT;
      }

      if (res1.matched) {
        w->signatures_matched++;
        w->category_hits[res1.category]++;
        next[1] = (res1.action == IPS_ACTION_DROP) ? SECURITY_INSPECT_NEXT_DROP
                                                   : SECURITY_INSPECT_NEXT_LOG;
        if (res1.action == IPS_ACTION_DROP)
          w->packets_blocked++;
      } else {
        next[1] = SECURITY_INSPECT_NEXT_NAT;
      }

      if (res2.matched) {
        w->signatures_matched++;
        w->category_hits[res2.category]++;
        next[2] = (res2.action == IPS_ACTION_DROP) ? SECURITY_INSPECT_NEXT_DROP
                                                   : SECURITY_INSPECT_NEXT_LOG;
        if (res2.action == IPS_ACTION_DROP)
          w->packets_blocked++;
      } else {
        next[2] = SECURITY_INSPECT_NEXT_NAT;
      }

      if (res3.matched) {
        w->signatures_matched++;
        w->category_hits[res3.category]++;
        next[3] = (res3.action == IPS_ACTION_DROP) ? SECURITY_INSPECT_NEXT_DROP
                                                   : SECURITY_INSPECT_NEXT_LOG;
        if (res3.action == IPS_ACTION_DROP)
          w->packets_blocked++;
      } else {
        next[3] = SECURITY_INSPECT_NEXT_NAT;
      }
    }

    b += 4;
    next += 4;
    n_left_from -= 4;
  }

  /* Single packet processing */
  while (n_left_from > 0) {
    ip4_header_t *ip0 = vlib_buffer_get_current(b[0]);
    ips_match_result_t res0;

    ips_scan_packet(w, b[0], ip0, &res0);
    w->packets_scanned++;

    if (res0.matched) {
      w->signatures_matched++;
      w->category_hits[res0.category]++;

      if (res0.action == IPS_ACTION_DROP) {
        next[0] = SECURITY_INSPECT_NEXT_DROP;
        w->packets_blocked++;
      } else {
        next[0] = SECURITY_INSPECT_NEXT_LOG;
      }
    } else {
      next[0] = SECURITY_INSPECT_NEXT_NAT;
    }

    b += 1;
    next += 1;
    n_left_from -= 1;
  }

  vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

/* Node registration */
VLIB_REGISTER_NODE(security_inspect_node) = {
    .name = "security-inspect",
    .vector_size = sizeof(u32),
    .format_trace = format_security_inspect_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_next_nodes = SECURITY_INSPECT_N_NEXT,
    .next_nodes =
        {
            [SECURITY_INSPECT_NEXT_NAT] = "nat44-in2out",
            [SECURITY_INSPECT_NEXT_DROP] = "error-drop",
            [SECURITY_INSPECT_NEXT_LOG] =
                "nat44-in2out", /* Log then continue */
        },
};

/* Initialize IPS workers */
static clib_error_t *security_inspect_init(vlib_main_t *vm) {
  u32 n_workers = vlib_num_workers();
  u32 i;

  if (n_workers == 0)
    n_workers = 1;

  vec_validate_aligned(ips_workers, n_workers - 1, CLIB_CACHE_LINE_BYTES);

#ifdef HAVE_HYPERSCAN
  /* Compile Hyperscan database */
  {
    const ips_signature_t *sig;
    u32 n_patterns = 0;
    hs_compile_error_t *compile_err;

    /* Count patterns */
    for (sig = default_signatures; sig->pattern; sig++)
      n_patterns++;

    if (n_patterns > 0) {
      const char **patterns = clib_mem_alloc(n_patterns * sizeof(char *));
      unsigned int *ids = clib_mem_alloc(n_patterns * sizeof(unsigned int));
      unsigned int *flags = clib_mem_alloc(n_patterns * sizeof(unsigned int));

      i = 0;
      for (sig = default_signatures; sig->pattern; sig++) {
        patterns[i] = sig->pattern;
        ids[i] = sig->id;
        flags[i] = HS_FLAG_CASELESS | HS_FLAG_SINGLEMATCH;
        i++;
      }

      if (hs_compile_multi(patterns, flags, ids, n_patterns, HS_MODE_BLOCK,
                           NULL, &ips_database, &compile_err) != HS_SUCCESS) {
        vlib_log_err(vm, "Hyperscan compile error: %s", compile_err->message);
        hs_free_compile_error(compile_err);
      }

      clib_mem_free((void *)patterns);
      clib_mem_free(ids);
      clib_mem_free(flags);
    }

    /* Allocate scratch per worker */
    for (i = 0; i < n_workers; i++) {
      if (ips_database) {
        hs_alloc_scratch(ips_database, &ips_workers[i].scratch);
      }
    }
  }
#endif

  vlib_log_notice(
      vm, "Security inspect initialized: %u workers, %u signatures", n_workers,
      (u32)(sizeof(default_signatures) / sizeof(default_signatures[0]) - 1));

  return 0;
}

VLIB_INIT_FUNCTION(security_inspect_init);

/* CLI: Show IPS statistics */
static clib_error_t *ips_show_stats_fn(vlib_main_t *vm, unformat_input_t *input,
                                       vlib_cli_command_t *cmd) {
  u32 i;
  u64 total_scanned = 0, total_matched = 0, total_blocked = 0;
  u64 total_bytes = 0;
  u64 cat_totals[IPS_CAT_N_CATEGORIES] = {0};
  const char *cat_names[] = {"malware", "exploit", "botnet", "cve", "policy"};

  vlib_cli_output(vm, "IPS Statistics:");
  vlib_cli_output(vm, "===============\n");

  vec_foreach_index(i, ips_workers) {
    ips_worker_t *w = vec_elt_at_index(ips_workers, i);

    total_scanned += w->packets_scanned;
    total_matched += w->signatures_matched;
    total_blocked += w->packets_blocked;
    total_bytes += w->bytes_scanned;

    for (u32 c = 0; c < IPS_CAT_N_CATEGORIES; c++)
      cat_totals[c] += w->category_hits[c];
  }

  vlib_cli_output(vm, "Packets scanned:  %lu", total_scanned);
  vlib_cli_output(vm, "Bytes scanned:    %lu", total_bytes);
  vlib_cli_output(vm, "Signatures hit:   %lu", total_matched);
  vlib_cli_output(vm, "Packets blocked:  %lu", total_blocked);
  vlib_cli_output(vm, "");
  vlib_cli_output(vm, "By category:");

  for (i = 0; i < IPS_CAT_N_CATEGORIES; i++) {
    vlib_cli_output(vm, "  %-10s: %lu", cat_names[i], cat_totals[i]);
  }

  return 0;
}

VLIB_CLI_COMMAND(ips_show_stats_command, static) = {
    .path = "show opensase ips stats",
    .short_help = "show opensase ips stats",
    .function = ips_show_stats_fn,
};
