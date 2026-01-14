/*
 * OpenSASE VPP Plugin - Main Plugin Registration
 *
 * Copyright (c) 2026 OpenSASE Project
 * Licensed under Apache 2.0
 *
 * Plugin initialization, graph node registration, and API setup
 */

#include <vlib/vlib.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/plugin/plugin.h>
#include <vnet/vnet.h>

#include "opensase.h"

/* Global plugin instance */
opensase_main_t opensase_main;

/* VPP Plugin Registration */
VLIB_PLUGIN_REGISTER() = {
    .version = "1.0.0",
    .description = "OpenSASE High-Performance SASE Data Plane",
};

/**
 * Initialize per-worker data structures
 */
static clib_error_t *opensase_worker_init(vlib_main_t *vm, u32 worker_index) {
  opensase_main_t *osm = &opensase_main;
  opensase_worker_t *w;

  vec_validate_aligned(osm->workers, worker_index, CLIB_CACHE_LINE_BYTES);
  w = vec_elt_at_index(osm->workers, worker_index);

  /* Allocate session table */
  vec_validate_aligned(w->sessions, osm->max_sessions_per_worker - 1,
                       CLIB_CACHE_LINE_BYTES);

  /* Initialize session hash */
  w->session_hash = hash_create(0, sizeof(u32));

  /* Zero statistics */
  clib_memset(&w->packets_processed, 0,
              sizeof(opensase_worker_t) -
                  STRUCT_OFFSET_OF(opensase_worker_t, packets_processed));

  return 0;
}

/**
 * Main plugin initialization
 */
static clib_error_t *opensase_init(vlib_main_t *vm) {
  opensase_main_t *osm = &opensase_main;
  clib_error_t *error = 0;
  u32 i;

  osm->vlib_main = vm;
  osm->vnet_main = vnet_get_main();

  /* Default configuration */
  osm->session_timeout_secs = 300; /* 5 minutes */
  osm->max_sessions_per_worker = OPENSASE_MAX_SESSIONS_PER_CORE;
  osm->dlp_enabled = 1;
  osm->logging_enabled = 1;

  /* Initialize policies vector */
  vec_validate(osm->policies, OPENSASE_MAX_POLICIES - 1);
  osm->n_policies = 0;

  /* Get number of workers */
  osm->n_workers = vlib_num_workers();
  if (osm->n_workers == 0)
    osm->n_workers = 1; /* Main thread only */

  /* Initialize per-worker data */
  for (i = 0; i < osm->n_workers; i++) {
    error = opensase_worker_init(vm, i);
    if (error)
      return error;
  }

#ifdef HAVE_HYPERSCAN
  /* Initialize Hyperscan for DLP */
  osm->hs_database = NULL;
  osm->hs_scratch = NULL;
  /* DLP patterns loaded via CLI or API */
#endif

#ifdef HAVE_NDPI
  /* Initialize nDPI for application classification */
  osm->ndpi_struct = NULL;
  /* nDPI initialized on first use */
#endif

  vlib_log_notice(vm, "OpenSASE VPP Engine initialized");
  vlib_log_notice(vm, "  Workers: %u", osm->n_workers);
  vlib_log_notice(vm, "  Max sessions/worker: %u",
                  osm->max_sessions_per_worker);
  vlib_log_notice(vm, "  DLP: %s", osm->dlp_enabled ? "enabled" : "disabled");

  return 0;
}

VLIB_INIT_FUNCTION(opensase_init);

/**
 * Add worker thread initialization
 */
static clib_error_t *opensase_worker_thread_init(vlib_main_t *vm) {
  u32 thread_index = vlib_get_thread_index();
  return opensase_worker_init(vm, thread_index);
}

VLIB_WORKER_INIT_FUNCTION(opensase_worker_thread_init);

/**
 * Plugin cleanup on shutdown
 */
static clib_error_t *opensase_exit(vlib_main_t *vm) {
  opensase_main_t *osm = &opensase_main;
  opensase_worker_t *w;
  u32 i;

  /* Free per-worker resources */
  vec_foreach_index(i, osm->workers) {
    w = vec_elt_at_index(osm->workers, i);
    vec_free(w->sessions);
    hash_free(w->session_hash);
  }
  vec_free(osm->workers);
  vec_free(osm->policies);

#ifdef HAVE_HYPERSCAN
  if (osm->hs_scratch)
    hs_free_scratch(osm->hs_scratch);
  if (osm->hs_database)
    hs_free_database(osm->hs_database);
#endif

  vlib_log_notice(vm, "OpenSASE VPP Engine shutdown complete");
  return 0;
}

VLIB_MAIN_LOOP_EXIT_FUNCTION(opensase_exit);

/**
 * Feature arc registration - insert into IPv4 path
 */
VNET_FEATURE_INIT(opensase_security_feature, static) = {
    .arc_name = "ip4-unicast",
    .node_name = "opensase-security",
    .runs_after = VNET_FEATURES("ip4-policer-classify"),
    .runs_before = VNET_FEATURES("ip4-flow-classify"),
};

/**
 * Show plugin version
 */
static clib_error_t *opensase_show_version_fn(vlib_main_t *vm,
                                              unformat_input_t *input,
                                              vlib_cli_command_t *cmd) {
  vlib_cli_output(vm, "OpenSASE VPP Engine v%d.%d.%d", OPENSASE_VERSION_MAJOR,
                  OPENSASE_VERSION_MINOR, OPENSASE_VERSION_PATCH);
  vlib_cli_output(vm, "  Built for 100+ Gbps SASE processing");
  vlib_cli_output(vm, "  Vector size: %d packets", OPENSASE_VECTOR_SIZE);
  return 0;
}

VLIB_CLI_COMMAND(opensase_show_version_command, static) = {
    .path = "show opensase version",
    .short_help = "show opensase version",
    .function = opensase_show_version_fn,
};

/**
 * Show statistics
 */
clib_error_t *opensase_show_stats_fn(vlib_main_t *vm, unformat_input_t *input,
                                     vlib_cli_command_t *cmd) {
  opensase_main_t *osm = &opensase_main;
  opensase_worker_t *w;
  u64 total_packets = 0, total_bytes = 0, total_dropped = 0;
  u64 total_sessions = 0;
  u32 i;

  vlib_cli_output(vm, "OpenSASE Statistics:");
  vlib_cli_output(vm, "====================\n");

  vec_foreach_index(i, osm->workers) {
    w = vec_elt_at_index(osm->workers, i);

    vlib_cli_output(vm, "Worker %u:", i);
    vlib_cli_output(vm, "  Packets processed: %lu", w->packets_processed);
    vlib_cli_output(vm, "  Bytes processed:   %lu", w->bytes_processed);
    vlib_cli_output(vm, "  Packets dropped:   %lu", w->packets_dropped);
    vlib_cli_output(vm, "  Active sessions:   %u", w->n_sessions);
    vlib_cli_output(vm, "  DLP patterns matched: %lu", w->dlp_patterns_matched);
    vlib_cli_output(vm, "");

    total_packets += w->packets_processed;
    total_bytes += w->bytes_processed;
    total_dropped += w->packets_dropped;
    total_sessions += w->n_sessions;
  }

  vlib_cli_output(vm, "Total:");
  vlib_cli_output(vm, "  Packets: %lu (%.2f Mpps)", total_packets,
                  (f64)total_packets / 1e6);
  vlib_cli_output(vm, "  Bytes:   %lu (%.2f GB)", total_bytes,
                  (f64)total_bytes / 1e9);
  vlib_cli_output(vm, "  Dropped: %lu", total_dropped);
  vlib_cli_output(vm, "  Sessions: %lu", total_sessions);

  return 0;
}

VLIB_CLI_COMMAND(opensase_show_stats_command, static) = {
    .path = "show opensase stats",
    .short_help = "show opensase stats",
    .function = opensase_show_stats_fn,
};

/**
 * Show active sessions
 */
clib_error_t *opensase_show_sessions_fn(vlib_main_t *vm,
                                        unformat_input_t *input,
                                        vlib_cli_command_t *cmd) {
  opensase_main_t *osm = &opensase_main;
  opensase_worker_t *w;
  opensase_session_t *s;
  u32 i, j, count = 0, limit = 20;

  if (unformat(input, "limit %u", &limit))
    ;

  vlib_cli_output(vm, "Active Sessions (limit %u):", limit);
  vlib_cli_output(vm, "%-15s %-15s %-6s %-6s %-5s %-10s %-10s", "Src IP",
                  "Dst IP", "SPort", "DPort", "Proto", "Packets", "Bytes");

  vec_foreach_index(i, osm->workers) {
    w = vec_elt_at_index(osm->workers, i);

    vec_foreach_index(j, w->sessions) {
      if (count >= limit)
        break;

      s = vec_elt_at_index(w->sessions, j);
      if (s->state == OPENSASE_SESSION_CLOSED)
        continue;

      vlib_cli_output(
          vm, "%-15U %-15U %-6u %-6u %-5u %-10lu %-10lu", format_ip46_address,
          &s->src_addr, IP46_TYPE_ANY, format_ip46_address, &s->dst_addr,
          IP46_TYPE_ANY, s->src_port, s->dst_port, s->protocol,
          s->packets_fwd + s->packets_rev, s->bytes_fwd + s->bytes_rev);
      count++;
    }
  }

  vlib_cli_output(vm, "\nTotal sessions shown: %u", count);
  return 0;
}

VLIB_CLI_COMMAND(opensase_show_sessions_command, static) = {
    .path = "show opensase sessions",
    .short_help = "show opensase sessions [limit N]",
    .function = opensase_show_sessions_fn,
};
