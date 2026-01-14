/*
 * OpenSASE VPP Plugin - Main Header
 *
 * Copyright (c) 2026 OpenSASE Project
 * Licensed under Apache 2.0
 *
 * High-performance SASE data plane for 100+ Gbps processing
 */

#ifndef __included_opensase_h__
#define __included_opensase_h__

#include <vnet/ip/ip.h>
#include <vnet/vnet.h>
#include <vppinfra/elog.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>

/* Plugin version */
#define OPENSASE_VERSION_MAJOR 1
#define OPENSASE_VERSION_MINOR 0
#define OPENSASE_VERSION_PATCH 0

/* Vector batch size - optimized for cache efficiency */
#define OPENSASE_VECTOR_SIZE 256

/* Maximum sessions per core */
#define OPENSASE_MAX_SESSIONS_PER_CORE (1 << 20) /* 1M sessions */

/* Policy table sizes */
#define OPENSASE_MAX_POLICIES 65536
#define OPENSASE_MAX_TENANTS 10000

/* DLP configuration */
#define OPENSASE_DLP_MAX_PATTERNS 1024
#define OPENSASE_DLP_MAX_MATCH_DEPTH 4096 /* bytes to inspect */

/* QoS classes */
typedef enum {
  OPENSASE_QOS_REALTIME = 0,
  OPENSASE_QOS_BUSINESS_CRITICAL,
  OPENSASE_QOS_DEFAULT,
  OPENSASE_QOS_BULK,
  OPENSASE_QOS_SCAVENGER,
  OPENSASE_QOS_N_CLASSES
} opensase_qos_class_t;

/* Policy actions */
typedef enum {
  OPENSASE_ACTION_ALLOW = 0,
  OPENSASE_ACTION_DENY,
  OPENSASE_ACTION_LOG,
  OPENSASE_ACTION_RATE_LIMIT,
  OPENSASE_ACTION_REDIRECT,
  OPENSASE_ACTION_ENCRYPT,
  OPENSASE_ACTION_INSPECT_DLP,
  OPENSASE_ACTION_N_ACTIONS
} opensase_action_t;

/* Session state */
typedef enum {
  OPENSASE_SESSION_NEW = 0,
  OPENSASE_SESSION_ESTABLISHED,
  OPENSASE_SESSION_CLOSING,
  OPENSASE_SESSION_CLOSED,
} opensase_session_state_t;

/* Per-packet metadata stored in vlib_buffer opaque */
typedef struct {
  u32 tenant_id; /* Tenant identifier */
  u32 policy_id; /* Matched policy */
  u16 app_id;    /* Application ID (from DPI) */
  u8 qos_class;  /* QoS classification */
  u8 flags;      /* Processing flags */
#define OPENSASE_FLAG_DLP_INSPECTED (1 << 0)
#define OPENSASE_FLAG_ENCRYPTED (1 << 1)
#define OPENSASE_FLAG_LOGGED (1 << 2)
#define OPENSASE_FLAG_RATE_LIMITED (1 << 3)
  u32 session_idx; /* Session table index */
} opensase_buffer_opaque_t;

/* Session entry - 64 bytes aligned for cache efficiency */
typedef struct {
  CLIB_CACHE_LINE_ALIGN_MARK(cache_line0);
  ip46_address_t src_addr; /* Source IP */
  ip46_address_t dst_addr; /* Destination IP */
  u16 src_port;            /* Source port */
  u16 dst_port;            /* Destination port */
  u8 protocol;             /* IP protocol */
  u8 state;                /* Session state */
  u8 qos_class;            /* QoS class */
  u8 pad0;
  u32 tenant_id;   /* Tenant ID */
  u32 policy_id;   /* Applied policy */
  u64 packets_fwd; /* Forward packet count */
  u64 bytes_fwd;   /* Forward byte count */
  u64 packets_rev; /* Reverse packet count */
  u64 bytes_rev;   /* Reverse byte count */
  f64 last_active; /* Last activity time */
} opensase_session_t;

STATIC_ASSERT(sizeof(opensase_session_t) == CLIB_CACHE_LINE_BYTES,
              "Session must be cache-line aligned");

/* Policy entry */
typedef struct {
  u32 policy_id; /* Policy identifier */
  u32 priority;  /* Priority (lower = higher) */
  u32 tenant_id; /* Tenant (0 = global) */

  /* Match criteria */
  ip46_address_t src_prefix;
  ip46_address_t dst_prefix;
  u8 src_prefix_len;
  u8 dst_prefix_len;
  u16 src_port_min;
  u16 src_port_max;
  u16 dst_port_min;
  u16 dst_port_max;
  u8 protocol; /* 0 = any */

  /* Actions */
  u8 action;           /* opensase_action_t */
  u8 qos_class;        /* QoS marking */
  u8 log_enabled;      /* Generate logs */
  u32 rate_limit_kbps; /* Rate limit (0 = unlimited) */
} opensase_policy_t;

/* Per-thread worker data */
typedef struct {
  CLIB_CACHE_LINE_ALIGN_MARK(cache_line0);

  /* Session table (per-worker) */
  opensase_session_t *sessions;
  u32 n_sessions;
  uword *session_hash; /* 5-tuple hash to session index */

  /* Statistics */
  u64 packets_processed;
  u64 bytes_processed;
  u64 packets_dropped;
  u64 sessions_created;
  u64 sessions_expired;
  u64 policy_hits[OPENSASE_ACTION_N_ACTIONS];

  /* DLP statistics */
  u64 dlp_patterns_matched;
  u64 dlp_bytes_inspected;

} opensase_worker_t;

/* Main plugin data structure */
typedef struct {
  /* API message ID base */
  u16 msg_id_base;

  /* Convenience pointers */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /* Global policy table (shared, RCU-protected) */
  opensase_policy_t *policies;
  u32 n_policies;

  /* Per-worker data */
  opensase_worker_t *workers;
  u32 n_workers;

  /* Configuration */
  u32 session_timeout_secs;
  u32 max_sessions_per_worker;
  u8 dlp_enabled;
  u8 logging_enabled;

  /* Node indices */
  u32 security_node_index;
  u32 policy_node_index;
  u32 dlp_node_index;
  u32 classify_node_index;
  u32 qos_node_index;

#ifdef HAVE_HYPERSCAN
  /* Hyperscan database for DLP */
  void *hs_database;
  void *hs_scratch;
#endif

#ifdef HAVE_NDPI
  /* nDPI for application classification */
  void *ndpi_struct;
#endif

} opensase_main_t;

/* Global plugin instance */
extern opensase_main_t opensase_main;

/* Get buffer opaque data */
static inline opensase_buffer_opaque_t *
opensase_buffer_opaque(vlib_buffer_t *b) {
  return (opensase_buffer_opaque_t *)b->opaque2;
}

/* Node registration declarations */
extern vlib_node_registration_t opensase_security_node;
extern vlib_node_registration_t opensase_policy_node;
extern vlib_node_registration_t opensase_dlp_node;
extern vlib_node_registration_t opensase_classify_node;
extern vlib_node_registration_t opensase_qos_node;

/* Function declarations */
clib_error_t *opensase_plugin_init(vlib_main_t *vm);
void opensase_session_expire_walk(void);

/* CLI functions */
clib_error_t *opensase_show_sessions_fn(vlib_main_t *vm,
                                        unformat_input_t *input,
                                        vlib_cli_command_t *cmd);

clib_error_t *opensase_show_stats_fn(vlib_main_t *vm, unformat_input_t *input,
                                     vlib_cli_command_t *cmd);

clib_error_t *opensase_policy_add_fn(vlib_main_t *vm, unformat_input_t *input,
                                     vlib_cli_command_t *cmd);

#endif /* __included_opensase_h__ */
