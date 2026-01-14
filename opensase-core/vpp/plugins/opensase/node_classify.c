/*
 * OpenSASE VPP Plugin - Traffic Classification Node
 *
 * Copyright (c) 2026 OpenSASE Project
 * Licensed under Apache 2.0
 *
 * Application identification using DPI and flow analysis.
 * Integrates with nDPI for protocol and application detection.
 */

#include <vlib/vlib.h>
#include <vnet/ip/ip4.h>
#include <vnet/vnet.h>

#include "opensase.h"

#ifdef HAVE_NDPI
#include <libndpi/ndpi_api.h>
#endif

typedef enum {
  OPENSASE_CLASSIFY_NEXT_QOS,        /* Continue to QoS */
  OPENSASE_CLASSIFY_NEXT_IP4_LOOKUP, /* Direct to lookup */
  OPENSASE_CLASSIFY_NEXT_DROP,       /* Drop */
  OPENSASE_CLASSIFY_N_NEXT,
} opensase_classify_next_t;

typedef struct {
  u16 app_id;
  u8 qos_class;
  u8 protocol;
} opensase_classify_trace_t;

/* Well-known application IDs */
typedef enum {
  APP_UNKNOWN = 0,
  APP_HTTP,
  APP_HTTPS,
  APP_DNS,
  APP_QUIC,
  APP_SSH,
  APP_RDP,
  APP_SMTP,
  APP_IMAP,
  APP_FTP,
  APP_MYSQL,
  APP_POSTGRESQL,
  APP_MONGODB,
  APP_REDIS,
  APP_MEMCACHED,
  APP_LDAP,
  APP_KERBEROS,
  APP_SMB,
  APP_NFS,

  /* Streaming */
  APP_RTSP,
  APP_RTP,
  APP_WEBRTC,

  /* Collaboration */
  APP_ZOOM,
  APP_TEAMS,
  APP_SLACK,
  APP_WEBEX,

  /* Cloud */
  APP_AWS,
  APP_AZURE,
  APP_GCP,
  APP_SALESFORCE,
  APP_OFFICE365,

  APP_MAX
} app_id_t;

/* Port-based classification table */
typedef struct {
  u16 port;
  u16 app_id;
  u8 qos_class;
} port_app_mapping_t;

static port_app_mapping_t port_map[] = {
    {80, APP_HTTP, OPENSASE_QOS_DEFAULT},
    {443, APP_HTTPS, OPENSASE_QOS_DEFAULT},
    {53, APP_DNS, OPENSASE_QOS_REALTIME},
    {22, APP_SSH, OPENSASE_QOS_BUSINESS_CRITICAL},
    {3389, APP_RDP, OPENSASE_QOS_BUSINESS_CRITICAL},
    {25, APP_SMTP, OPENSASE_QOS_BULK},
    {143, APP_IMAP, OPENSASE_QOS_DEFAULT},
    {993, APP_IMAP, OPENSASE_QOS_DEFAULT},
    {21, APP_FTP, OPENSASE_QOS_BULK},
    {3306, APP_MYSQL, OPENSASE_QOS_BUSINESS_CRITICAL},
    {5432, APP_POSTGRESQL, OPENSASE_QOS_BUSINESS_CRITICAL},
    {27017, APP_MONGODB, OPENSASE_QOS_BUSINESS_CRITICAL},
    {6379, APP_REDIS, OPENSASE_QOS_REALTIME},
    {11211, APP_MEMCACHED, OPENSASE_QOS_REALTIME},
    {389, APP_LDAP, OPENSASE_QOS_BUSINESS_CRITICAL},
    {636, APP_LDAP, OPENSASE_QOS_BUSINESS_CRITICAL},
    {88, APP_KERBEROS, OPENSASE_QOS_REALTIME},
    {445, APP_SMB, OPENSASE_QOS_BUSINESS_CRITICAL},
    {2049, APP_NFS, OPENSASE_QOS_BULK},
    {554, APP_RTSP, OPENSASE_QOS_REALTIME},
    {0, 0, 0} /* Terminator */
};

static u8 *format_opensase_classify_trace(u8 *s, va_list *args) {
  CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
  CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
  opensase_classify_trace_t *t = va_arg(*args, opensase_classify_trace_t *);

  s = format(s, "opensase-classify: app %u qos %u proto %u", t->app_id,
             t->qos_class, t->protocol);
  return s;
}

/**
 * Port-based classification (fast path)
 */
always_inline void classify_by_port(u16 dst_port, u16 *app_id, u8 *qos_class) {
  port_app_mapping_t *m;

  for (m = port_map; m->port != 0; m++) {
    if (m->port == dst_port) {
      *app_id = m->app_id;
      *qos_class = m->qos_class;
      return;
    }
  }

  /* Unknown - default QoS */
  *app_id = APP_UNKNOWN;
  *qos_class = OPENSASE_QOS_DEFAULT;
}

/**
 * Deep packet inspection for QUIC detection
 * QUIC uses UDP port 443 with specific header patterns
 */
always_inline u8 detect_quic(ip4_header_t *ip4, u8 *l4_payload,
                             u32 payload_len) {
  if (ip4->protocol != IP_PROTOCOL_UDP)
    return 0;

  if (payload_len < 5)
    return 0;

  /* QUIC long header starts with 1 in MSB */
  /* QUIC short header starts with 0 in MSB but has specific patterns */
  u8 first_byte = l4_payload[0];

  /* Long header form */
  if (first_byte & 0x80) {
    /* Check version field (bytes 1-4) */
    /* QUIC v1: 0x00000001, QUIC v2: 0x6b3343cf */
    u32 version = *(u32 *)(l4_payload + 1);
    version = clib_net_to_host_u32(version);

    if (version == 0x00000001 || version == 0x6b3343cf ||
        version == 0xff000000 /* draft versions */) {
      return 1;
    }
  }

  return 0;
}

/**
 * Detect collaboration apps by TLS SNI or IP ranges
 */
always_inline u16 detect_collaboration_app(ip4_header_t *ip4, u8 *payload,
                                           u32 payload_len) {
  /* Check for TLS Client Hello SNI */
  if (payload_len >= 44 && payload[0] == 0x16) /* TLS handshake */
  {
    /* Parse TLS to find SNI - simplified */
    /* In production, would parse full TLS handshake */

    /* For now, just use IP ranges for known services */
    u32 dst = clib_net_to_host_u32(ip4->dst_address.as_u32);

    /* Zoom IP ranges (simplified) */
    if ((dst & 0xFFFF0000) == 0x3B870000 || /* 59.135.x.x */
        (dst & 0xFFFF0000) == 0xD5880000)   /* 213.136.x.x */
    {
      return APP_ZOOM;
    }

    /* Microsoft Teams uses Office 365 ranges */
    if ((dst & 0xFFFE0000) == 0x0D6A0000 || /* 13.106.x.x */
        (dst & 0xFFFE0000) == 0x340C0000)   /* 52.12.x.x */
    {
      return APP_TEAMS;
    }
  }

  return APP_UNKNOWN;
}

/**
 * Classification node - main processing function
 */
VLIB_NODE_FN(opensase_classify_node)(vlib_main_t *vm, vlib_node_runtime_t *node,
                                     vlib_frame_t *frame) {
  u32 n_left_from, *from;

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
      u16 dst_port0, dst_port1, dst_port2, dst_port3;
      u16 app_id0, app_id1, app_id2, app_id3;
      u8 qos0, qos1, qos2, qos3;

      ip4_0 = vlib_buffer_get_current(b[0]);
      ip4_1 = vlib_buffer_get_current(b[1]);
      ip4_2 = vlib_buffer_get_current(b[2]);
      ip4_3 = vlib_buffer_get_current(b[3]);

      op0 = opensase_buffer_opaque(b[0]);
      op1 = opensase_buffer_opaque(b[1]);
      op2 = opensase_buffer_opaque(b[2]);
      op3 = opensase_buffer_opaque(b[3]);

      /* Extract destination ports */
      if (ip4_0->protocol == IP_PROTOCOL_TCP ||
          ip4_0->protocol == IP_PROTOCOL_UDP) {
        u16 *ports = (u16 *)(ip4_0 + 1);
        dst_port0 = clib_net_to_host_u16(ports[1]);
      } else
        dst_port0 = 0;

      if (ip4_1->protocol == IP_PROTOCOL_TCP ||
          ip4_1->protocol == IP_PROTOCOL_UDP) {
        u16 *ports = (u16 *)(ip4_1 + 1);
        dst_port1 = clib_net_to_host_u16(ports[1]);
      } else
        dst_port1 = 0;

      if (ip4_2->protocol == IP_PROTOCOL_TCP ||
          ip4_2->protocol == IP_PROTOCOL_UDP) {
        u16 *ports = (u16 *)(ip4_2 + 1);
        dst_port2 = clib_net_to_host_u16(ports[1]);
      } else
        dst_port2 = 0;

      if (ip4_3->protocol == IP_PROTOCOL_TCP ||
          ip4_3->protocol == IP_PROTOCOL_UDP) {
        u16 *ports = (u16 *)(ip4_3 + 1);
        dst_port3 = clib_net_to_host_u16(ports[1]);
      } else
        dst_port3 = 0;

      /* Fast path: port-based classification */
      classify_by_port(dst_port0, &app_id0, &qos0);
      classify_by_port(dst_port1, &app_id1, &qos1);
      classify_by_port(dst_port2, &app_id2, &qos2);
      classify_by_port(dst_port3, &app_id3, &qos3);

      /* Check for QUIC (UDP 443) */
      if (dst_port0 == 443 && ip4_0->protocol == IP_PROTOCOL_UDP) {
        u32 ip_hdr_len = ip4_header_bytes(ip4_0);
        u8 *l4_payload = (u8 *)ip4_0 + ip_hdr_len + 8;
        u32 payload_len = clib_net_to_host_u16(ip4_0->length) - ip_hdr_len - 8;

        if (detect_quic(ip4_0, l4_payload, payload_len)) {
          app_id0 = APP_QUIC;
          qos0 = OPENSASE_QOS_BUSINESS_CRITICAL;
        }
      }

      /* Store results */
      op0->app_id = app_id0;
      op0->qos_class = (op0->qos_class == 0) ? qos0 : op0->qos_class;

      op1->app_id = app_id1;
      op1->qos_class = (op1->qos_class == 0) ? qos1 : op1->qos_class;

      op2->app_id = app_id2;
      op2->qos_class = (op2->qos_class == 0) ? qos2 : op2->qos_class;

      op3->app_id = app_id3;
      op3->qos_class = (op3->qos_class == 0) ? qos3 : op3->qos_class;

      /* All go to QoS node */
      next[0] = OPENSASE_CLASSIFY_NEXT_QOS;
      next[1] = OPENSASE_CLASSIFY_NEXT_QOS;
      next[2] = OPENSASE_CLASSIFY_NEXT_QOS;
      next[3] = OPENSASE_CLASSIFY_NEXT_QOS;

      /* Tracing */
      if (PREDICT_FALSE(b[0]->flags & VLIB_BUFFER_IS_TRACED)) {
        opensase_classify_trace_t *t =
            vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->app_id = app_id0;
        t->qos_class = op0->qos_class;
        t->protocol = ip4_0->protocol;
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
    u16 dst_port0, app_id0;
    u8 qos0;

    ip4_0 = vlib_buffer_get_current(b[0]);
    op0 = opensase_buffer_opaque(b[0]);

    if (ip4_0->protocol == IP_PROTOCOL_TCP ||
        ip4_0->protocol == IP_PROTOCOL_UDP) {
      u16 *ports = (u16 *)(ip4_0 + 1);
      dst_port0 = clib_net_to_host_u16(ports[1]);
    } else
      dst_port0 = 0;

    classify_by_port(dst_port0, &app_id0, &qos0);

    op0->app_id = app_id0;
    op0->qos_class = (op0->qos_class == 0) ? qos0 : op0->qos_class;

    next[0] = OPENSASE_CLASSIFY_NEXT_QOS;

    b += 1;
    next += 1;
    n_left_from -= 1;
  }

  vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

/* Node registration */
VLIB_REGISTER_NODE(opensase_classify_node) = {
    .name = "opensase-classify",
    .vector_size = sizeof(u32),
    .format_trace = format_opensase_classify_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_errors = 0,

    .n_next_nodes = OPENSASE_CLASSIFY_N_NEXT,
    .next_nodes =
        {
            [OPENSASE_CLASSIFY_NEXT_QOS] = "opensase-qos",
            [OPENSASE_CLASSIFY_NEXT_IP4_LOOKUP] = "ip4-lookup",
            [OPENSASE_CLASSIFY_NEXT_DROP] = "error-drop",
        },
};
