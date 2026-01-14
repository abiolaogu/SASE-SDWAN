# OBMO BGP Session Management Module

variable "pop_name" {
  type = string
}

variable "provider_type" {
  type = string
}

variable "server_ips" {
  description = "Server public IPs for BGP sessions"
  type        = list(string)
}

variable "bgp_asn" {
  description = "Local ASN"
  type        = number
  default     = 65100
}

variable "peer_asn" {
  description = "Peer ASN (provider's BGP ASN)"
  type        = number
  default     = 65530
}

variable "peer_ip" {
  description = "BGP peer IP"
  type        = string
  default     = ""
}

variable "anycast_prefixes" {
  description = "IPv4 prefixes to announce"
  type        = list(string)
  default     = []
}

variable "anycast_prefixes_v6" {
  description = "IPv6 prefixes to announce"
  type        = list(string)
  default     = []
}

variable "bgp_password" {
  description = "BGP session MD5 password"
  type        = string
  sensitive   = true
  default     = ""
}

# ===========================================
# Provider-Specific BGP Configuration
# ===========================================

locals {
  provider_bgp = {
    equinix = {
      peer_asn   = 65530
      peer_ip_v4 = "169.254.255.1"
      peer_ip_v6 = "2604:1380:4641:c500::1"
      multihop   = 2
    }
    ovh = {
      peer_asn   = 16276
      peer_ip_v4 = var.peer_ip
      multihop   = 1
    }
    hetzner = {
      peer_asn   = 24940
      peer_ip_v4 = var.peer_ip
      multihop   = 1
    }
    phoenixnap = {
      peer_asn   = 395950
      peer_ip_v4 = var.peer_ip
      multihop   = 2
    }
    # Default for providers without BGP
    default = {
      peer_asn   = var.peer_asn
      peer_ip_v4 = var.peer_ip
      multihop   = 1
    }
  }
  
  bgp_config = lookup(local.provider_bgp, var.provider_type, local.provider_bgp["default"])
}

# ===========================================
# BIRD Configuration File
# ===========================================

resource "local_file" "bird_conf" {
  filename = "${path.module}/generated/${var.pop_name}-bird.conf"
  
  content = <<-EOF
# OBMO BGP Configuration
# PoP: ${var.pop_name}
# Local ASN: ${var.bgp_asn}
# Peer ASN: ${local.bgp_config.peer_asn}

log syslog all;
log stderr { error, fatal };

router id from "lo";

define MY_AS = ${var.bgp_asn};
define PEER_AS = ${local.bgp_config.peer_asn};

protocol device { scan time 10; }

protocol direct {
    ipv4;
    ipv6;
    interface "lo", "lo:*";
}

protocol kernel kernel4 {
    ipv4 { export all; import none; };
    learn;
    persist;
}

protocol kernel kernel6 {
    ipv6 { export all; import none; };
    learn;
    persist;
}

# Anycast routes
protocol static static_anycast {
    ipv4;
%{ for prefix in var.anycast_prefixes ~}
    route ${prefix} blackhole;
%{ endfor ~}
}

%{ if length(var.anycast_prefixes_v6) > 0 ~}
protocol static static_anycast6 {
    ipv6;
%{ for prefix in var.anycast_prefixes_v6 ~}
    route ${prefix} blackhole;
%{ endfor ~}
}
%{ endif ~}

# BGP session to ${var.provider_type}
protocol bgp ${var.provider_type}_v4 {
    local as MY_AS;
    neighbor ${local.bgp_config.peer_ip_v4} as PEER_AS;
    multihop ${local.bgp_config.multihop};
%{ if var.bgp_password != "" ~}
    password "${var.bgp_password}";
%{ endif ~}
    hold time 90;
    keepalive time 30;
    graceful restart on;
    
    ipv4 {
        import none;
        export filter {
%{ for prefix in var.anycast_prefixes ~}
            if net = ${prefix} then accept;
%{ endfor ~}
            reject;
        };
        next hop self;
    };
}

# BFD for fast failover
protocol bfd {
    interface "*" {
        min rx interval 100 ms;
        min tx interval 100 ms;
        multiplier 3;
    };
}
EOF
}

# ===========================================
# Outputs
# ===========================================

output "bgp_config" {
  value = {
    local_asn   = var.bgp_asn
    peer_asn    = local.bgp_config.peer_asn
    peer_ip     = local.bgp_config.peer_ip_v4
    prefixes_v4 = var.anycast_prefixes
    prefixes_v6 = var.anycast_prefixes_v6
  }
}

output "bird_config_path" {
  value = local_file.bird_conf.filename
}
