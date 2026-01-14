# OpenSASE Peering Engine - IXP Deployment
# Provisions ports at priority IXPs

terraform {
  required_version = ">= 1.5.0"
}

# ===========================================
# Variables
# ===========================================

variable "deployment_phase" {
  description = "Deployment phase: 1 (EU), 2 (NA), 3 (APAC)"
  type        = number
  default     = 1
}

variable "port_speed_mbps" {
  description = "Default port speed"
  type        = number
  default     = 10000
}

variable "opensase_asn" {
  type    = number
  default = 65100
}

variable "enable_route_servers" {
  type    = bool
  default = true
}

# ===========================================
# Locals - IXP Database
# ===========================================

locals {
  # Complete IXP database with route server info
  ixp_database = {
    # Tier 1 - Europe
    decix_fra = {
      id              = 26
      name            = "DE-CIX Frankfurt"
      region          = "europe"
      tier            = 1
      members         = 1000
      peak_traffic_tbps = 15
      route_servers_v4 = ["80.81.192.157", "80.81.192.158"]
      route_servers_v6 = ["2001:7f8::6e28:0:1", "2001:7f8::6e28:0:2"]
      rs_asn          = 6695
      peering_lan_v4  = "80.81.192.0/22"
      peering_lan_v6  = "2001:7f8::/32"
      monthly_cost_10g = 1500
      currency        = "EUR"
      pop_location    = "fra1"
    }
    
    amsix = {
      id              = 18
      name            = "AMS-IX"
      region          = "europe"
      tier            = 1
      members         = 900
      peak_traffic_tbps = 12
      route_servers_v4 = ["80.249.208.31", "80.249.208.32"]
      route_servers_v6 = ["2001:7f8:1::a502:6695:1", "2001:7f8:1::a502:6695:2"]
      rs_asn          = 6777
      peering_lan_v4  = "80.249.208.0/21"
      peering_lan_v6  = "2001:7f8:1::/48"
      monthly_cost_10g = 1200
      currency        = "EUR"
      pop_location    = "ams1"
    }
    
    linx_lon1 = {
      id              = 10
      name            = "LINX LON1"
      region          = "europe"
      tier            = 1
      members         = 900
      peak_traffic_tbps = 8
      route_servers_v4 = ["195.66.224.1", "195.66.224.2"]
      route_servers_v6 = ["2001:7f8:4::1", "2001:7f8:4::2"]
      rs_asn          = 8714
      peering_lan_v4  = "195.66.224.0/21"
      peering_lan_v6  = "2001:7f8:4::/48"
      monthly_cost_10g = 1000
      currency        = "GBP"
      pop_location    = "lon1"
    }
    
    # Tier 1 - North America
    equinix_ash = {
      id              = 171
      name            = "Equinix Ashburn"
      region          = "north_america"
      tier            = 1
      members         = 400
      peak_traffic_tbps = 4
      route_servers_v4 = ["206.126.236.1"]
      route_servers_v6 = ["2001:504:0:2::1"]
      rs_asn          = 19754
      peering_lan_v4  = "206.126.236.0/22"
      peering_lan_v6  = "2001:504:0:2::/48"
      monthly_cost_10g = 2000
      currency        = "USD"
      pop_location    = "ash1"
    }
    
    equinix_nyc = {
      id              = 387
      name            = "Equinix New York"
      region          = "north_america"
      tier            = 1
      members         = 500
      peak_traffic_tbps = 5
      route_servers_v4 = ["198.32.124.1"]
      route_servers_v6 = ["2001:504:13::1"]
      rs_asn          = 19754
      peering_lan_v4  = "198.32.124.0/22"
      peering_lan_v6  = "2001:504:13::/48"
      monthly_cost_10g = 2000
      currency        = "USD"
      pop_location    = "nyc1"
    }
    
    # Tier 2 - North America
    six_seattle = {
      id              = 16
      name            = "SIX Seattle"
      region          = "north_america"
      tier            = 2
      members         = 300
      peak_traffic_tbps = 2
      route_servers_v4 = ["206.81.80.1"]
      route_servers_v6 = ["2001:504:16::1"]
      rs_asn          = 33108
      peering_lan_v4  = "206.81.80.0/22"
      peering_lan_v6  = "2001:504:16::/48"
      monthly_cost_10g = 1500
      currency        = "USD"
      pop_location    = "sea1"
    }
    
    any2_lax = {
      id              = 59
      name            = "Any2 Los Angeles"
      region          = "north_america"
      tier            = 2
      members         = 200
      peak_traffic_tbps = 1.5
      route_servers_v4 = ["206.72.210.1"]
      route_servers_v6 = ["2001:504:8::1"]
      rs_asn          = 7575
      peering_lan_v4  = "206.72.210.0/23"
      peering_lan_v6  = "2001:504:8::/48"
      monthly_cost_10g = 1200
      currency        = "USD"
      pop_location    = "lax1"
    }
    
    # Tier 2 - Asia Pacific
    hkix = {
      id              = 1
      name            = "HKIX"
      region          = "asia_pacific"
      tier            = 2
      members         = 300
      peak_traffic_tbps = 3
      route_servers_v4 = ["202.40.161.1"]
      route_servers_v6 = ["2001:7fa:0:1::1"]
      rs_asn          = 4635
      peering_lan_v4  = "202.40.161.0/24"
      peering_lan_v6  = "2001:7fa:0:1::/64"
      monthly_cost_10g = 1200
      currency        = "USD"
      pop_location    = "hkg1"
    }
    
    jpix_tokyo = {
      id              = 2
      name            = "JPIX Tokyo"
      region          = "asia_pacific"
      tier            = 2
      members         = 200
      peak_traffic_tbps = 2
      route_servers_v4 = ["210.171.224.1"]
      route_servers_v6 = ["2001:de8:8::1"]
      rs_asn          = 7527
      peering_lan_v4  = "210.171.224.0/23"
      peering_lan_v6  = "2001:de8:8::/48"
      monthly_cost_10g = 1300
      currency        = "USD"
      pop_location    = "tok1"
    }
    
    sgix = {
      id              = 44
      name            = "SGIX"
      region          = "asia_pacific"
      tier            = 2
      members         = 200
      peak_traffic_tbps = 1.5
      route_servers_v4 = ["103.16.102.1"]
      route_servers_v6 = ["2001:de8:12::1"]
      rs_asn          = 24482
      peering_lan_v4  = "103.16.102.0/23"
      peering_lan_v6  = "2001:de8:12::/48"
      monthly_cost_10g = 1000
      currency        = "USD"
      pop_location    = "sin1"
    }
  }
  
  # Filter by deployment phase
  phase_ixps = {
    1 = ["decix_fra", "amsix", "linx_lon1"]
    2 = ["equinix_ash", "equinix_nyc", "six_seattle", "any2_lax"]
    3 = ["hkix", "jpix_tokyo", "sgix"]
  }
  
  # IXPs for current phase
  current_ixps = {
    for key in local.phase_ixps[var.deployment_phase] :
    key => local.ixp_database[key]
  }
  
  # All IXPs up to current phase
  all_active_ixps = merge([
    for phase in range(1, var.deployment_phase + 1) : {
      for key in local.phase_ixps[phase] :
      key => local.ixp_database[key]
    }
  ]...)
}

# ===========================================
# Deploy IXP Ports
# ===========================================

module "ixp_port" {
  for_each = local.current_ixps
  source   = "./modules/ixp-port"
  
  ixp_config = {
    ixp_id       = each.value.id
    ixp_name     = each.value.name
    pop_name     = each.value.pop_location
    speed_mbps   = var.port_speed_mbps
    vlan_id      = 100 + index(keys(local.current_ixps), each.key)
  }
  
  opensase_asn = var.opensase_asn
}

# ===========================================
# Generate Master BGP Configuration
# ===========================================

resource "local_file" "master_bird_config" {
  filename = "${path.module}/generated/bird-ixp-master.conf"
  
  content = <<-EOF
# OpenSASE Peering Engine - Master BGP Configuration
# Phase ${var.deployment_phase} Deployment
# Generated: ${timestamp()}

router id 10.255.0.1;
define MY_AS = ${var.opensase_asn};

# BGP Communities
define IXP_LEARNED = (${var.opensase_asn}, 100);
define TRANSIT_LEARNED = (${var.opensase_asn}, 200);
define CUSTOMER_ROUTE = (${var.opensase_asn}, 300);

# Our prefixes
define MY_PREFIXES = [ 203.0.113.0/24 ];

# Import filter
filter ixp_import {
    # Reject bogons
    if net ~ [ 0.0.0.0/8+, 10.0.0.0/8+, 127.0.0.0/8+, 
               172.16.0.0/12+, 192.168.0.0/16+,
               224.0.0.0/4+, 240.0.0.0/4+ ] then reject;
    
    # Reject too specific
    if net.len > 24 then reject;
    
    # Reject long AS paths
    if bgp_path.len > 64 then reject;
    
    # Accept and tag
    bgp_community.add(IXP_LEARNED);
    bgp_local_pref = 150;
    accept;
}

# Export filter
filter ixp_export {
    if net ~ MY_PREFIXES then accept;
    if source = RTS_STATIC then accept;
    reject;
}

%{ for ixp_key, ixp in local.current_ixps ~}
# ========================================
# ${ixp.name} (ID: ${ixp.id})
# ========================================

%{ for i, rs in ixp.route_servers_v4 ~}
protocol bgp rs_${ixp.id}_${i + 1} {
    local as MY_AS;
    neighbor ${rs} as ${ixp.rs_asn};
    description "Route Server ${i + 1} @ ${ixp.name}";
    
    graceful restart on;
    
    ipv4 {
        import filter ixp_import;
        export filter ixp_export;
        import limit 200000 action restart;
    };
}

%{ endfor ~}
%{ endfor ~}
EOF
}

# ===========================================
# Deployment Summary
# ===========================================

resource "local_file" "deployment_summary" {
  filename = "${path.module}/generated/deployment-summary.json"
  
  content = jsonencode({
    deployment_phase = var.deployment_phase
    generated_at     = timestamp()
    
    ixps = {
      for key, ixp in local.current_ixps : key => {
        id          = ixp.id
        name        = ixp.name
        region      = ixp.region
        members     = ixp.members
        traffic_tbps = ixp.peak_traffic_tbps
        monthly_cost = ixp.monthly_cost_10g
        currency    = ixp.currency
      }
    }
    
    summary = {
      total_ixps = length(local.current_ixps)
      total_monthly_cost = sum([for ixp in local.current_ixps : ixp.monthly_cost_10g])
      regions = distinct([for ixp in local.current_ixps : ixp.region])
      expected_peers = sum([for ixp in local.current_ixps : ixp.members])
    }
  })
}

# ===========================================
# Outputs
# ===========================================

output "ixp_ports" {
  value = {
    for key, mod in module.ixp_port : key => mod.port_info
  }
}

output "route_servers" {
  value = {
    for key, ixp in local.current_ixps : key => {
      v4  = ixp.route_servers_v4
      v6  = ixp.route_servers_v6
      asn = ixp.rs_asn
    }
  }
}

output "deployment_summary" {
  value = {
    phase        = var.deployment_phase
    ixp_count    = length(local.current_ixps)
    regions      = distinct([for ixp in local.current_ixps : ixp.region])
    monthly_cost = sum([for ixp in local.current_ixps : ixp.monthly_cost_10g])
    expected_latency_reduction = "20-50%"
  }
}

output "config_files" {
  value = {
    bird_master = local_file.master_bird_config.filename
    summary     = local_file.deployment_summary.filename
  }
}
