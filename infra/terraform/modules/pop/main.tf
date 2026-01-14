# OpenSASE PoP Module
# Reusable module for deploying a complete PoP

# ===========================================
# Local Variables
# ===========================================

locals {
  pop_tags = merge(var.tags, {
    PoP         = var.pop_name
    Environment = var.environment
    ManagedBy   = "terraform"
  })
  
  # Provider-specific instance type mappings
  instance_types = {
    aws = {
      small  = "c6i.xlarge"
      medium = "c6i.2xlarge"
      large  = "c6i.4xlarge"
      xlarge = "c6i.8xlarge"
      metal  = "c6i.metal"
    }
    gcp = {
      small  = "c2-standard-4"
      medium = "c2-standard-8"
      large  = "c2-standard-16"
      xlarge = "c2-standard-30"
      metal  = "c2-standard-60"
    }
    azure = {
      small  = "Standard_F4s_v2"
      medium = "Standard_F8s_v2"
      large  = "Standard_F16s_v2"
      xlarge = "Standard_F32s_v2"
      metal  = "Standard_F72s_v2"
    }
    equinix = {
      small  = "c3.small.x86"
      medium = "c3.medium.x86"
      large  = "m3.large.x86"
      xlarge = "m3.xlarge.x86"
      metal  = "n3.xlarge.x86"
    }
    vultr = {
      small  = "vhf-4c-16gb"
      medium = "vhf-8c-32gb"
      large  = "vhf-12c-48gb"
      xlarge = "vbm-12c-32gb"
      metal  = "vbm-24c-256gb"
    }
    hetzner = {
      small  = "cpx31"
      medium = "cpx41"
      large  = "cpx51"
      xlarge = "ccx53"
      metal  = "ax52"
    }
  }
  
  # Get actual instance type for provider
  actual_instance_type = lookup(
    local.instance_types[var.provider],
    var.instance_size,
    local.instance_types[var.provider]["medium"]
  )
}

# ===========================================
# Network Module
# ===========================================

module "network" {
  source = "../vpc"
  
  cloud_provider     = var.provider
  region             = var.region
  pop_name           = var.pop_name
  environment        = var.environment
  vpc_cidr           = var.vpc_cidr
  public_subnet_cidr = var.public_subnet_cidr
  private_subnet_cidr = var.private_subnet_cidr
  tags               = local.pop_tags
}

# ===========================================
# Security Module
# ===========================================

module "security" {
  source = "../security"
  
  cloud_provider = var.provider
  vpc_id         = module.network.vpc_id
  pop_name       = var.pop_name
  
  allowed_ports = [
    { port = 22, protocol = "tcp", cidr = var.ssh_allowed_cidrs, description = "SSH" },
    { port = 443, protocol = "tcp", cidr = "0.0.0.0/0", description = "HTTPS" },
    { port = 80, protocol = "tcp", cidr = "0.0.0.0/0", description = "HTTP" },
    { port = 51820, protocol = "udp", cidr = "0.0.0.0/0", description = "WireGuard" },
    { port = 4433, protocol = "tcp", cidr = "0.0.0.0/0", description = "FlexiWAN Device" },
    { port = 8080, protocol = "tcp", cidr = "10.0.0.0/8", description = "Health API" },
    { port = 9100, protocol = "tcp", cidr = var.monitoring_cidr, description = "Node Exporter" },
    { port = 9090, protocol = "tcp", cidr = var.monitoring_cidr, description = "Prometheus" },
  ]
  
  tags = local.pop_tags
}

# ===========================================
# Compute Module
# ===========================================

module "compute" {
  source = "../compute"
  
  cloud_provider    = var.provider
  region            = var.region
  pop_name          = var.pop_name
  environment       = var.environment
  vpc_id            = module.network.vpc_id
  subnet_id         = module.network.public_subnet_id
  security_group_id = module.security.security_group_id
  instance_type     = local.actual_instance_type
  instance_count    = var.instance_count
  ssh_public_key    = var.ssh_public_key
  
  user_data = templatefile("${path.module}/templates/user_data.sh.tpl", {
    pop_name        = var.pop_name
    flexiwan_url    = var.flexiwan_url
    flexiwan_token  = var.flexiwan_token
    environment     = var.environment
    vpp_workers     = var.vpp_worker_cores
    enable_suricata = var.enable_suricata
    enable_envoy    = var.enable_envoy
  })
  
  tags = local.pop_tags
}

# ===========================================
# DNS Module
# ===========================================

module "dns" {
  source = "../dns"
  count  = var.enable_dns ? 1 : 0
  
  domain         = var.domain
  pop_name       = var.pop_name
  instance_ips   = module.compute.public_ips
  enable_geo_dns = var.enable_geo_dns
  
  health_check = {
    path     = "/health"
    port     = 443
    protocol = "HTTPS"
  }
}

# ===========================================
# Monitoring Module
# ===========================================

module "monitoring" {
  source = "../monitoring"
  count  = var.enable_monitoring ? 1 : 0
  
  pop_name       = var.pop_name
  instance_ips   = module.compute.private_ips
  grafana_url    = var.grafana_url
  prometheus_url = var.prometheus_url
}

# ===========================================
# Ansible Inventory Generation
# ===========================================

resource "local_file" "ansible_inventory" {
  count = var.generate_inventory ? 1 : 0
  
  filename = "${path.module}/../../../ansible/inventory/${var.pop_name}.yml"
  
  content = yamlencode({
    all = {
      children = {
        pop_nodes = {
          hosts = { for idx, ip in module.compute.public_ips :
            "${var.pop_name}-${idx + 1}" => {
              ansible_host = ip
              private_ip   = module.compute.private_ips[idx]
            }
          }
          vars = {
            ansible_user                = "ubuntu"
            ansible_ssh_private_key_file = var.ssh_private_key_path
            pop_name                    = var.pop_name
            flexiwan_url                = var.flexiwan_url
            flexiwan_token              = var.flexiwan_token
            cloud_provider              = var.provider
            region                      = var.region
            vpp_worker_cores            = var.vpp_worker_cores
          }
        }
      }
    }
  })
}
