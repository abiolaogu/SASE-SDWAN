# OpenSASE Security Module
# Multi-cloud security groups/firewall rules

variable "cloud_provider" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "pop_name" {
  type = string
}

variable "allowed_ports" {
  type = list(object({
    port        = number
    protocol    = string
    cidr        = string
    description = string
  }))
}

variable "tags" {
  type = map(string)
}

# ===========================================
# AWS Security Group
# ===========================================

resource "aws_security_group" "pop" {
  count = var.cloud_provider == "aws" ? 1 : 0
  
  name        = "opensase-${var.pop_name}-sg"
  description = "OpenSASE PoP security group"
  vpc_id      = var.vpc_id
  
  # Dynamic ingress rules
  dynamic "ingress" {
    for_each = var.allowed_ports
    content {
      from_port   = ingress.value.port
      to_port     = ingress.value.port
      protocol    = ingress.value.protocol
      cidr_blocks = [ingress.value.cidr]
      description = ingress.value.description
    }
  }
  
  # Allow all egress
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound"
  }
  
  # Allow internal VPC traffic
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
    description = "Allow internal cluster traffic"
  }
  
  tags = merge(var.tags, {
    Name = "opensase-${var.pop_name}-sg"
  })
}

# ===========================================
# GCP Firewall Rules
# ===========================================

resource "google_compute_firewall" "allow_ingress" {
  count = var.cloud_provider == "gcp" ? 1 : 0
  
  name    = "opensase-${var.pop_name}-allow-ingress"
  network = var.vpc_id
  
  dynamic "allow" {
    for_each = var.allowed_ports
    content {
      protocol = allow.value.protocol
      ports    = [allow.value.port]
    }
  }
  
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["opensase-pop"]
}

resource "google_compute_firewall" "allow_internal" {
  count = var.cloud_provider == "gcp" ? 1 : 0
  
  name    = "opensase-${var.pop_name}-allow-internal"
  network = var.vpc_id
  
  allow {
    protocol = "all"
  }
  
  source_tags = ["opensase-pop"]
  target_tags = ["opensase-pop"]
}

# ===========================================
# Azure Network Security Group
# ===========================================

resource "azurerm_network_security_group" "pop" {
  count = var.cloud_provider == "azure" ? 1 : 0
  
  name                = "opensase-${var.pop_name}-nsg"
  location            = var.tags["Location"]
  resource_group_name = var.tags["ResourceGroup"]
  
  tags = var.tags
}

resource "azurerm_network_security_rule" "ingress" {
  count = var.cloud_provider == "azure" ? length(var.allowed_ports) : 0
  
  name                        = "allow-${var.allowed_ports[count.index].description}"
  priority                    = 100 + count.index
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = title(var.allowed_ports[count.index].protocol)
  source_port_range           = "*"
  destination_port_range      = var.allowed_ports[count.index].port
  source_address_prefix       = var.allowed_ports[count.index].cidr
  destination_address_prefix  = "*"
  resource_group_name         = var.tags["ResourceGroup"]
  network_security_group_name = azurerm_network_security_group.pop[0].name
}

# ===========================================
# Hetzner Firewall
# ===========================================

resource "hcloud_firewall" "pop" {
  count = var.cloud_provider == "hetzner" ? 1 : 0
  
  name = "opensase-${var.pop_name}-fw"
  
  dynamic "rule" {
    for_each = var.allowed_ports
    content {
      direction  = "in"
      protocol   = rule.value.protocol
      port       = tostring(rule.value.port)
      source_ips = [rule.value.cidr]
    }
  }
  
  # Allow all outbound
  rule {
    direction       = "out"
    protocol        = "tcp"
    port            = "1-65535"
    destination_ips = ["0.0.0.0/0"]
  }
  
  rule {
    direction       = "out"
    protocol        = "udp"
    port            = "1-65535"
    destination_ips = ["0.0.0.0/0"]
  }
  
  labels = var.tags
}

# ===========================================
# Outputs
# ===========================================

output "security_group_id" {
  value = coalesce(
    try(aws_security_group.pop[0].id, null),
    try(google_compute_firewall.allow_ingress[0].id, null),
    try(azurerm_network_security_group.pop[0].id, null),
    try(hcloud_firewall.pop[0].id, null),
    ""
  )
}
