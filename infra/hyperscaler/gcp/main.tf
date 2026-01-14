# ============================================================
# ⚠️  MVP/STARTUP DEPLOYMENT - NOT FOR PRODUCTION SCALE  ⚠️
# ============================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

variable "project_id" {
  type = string
}

variable "environment" {
  type    = string
  default = "demo"
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "node_count" {
  type    = number
  default = 3
}

variable "machine_type" {
  type    = string
  default = "n2-standard-8"
}

locals {
  name_prefix = "opensase-mvp-${var.environment}"
  common_labels = {
    project     = "opensase"
    environment = var.environment
    deployment  = "hyperscaler-mvp"
    warning     = "mvp-only"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# VPC Network
resource "google_compute_network" "main" {
  name                    = "${local.name_prefix}-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "nodes" {
  name          = "${local.name_prefix}-nodes"
  ip_cidr_range = "10.0.0.0/24"
  region        = var.region
  network       = google_compute_network.main.id
  
  private_ip_google_access = true
}

# Firewall Rules
resource "google_compute_firewall" "wireguard" {
  name    = "${local.name_prefix}-wireguard"
  network = google_compute_network.main.name
  
  allow {
    protocol = "udp"
    ports    = ["51820-51830"]
  }
  
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["sase-node"]
}

resource "google_compute_firewall" "https" {
  name    = "${local.name_prefix}-https"
  network = google_compute_network.main.name
  
  allow {
    protocol = "tcp"
    ports    = ["443", "80"]
  }
  
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["sase-node"]
}

resource "google_compute_firewall" "dns" {
  name    = "${local.name_prefix}-dns"
  network = google_compute_network.main.name
  
  allow {
    protocol = "udp"
    ports    = ["53"]
  }
  
  allow {
    protocol = "tcp"
    ports    = ["53"]
  }
  
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["sase-node"]
}

resource "google_compute_firewall" "internal" {
  name    = "${local.name_prefix}-internal"
  network = google_compute_network.main.name
  
  allow {
    protocol = "tcp"
  }
  
  allow {
    protocol = "udp"
  }
  
  allow {
    protocol = "icmp"
  }
  
  source_tags = ["sase-node"]
  target_tags = ["sase-node"]
}

resource "google_compute_firewall" "health_check" {
  name    = "${local.name_prefix}-health"
  network = google_compute_network.main.name
  
  allow {
    protocol = "tcp"
    ports    = ["51821"]
  }
  
  source_ranges = ["130.211.0.0/22", "35.191.0.0/16"]
  target_tags   = ["sase-node"]
}

# Instance Template
resource "google_compute_instance_template" "sase" {
  name_prefix  = "${local.name_prefix}-"
  machine_type = var.machine_type
  
  disk {
    source_image = "ubuntu-os-cloud/ubuntu-2204-lts"
    auto_delete  = true
    boot         = true
    disk_size_gb = 100
    disk_type    = "pd-ssd"
  }
  
  network_interface {
    network    = google_compute_network.main.id
    subnetwork = google_compute_subnetwork.nodes.id
    
    access_config {
      // Ephemeral public IP
    }
  }
  
  metadata_startup_script = file("${path.module}/../aws/user_data.sh")
  
  tags = ["sase-node"]
  
  labels = local.common_labels
  
  lifecycle {
    create_before_destroy = true
  }
}

# Managed Instance Group
resource "google_compute_instance_group_manager" "sase" {
  name               = "${local.name_prefix}-igm"
  base_instance_name = "${local.name_prefix}-node"
  zone               = "${var.region}-a"
  target_size        = var.node_count
  
  version {
    instance_template = google_compute_instance_template.sase.id
  }
  
  named_port {
    name = "https"
    port = 443
  }
  
  named_port {
    name = "wireguard"
    port = 51820
  }
  
  auto_healing_policies {
    health_check      = google_compute_health_check.tcp.id
    initial_delay_sec = 300
  }
}

# Health Check
resource "google_compute_health_check" "tcp" {
  name = "${local.name_prefix}-health"
  
  tcp_health_check {
    port = 51821
  }
  
  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3
}

# External Load Balancer for WireGuard (UDP)
resource "google_compute_address" "lb" {
  name   = "${local.name_prefix}-lb-ip"
  region = var.region
}

resource "google_compute_forwarding_rule" "wireguard" {
  name                  = "${local.name_prefix}-wg-fwd"
  region                = var.region
  ip_address            = google_compute_address.lb.address
  ip_protocol           = "UDP"
  port_range            = "51820"
  load_balancing_scheme = "EXTERNAL"
  target                = google_compute_target_pool.sase.id
}

resource "google_compute_target_pool" "sase" {
  name   = "${local.name_prefix}-pool"
  region = var.region
  
  health_checks = [google_compute_http_health_check.tcp.name]
}

resource "google_compute_http_health_check" "tcp" {
  name               = "${local.name_prefix}-http-health"
  request_path       = "/health"
  check_interval_sec = 10
  timeout_sec        = 5
  port               = 8080
}

# Cloud SQL PostgreSQL
resource "google_sql_database_instance" "main" {
  name             = "${local.name_prefix}-db"
  database_version = "POSTGRES_15"
  region           = var.region
  
  settings {
    tier = var.environment == "demo" ? "db-f1-micro" : "db-custom-4-16384"
    
    ip_configuration {
      ipv4_enabled    = true
      private_network = google_compute_network.main.id
    }
    
    backup_configuration {
      enabled = var.environment != "demo"
    }
  }
  
  deletion_protection = var.environment != "demo"
}

resource "google_sql_database" "opensase" {
  name     = "opensase"
  instance = google_sql_database_instance.main.name
}

resource "google_sql_user" "opensase" {
  name     = "opensase"
  instance = google_sql_database_instance.main.name
  password = random_password.db_password.result
}

resource "random_password" "db_password" {
  length  = 32
  special = false
}

# Memorystore Redis
resource "google_redis_instance" "main" {
  name           = "${local.name_prefix}-redis"
  tier           = var.environment == "demo" ? "BASIC" : "STANDARD_HA"
  memory_size_gb = var.environment == "demo" ? 1 : 5
  region         = var.region
  
  authorized_network = google_compute_network.main.id
  
  labels = local.common_labels
}

# Outputs
output "lb_ip" {
  value = google_compute_address.lb.address
}

output "db_connection" {
  value     = google_sql_database_instance.main.connection_name
  sensitive = true
}

output "redis_host" {
  value = google_redis_instance.main.host
}
