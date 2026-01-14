# OpenSASE Compute Module
# Multi-cloud compute instances for PoP

variable "cloud_provider" {
  type = string
}

variable "region" {
  type = string
}

variable "pop_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "subnet_id" {
  type = string
}

variable "security_group_id" {
  type = string
}

variable "instance_type" {
  type = string
}

variable "instance_count" {
  type    = number
  default = 2
}

variable "ssh_public_key" {
  type = string
}

variable "user_data" {
  type = string
}

variable "tags" {
  type = map(string)
}

# AMI lookup
data "aws_ami" "ubuntu" {
  count = var.cloud_provider == "aws" ? 1 : 0
  
  most_recent = true
  owners      = ["099720109477"] # Canonical
  
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

# ===========================================
# AWS EC2 Instances
# ===========================================

resource "aws_key_pair" "main" {
  count = var.cloud_provider == "aws" ? 1 : 0
  
  key_name   = "opensase-${var.pop_name}"
  public_key = var.ssh_public_key
  
  tags = merge(var.tags, {
    Name = "opensase-${var.pop_name}-key"
  })
}

resource "aws_instance" "pop" {
  count = var.cloud_provider == "aws" ? var.instance_count : 0
  
  ami                    = data.aws_ami.ubuntu[0].id
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [var.security_group_id]
  key_name               = aws_key_pair.main[0].key_name
  
  user_data = var.user_data
  
  # Enable enhanced networking
  ebs_optimized = true
  
  # Root volume
  root_block_device {
    volume_type = "gp3"
    volume_size = 100
    iops        = 3000
    throughput  = 125
    encrypted   = true
  }
  
  # Enable DPDK/SR-IOV
  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }
  
  tags = merge(var.tags, {
    Name = "opensase-${var.pop_name}-${count.index + 1}"
    Role = "pop-node"
  })
  
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_eip" "pop" {
  count = var.cloud_provider == "aws" ? var.instance_count : 0
  
  instance = aws_instance.pop[count.index].id
  domain   = "vpc"
  
  tags = merge(var.tags, {
    Name = "opensase-${var.pop_name}-eip-${count.index + 1}"
  })
}

# ===========================================
# GCP Compute Instances
# ===========================================

resource "google_compute_instance" "pop" {
  count = var.cloud_provider == "gcp" ? var.instance_count : 0
  
  name         = "opensase-${var.pop_name}-${count.index + 1}"
  machine_type = var.instance_type
  zone         = "${var.region}-a"
  
  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
      size  = 100
      type  = "pd-ssd"
    }
  }
  
  network_interface {
    subnetwork = var.subnet_id
    
    access_config {
      // Ephemeral public IP
    }
  }
  
  metadata = {
    ssh-keys  = "ubuntu:${var.ssh_public_key}"
    user-data = var.user_data
  }
  
  metadata_startup_script = var.user_data
  
  service_account {
    scopes = ["cloud-platform"]
  }
  
  labels = var.tags
  
  scheduling {
    on_host_maintenance = "MIGRATE"
    automatic_restart   = true
  }
}

# ===========================================
# Azure VMs
# ===========================================

resource "azurerm_public_ip" "pop" {
  count = var.cloud_provider == "azure" ? var.instance_count : 0
  
  name                = "opensase-${var.pop_name}-pip-${count.index + 1}"
  resource_group_name = var.tags["ResourceGroup"]
  location            = var.region
  allocation_method   = "Static"
  sku                 = "Standard"
  
  tags = var.tags
}

resource "azurerm_network_interface" "pop" {
  count = var.cloud_provider == "azure" ? var.instance_count : 0
  
  name                = "opensase-${var.pop_name}-nic-${count.index + 1}"
  resource_group_name = var.tags["ResourceGroup"]
  location            = var.region
  
  ip_configuration {
    name                          = "internal"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.pop[count.index].id
  }
  
  tags = var.tags
}

resource "azurerm_linux_virtual_machine" "pop" {
  count = var.cloud_provider == "azure" ? var.instance_count : 0
  
  name                = "opensase-${var.pop_name}-${count.index + 1}"
  resource_group_name = var.tags["ResourceGroup"]
  location            = var.region
  size                = var.instance_type
  admin_username      = "ubuntu"
  
  network_interface_ids = [azurerm_network_interface.pop[count.index].id]
  
  admin_ssh_key {
    username   = "ubuntu"
    public_key = var.ssh_public_key
  }
  
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
    disk_size_gb         = 100
  }
  
  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }
  
  custom_data = base64encode(var.user_data)
  
  tags = var.tags
}

# ===========================================
# Hetzner Servers
# ===========================================

resource "hcloud_ssh_key" "main" {
  count = var.cloud_provider == "hetzner" ? 1 : 0
  
  name       = "opensase-${var.pop_name}"
  public_key = var.ssh_public_key
  
  labels = var.tags
}

resource "hcloud_server" "pop" {
  count = var.cloud_provider == "hetzner" ? var.instance_count : 0
  
  name        = "opensase-${var.pop_name}-${count.index + 1}"
  server_type = var.instance_type
  image       = "ubuntu-22.04"
  location    = var.region
  
  ssh_keys = [hcloud_ssh_key.main[0].id]
  
  user_data = var.user_data
  
  labels = var.tags
  
  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }
  
  network {
    network_id = var.vpc_id
  }
}

# ===========================================
# Outputs
# ===========================================

output "public_ips" {
  value = coalesce(
    try([for eip in aws_eip.pop : eip.public_ip], null),
    try([for vm in google_compute_instance.pop : vm.network_interface[0].access_config[0].nat_ip], null),
    try([for pip in azurerm_public_ip.pop : pip.ip_address], null),
    try([for srv in hcloud_server.pop : srv.ipv4_address], null),
    []
  )
}

output "private_ips" {
  value = coalesce(
    try([for vm in aws_instance.pop : vm.private_ip], null),
    try([for vm in google_compute_instance.pop : vm.network_interface[0].network_ip], null),
    try([for nic in azurerm_network_interface.pop : nic.private_ip_address], null),
    try([for srv in hcloud_server.pop : srv.network[0].ip], null),
    []
  )
}

output "instance_ids" {
  value = coalesce(
    try([for vm in aws_instance.pop : vm.id], null),
    try([for vm in google_compute_instance.pop : vm.instance_id], null),
    try([for vm in azurerm_linux_virtual_machine.pop : vm.id], null),
    try([for srv in hcloud_server.pop : srv.id], null),
    []
  )
}
