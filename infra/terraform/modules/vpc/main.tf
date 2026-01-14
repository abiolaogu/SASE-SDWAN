# OpenSASE VPC Module
# Multi-cloud VPC/Network configuration

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

variable "vpc_cidr" {
  type = string
}

variable "public_subnet_cidr" {
  type = string
}

variable "private_subnet_cidr" {
  type = string
}

variable "tags" {
  type = map(string)
}

# ===========================================
# AWS VPC
# ===========================================

resource "aws_vpc" "main" {
  count = var.cloud_provider == "aws" ? 1 : 0
  
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = merge(var.tags, {
    Name = "opensase-${var.pop_name}-vpc"
  })
}

resource "aws_internet_gateway" "main" {
  count = var.cloud_provider == "aws" ? 1 : 0
  
  vpc_id = aws_vpc.main[0].id
  
  tags = merge(var.tags, {
    Name = "opensase-${var.pop_name}-igw"
  })
}

resource "aws_subnet" "public" {
  count = var.cloud_provider == "aws" ? 1 : 0
  
  vpc_id                  = aws_vpc.main[0].id
  cidr_block              = var.public_subnet_cidr
  map_public_ip_on_launch = true
  availability_zone       = "${var.region}a"
  
  tags = merge(var.tags, {
    Name = "opensase-${var.pop_name}-public"
    Type = "public"
  })
}

resource "aws_subnet" "private" {
  count = var.cloud_provider == "aws" ? 1 : 0
  
  vpc_id            = aws_vpc.main[0].id
  cidr_block        = var.private_subnet_cidr
  availability_zone = "${var.region}b"
  
  tags = merge(var.tags, {
    Name = "opensase-${var.pop_name}-private"
    Type = "private"
  })
}

resource "aws_route_table" "public" {
  count = var.cloud_provider == "aws" ? 1 : 0
  
  vpc_id = aws_vpc.main[0].id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main[0].id
  }
  
  tags = merge(var.tags, {
    Name = "opensase-${var.pop_name}-public-rt"
  })
}

resource "aws_route_table_association" "public" {
  count = var.cloud_provider == "aws" ? 1 : 0
  
  subnet_id      = aws_subnet.public[0].id
  route_table_id = aws_route_table.public[0].id
}

# ===========================================
# GCP VPC
# ===========================================

resource "google_compute_network" "main" {
  count = var.cloud_provider == "gcp" ? 1 : 0
  
  name                    = "opensase-${var.pop_name}-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "public" {
  count = var.cloud_provider == "gcp" ? 1 : 0
  
  name          = "opensase-${var.pop_name}-public"
  ip_cidr_range = var.public_subnet_cidr
  region        = var.region
  network       = google_compute_network.main[0].id
}

resource "google_compute_subnetwork" "private" {
  count = var.cloud_provider == "gcp" ? 1 : 0
  
  name          = "opensase-${var.pop_name}-private"
  ip_cidr_range = var.private_subnet_cidr
  region        = var.region
  network       = google_compute_network.main[0].id
  
  private_ip_google_access = true
}

# ===========================================
# Azure VNet
# ===========================================

resource "azurerm_resource_group" "main" {
  count = var.cloud_provider == "azure" ? 1 : 0
  
  name     = "opensase-${var.pop_name}-rg"
  location = var.region
  
  tags = var.tags
}

resource "azurerm_virtual_network" "main" {
  count = var.cloud_provider == "azure" ? 1 : 0
  
  name                = "opensase-${var.pop_name}-vnet"
  resource_group_name = azurerm_resource_group.main[0].name
  location            = azurerm_resource_group.main[0].location
  address_space       = [var.vpc_cidr]
  
  tags = var.tags
}

resource "azurerm_subnet" "public" {
  count = var.cloud_provider == "azure" ? 1 : 0
  
  name                 = "opensase-${var.pop_name}-public"
  resource_group_name  = azurerm_resource_group.main[0].name
  virtual_network_name = azurerm_virtual_network.main[0].name
  address_prefixes     = [var.public_subnet_cidr]
}

resource "azurerm_subnet" "private" {
  count = var.cloud_provider == "azure" ? 1 : 0
  
  name                 = "opensase-${var.pop_name}-private"
  resource_group_name  = azurerm_resource_group.main[0].name
  virtual_network_name = azurerm_virtual_network.main[0].name
  address_prefixes     = [var.private_subnet_cidr]
}

# ===========================================
# Hetzner Network
# ===========================================

resource "hcloud_network" "main" {
  count = var.cloud_provider == "hetzner" ? 1 : 0
  
  name     = "opensase-${var.pop_name}-network"
  ip_range = var.vpc_cidr
  
  labels = var.tags
}

resource "hcloud_network_subnet" "public" {
  count = var.cloud_provider == "hetzner" ? 1 : 0
  
  network_id   = hcloud_network.main[0].id
  type         = "cloud"
  network_zone = "eu-central"
  ip_range     = var.public_subnet_cidr
}

# ===========================================
# Outputs
# ===========================================

output "vpc_id" {
  value = coalesce(
    try(aws_vpc.main[0].id, null),
    try(google_compute_network.main[0].id, null),
    try(azurerm_virtual_network.main[0].id, null),
    try(hcloud_network.main[0].id, null),
    ""
  )
}

output "public_subnet_id" {
  value = coalesce(
    try(aws_subnet.public[0].id, null),
    try(google_compute_subnetwork.public[0].id, null),
    try(azurerm_subnet.public[0].id, null),
    try(hcloud_network_subnet.public[0].id, null),
    ""
  )
}

output "private_subnet_id" {
  value = coalesce(
    try(aws_subnet.private[0].id, null),
    try(google_compute_subnetwork.private[0].id, null),
    try(azurerm_subnet.private[0].id, null),
    ""
  )
}

output "resource_group" {
  value = try(azurerm_resource_group.main[0].name, null)
}
