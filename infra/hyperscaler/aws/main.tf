# ============================================================
# ⚠️  MVP/STARTUP DEPLOYMENT - NOT FOR PRODUCTION SCALE  ⚠️
# ============================================================
# This deployment is for demonstration, testing, and early
# startup operations. Migrate to bare-metal when:
# - Monthly spend exceeds $5,000/region
# - Traffic exceeds 5 Gbps sustained
# - Customer SLAs require <10ms latency
# ============================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  
  backend "s3" {
    bucket         = "opensase-terraform-state"
    key            = "hyperscaler/aws/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "opensase-terraform-locks"
    encrypt        = true
  }
}

variable "environment" {
  type        = string
  description = "Environment name (demo, staging, mvp-prod)"
  validation {
    condition     = contains(["demo", "staging", "mvp-prod"], var.environment)
    error_message = "Environment must be demo, staging, or mvp-prod. For production, use bare-metal deployment."
  }
}

variable "region" {
  type        = string
  description = "AWS region for deployment"
  default     = "us-east-1"
}

variable "instance_type" {
  type        = string
  default     = "c5.2xlarge" # 8 vCPU, 16GB RAM - good balance for MVP
  description = "EC2 instance type for SASE nodes"
}

variable "node_count" {
  type        = number
  default     = 3
  description = "Number of SASE nodes (minimum 3 for HA)"
}

locals {
  name_prefix = "opensase-mvp-${var.environment}"
  
  common_tags = {
    Project     = "OpenSASE"
    Environment = var.environment
    Deployment  = "hyperscaler-mvp"
    Warning     = "MVP_ONLY_NOT_FOR_PRODUCTION_SCALE"
    ManagedBy   = "terraform"
  }
  
  cost_tags = {
    CostCenter    = "opensase-mvp"
    MigrationFlag = "review-monthly"
  }
}

# VPC Configuration
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
  
  name = "${local.name_prefix}-vpc"
  cidr = "10.0.0.0/16"
  
  azs             = ["${var.region}a", "${var.region}b", "${var.region}c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
  
  enable_nat_gateway     = true
  single_nat_gateway     = var.environment == "demo" # Cost saving for demos
  enable_vpn_gateway     = false
  enable_dns_hostnames   = true
  enable_dns_support     = true
  
  enable_flow_log                      = true
  create_flow_log_cloudwatch_log_group = true
  create_flow_log_cloudwatch_iam_role  = true
  
  tags = merge(local.common_tags, local.cost_tags)
}

# Security Group for SASE Nodes
resource "aws_security_group" "sase_nodes" {
  name_prefix = "${local.name_prefix}-sase-"
  vpc_id      = module.vpc.vpc_id
  
  # WireGuard UDP
  ingress {
    from_port   = 51820
    to_port     = 51830
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "WireGuard tunnels"
  }
  
  # HTTPS for management and proxy
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS proxy and management"
  }
  
  # HTTP for redirect
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP redirect"
  }
  
  # DNS
  ingress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "DNS resolution"
  }
  
  ingress {
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "DNS resolution TCP"
  }
  
  # Inter-node communication
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
    description = "Inter-node communication"
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound"
  }
  
  tags = merge(local.common_tags, { Name = "${local.name_prefix}-sase-sg" })
  
  lifecycle {
    create_before_destroy = true
  }
}

# AMI lookup
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical
  
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# IAM Role for SASE Nodes
resource "aws_iam_role" "sase_node" {
  name = "${local.name_prefix}-sase-node-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
  
  tags = local.common_tags
}

resource "aws_iam_instance_profile" "sase_node" {
  name = "${local.name_prefix}-sase-node-profile"
  role = aws_iam_role.sase_node.name
}

# Launch Template for SASE Nodes
resource "aws_launch_template" "sase_node" {
  name_prefix   = "${local.name_prefix}-sase-"
  image_id      = data.aws_ami.ubuntu.id
  instance_type = var.instance_type
  
  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.sase_nodes.id]
    delete_on_termination       = true
  }
  
  iam_instance_profile {
    name = aws_iam_instance_profile.sase_node.name
  }
  
  block_device_mappings {
    device_name = "/dev/sda1"
    ebs {
      volume_size           = 100
      volume_type           = "gp3"
      iops                  = 3000
      throughput            = 125
      encrypted             = true
      delete_on_termination = true
    }
  }
  
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 required
    http_put_response_hop_limit = 1
  }
  
  user_data = base64encode(file("${path.module}/user_data.sh"))
  
  tag_specifications {
    resource_type = "instance"
    tags          = merge(local.common_tags, local.cost_tags, { Name = "${local.name_prefix}-sase-node" })
  }
  
  tag_specifications {
    resource_type = "volume"
    tags          = merge(local.common_tags, { Name = "${local.name_prefix}-sase-volume" })
  }
  
  tags = local.common_tags
}

# Auto Scaling Group
resource "aws_autoscaling_group" "sase_nodes" {
  name                = "${local.name_prefix}-sase-asg"
  desired_capacity    = var.node_count
  min_size            = var.environment == "demo" ? 1 : 2
  max_size            = var.node_count * 2
  vpc_zone_identifier = module.vpc.private_subnets
  
  launch_template {
    id      = aws_launch_template.sase_node.id
    version = "$Latest"
  }
  
  health_check_type         = "ELB"
  health_check_grace_period = 300
  
  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
    }
  }
  
  target_group_arns = [
    aws_lb_target_group.wireguard.arn,
    aws_lb_target_group.https.arn,
  ]
  
  dynamic "tag" {
    for_each = merge(local.common_tags, local.cost_tags)
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }
  
  lifecycle {
    create_before_destroy = true
  }
}

# Network Load Balancer (for WireGuard UDP)
resource "aws_lb" "wireguard" {
  name               = "${local.name_prefix}-wg-nlb"
  internal           = false
  load_balancer_type = "network"
  subnets            = module.vpc.public_subnets
  
  enable_cross_zone_load_balancing = true
  
  tags = merge(local.common_tags, { Name = "${local.name_prefix}-wireguard-nlb" })
}

resource "aws_lb_target_group" "wireguard" {
  name        = "${local.name_prefix}-wg-tg"
  port        = 51820
  protocol    = "UDP"
  vpc_id      = module.vpc.vpc_id
  target_type = "instance"
  
  health_check {
    enabled             = true
    protocol            = "TCP"
    port                = 51821
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 10
  }
  
  tags = local.common_tags
}

resource "aws_lb_listener" "wireguard" {
  load_balancer_arn = aws_lb.wireguard.arn
  port              = 51820
  protocol          = "UDP"
  
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.wireguard.arn
  }
}

# Application Load Balancer Security Group
resource "aws_security_group" "alb" {
  name_prefix = "${local.name_prefix}-alb-"
  vpc_id      = module.vpc.vpc_id
  
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = local.common_tags
}

# Application Load Balancer (for HTTPS)
resource "aws_lb" "https" {
  name               = "${local.name_prefix}-https-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = module.vpc.public_subnets
  security_groups    = [aws_security_group.alb.id]
  
  enable_http2 = true
  
  tags = merge(local.common_tags, { Name = "${local.name_prefix}-https-alb" })
}

resource "aws_lb_target_group" "https" {
  name        = "${local.name_prefix}-https-tg"
  port        = 443
  protocol    = "HTTPS"
  vpc_id      = module.vpc.vpc_id
  target_type = "instance"
  
  health_check {
    enabled             = true
    path                = "/health"
    protocol            = "HTTPS"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 10
    matcher             = "200"
  }
  
  tags = local.common_tags
}

# Database subnet group
resource "aws_db_subnet_group" "main" {
  name       = "${local.name_prefix}-db-subnet"
  subnet_ids = module.vpc.private_subnets
  
  tags = local.common_tags
}

# Database security group
resource "aws_security_group" "database" {
  name_prefix = "${local.name_prefix}-db-"
  vpc_id      = module.vpc.vpc_id
  
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.sase_nodes.id]
  }
  
  tags = local.common_tags
}

# Random password for database
resource "random_password" "db_password" {
  length  = 32
  special = false
}

# RDS PostgreSQL
resource "aws_db_instance" "postgres" {
  identifier = "${local.name_prefix}-db"
  
  engine               = "postgres"
  engine_version       = "15.4"
  instance_class       = var.environment == "demo" ? "db.t3.medium" : "db.r6g.large"
  allocated_storage    = 100
  max_allocated_storage = 500
  storage_type         = "gp3"
  storage_encrypted    = true
  
  db_name  = "opensase"
  username = "opensase"
  password = random_password.db_password.result
  
  vpc_security_group_ids = [aws_security_group.database.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  
  multi_az = var.environment != "demo"
  
  backup_retention_period = var.environment == "demo" ? 1 : 7
  backup_window           = "03:00-04:00"
  maintenance_window      = "Mon:04:00-Mon:05:00"
  
  auto_minor_version_upgrade = true
  deletion_protection        = var.environment != "demo"
  skip_final_snapshot        = var.environment == "demo"
  
  performance_insights_enabled = var.environment != "demo"
  
  tags = merge(local.common_tags, local.cost_tags, {
    Name = "${local.name_prefix}-postgres"
    Note = "MVP_ONLY-Migrate_to_YugabyteDB_for_production"
  })
}

# Redis subnet group
resource "aws_elasticache_subnet_group" "main" {
  name       = "${local.name_prefix}-redis-subnet"
  subnet_ids = module.vpc.private_subnets
}

# Redis security group
resource "aws_security_group" "redis" {
  name_prefix = "${local.name_prefix}-redis-"
  vpc_id      = module.vpc.vpc_id
  
  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.sase_nodes.id]
  }
  
  tags = local.common_tags
}

# ElastiCache Redis
resource "aws_elasticache_cluster" "redis" {
  cluster_id           = "${local.name_prefix}-redis"
  engine               = "redis"
  engine_version       = "7.0"
  node_type            = var.environment == "demo" ? "cache.t3.small" : "cache.r6g.large"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis7"
  port                 = 6379
  
  subnet_group_name  = aws_elasticache_subnet_group.main.name
  security_group_ids = [aws_security_group.redis.id]
  
  tags = merge(local.common_tags, local.cost_tags)
}

# Outputs
output "wireguard_endpoint" {
  value       = aws_lb.wireguard.dns_name
  description = "WireGuard NLB endpoint"
}

output "https_endpoint" {
  value       = aws_lb.https.dns_name
  description = "HTTPS ALB endpoint"
}

output "database_endpoint" {
  value       = aws_db_instance.postgres.endpoint
  description = "PostgreSQL endpoint"
  sensitive   = true
}

output "redis_endpoint" {
  value       = aws_elasticache_cluster.redis.cache_nodes[0].address
  description = "Redis endpoint"
}

output "vpc_id" {
  value       = module.vpc.vpc_id
  description = "VPC ID"
}

output "migration_warning" {
  value = <<-EOT
    ╔══════════════════════════════════════════════════════════════════╗
    ║  ⚠️  MVP DEPLOYMENT - REVIEW MONTHLY FOR MIGRATION  ⚠️           ║
    ╠══════════════════════════════════════════════════════════════════╣
    ║  This hyperscaler deployment is for MVP/demo purposes only.      ║
    ║                                                                   ║
    ║  MIGRATE TO BARE-METAL WHEN:                                     ║
    ║  • Monthly cost exceeds $5,000                                   ║
    ║  • Traffic exceeds 5 Gbps sustained                              ║
    ║  • Customer SLAs require <10ms latency                           ║
    ║                                                                   ║
    ║  See: /docs/deployment-strategy/MIGRATION_PLAYBOOK.md            ║
    ╚══════════════════════════════════════════════════════════════════╝
  EOT
}
