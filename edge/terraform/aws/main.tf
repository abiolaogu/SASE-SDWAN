# OpenSASE Edge - AWS Terraform Module

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "site_name" {
  type = string
}

variable "tenant_id" {
  type = string
}

variable "controller_url" {
  type    = string
  default = "https://controller.opensase.io"
}

variable "activation_code" {
  type      = string
  sensitive = true
}

variable "vpc_id" {
  type = string
}

variable "subnet_id" {
  type = string
}

variable "instance_type" {
  type    = string
  default = "t3.medium"
}

variable "key_name" {
  type = string
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

resource "aws_security_group" "edge" {
  name        = "opensase-edge-${var.site_name}"
  description = "OpenSASE Edge security group"
  vpc_id      = var.vpc_id

  # WireGuard
  ingress {
    from_port   = 51820
    to_port     = 51820
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Management API
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "opensase-edge-${var.site_name}"
  }
}

resource "aws_instance" "edge" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.instance_type
  key_name      = var.key_name
  subnet_id     = var.subnet_id

  vpc_security_group_ids = [aws_security_group.edge.id]

  user_data = templatefile("${path.module}/userdata.sh.tpl", {
    site_name       = var.site_name
    tenant_id       = var.tenant_id
    controller_url  = var.controller_url
    activation_code = var.activation_code
  })

  root_block_device {
    volume_size = 32
    volume_type = "gp3"
  }

  tags = {
    Name     = "opensase-edge-${var.site_name}"
    TenantId = var.tenant_id
  }
}

resource "aws_eip" "edge" {
  instance = aws_instance.edge.id
  domain   = "vpc"

  tags = {
    Name = "opensase-edge-${var.site_name}"
  }
}

output "public_ip" {
  value = aws_eip.edge.public_ip
}

output "instance_id" {
  value = aws_instance.edge.id
}
