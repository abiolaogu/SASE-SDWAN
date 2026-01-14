# OpenSASE PoP Module - Outputs

output "pop_info" {
  description = "PoP deployment information"
  value = {
    name        = var.pop_name
    provider    = var.provider
    region      = var.region
    environment = var.environment
    size        = var.instance_size
  }
}

output "network" {
  description = "Network information"
  value = {
    vpc_id      = module.network.vpc_id
    subnet_id   = module.network.public_subnet_id
    vpc_cidr    = var.vpc_cidr
  }
}

output "instances" {
  description = "Instance information"
  value = {
    count       = var.instance_count
    type        = local.actual_instance_type
    public_ips  = module.compute.public_ips
    private_ips = module.compute.private_ips
    ids         = module.compute.instance_ids
  }
}

output "public_ips" {
  description = "Public IP addresses of all instances"
  value       = module.compute.public_ips
}

output "private_ips" {
  description = "Private IP addresses of all instances"
  value       = module.compute.private_ips
}

output "dns" {
  description = "DNS endpoints"
  value = var.enable_dns ? {
    pop_endpoint = "${var.pop_name}.${var.domain}"
    api_endpoint = "api.${var.pop_name}.${var.domain}"
    health_url   = "https://${var.pop_name}.${var.domain}/health"
  } : null
}

output "ssh_commands" {
  description = "SSH commands to connect to instances"
  value = [
    for ip in module.compute.public_ips :
    "ssh -i ${var.ssh_private_key_path} ubuntu@${ip}"
  ]
}

output "ansible_inventory_path" {
  description = "Path to generated Ansible inventory"
  value       = var.generate_inventory ? local_file.ansible_inventory[0].filename : null
}

output "security_group_id" {
  description = "Security group ID"
  value       = module.security.security_group_id
}
