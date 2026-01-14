# OBMO PowerDNS Module (Self-Hosted DNS)

variable "pop_name" {
  type = string
}

variable "domain" {
  type    = string
  default = "opensase.io"
}

variable "pdns_api_url" {
  description = "PowerDNS API URL"
  type        = string
  default     = "http://ns1.opensase.io:8081"
}

variable "pdns_api_key" {
  description = "PowerDNS API key"
  type        = string
  sensitive   = true
}

variable "server_ips" {
  type = list(string)
}

variable "anycast_ips" {
  type    = list(string)
  default = []
}

variable "ttl" {
  type    = number
  default = 60
}

# ===========================================
# PowerDNS Records via API
# ===========================================

resource "null_resource" "pdns_records" {
  triggers = {
    pop_name   = var.pop_name
    server_ips = join(",", var.server_ips)
  }
  
  provisioner "local-exec" {
    command = <<-EOF
      # Create/Update A records for PoP
      curl -X PATCH "${var.pdns_api_url}/api/v1/servers/localhost/zones/${var.domain}." \
        -H "X-API-Key: ${var.pdns_api_key}" \
        -H "Content-Type: application/json" \
        -d '{
          "rrsets": [
            {
              "name": "${var.pop_name}.${var.domain}.",
              "type": "A",
              "ttl": ${var.ttl},
              "changetype": "REPLACE",
              "records": [
%{ for i, ip in var.server_ips ~}
                {"content": "${ip}", "disabled": false}${i < length(var.server_ips) - 1 ? "," : ""}
%{ endfor ~}
              ]
            },
            {
              "name": "api.${var.pop_name}.${var.domain}.",
              "type": "A",
              "ttl": ${var.ttl},
              "changetype": "REPLACE",
              "records": [
                {"content": "${length(var.anycast_ips) > 0 ? var.anycast_ips[0] : var.server_ips[0]}", "disabled": false}
              ]
            }
%{ for i, ip in var.server_ips ~}
            ,{
              "name": "${var.pop_name}-${format("%02d", i + 1)}.${var.domain}.",
              "type": "A",
              "ttl": ${var.ttl},
              "changetype": "REPLACE",
              "records": [
                {"content": "${ip}", "disabled": false}
              ]
            }
%{ endfor ~}
          ]
        }'
    EOF
  }
}

# ===========================================
# GeoDNS Configuration
# ===========================================

resource "local_file" "geodns_config" {
  filename = "${path.module}/generated/${var.pop_name}-geodns.lua"
  
  content = <<-EOF
-- OBMO GeoDNS Configuration for ${var.pop_name}
-- For use with PowerDNS GeoIP backend

local pop_servers = {
%{ for i, ip in var.server_ips ~}
    "${ip}",
%{ endfor ~}
}

local anycast_servers = {
%{ for i, ip in var.anycast_ips ~}
    "${ip}",
%{ endfor ~}
}

function pick_server(ip)
    -- Simple round-robin, can be extended for geo-based selection
    local idx = math.random(#pop_servers)
    return pop_servers[idx]
end

return {
    name = "${var.pop_name}",
    servers = pop_servers,
    anycast = anycast_servers
}
EOF
}

# ===========================================
# Outputs
# ===========================================

output "dns_names" {
  value = {
    pop  = "${var.pop_name}.${var.domain}"
    api  = "api.${var.pop_name}.${var.domain}"
    mgmt = [for i in range(length(var.server_ips)) : "${var.pop_name}-${format("%02d", i + 1)}.${var.domain}"]
  }
}

output "geodns_config_path" {
  value = local_file.geodns_config.filename
}
