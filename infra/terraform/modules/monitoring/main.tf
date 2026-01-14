# Monitoring Module
# Prometheus, Grafana, and alerting

variable "pop_name" {
  type = string
}

variable "instance_ips" {
  type = list(string)
}

variable "grafana_url" {
  type = string
}

variable "prometheus_url" {
  type = string
}

# ===========================================
# Prometheus Remote Write Config
# ===========================================

resource "local_file" "prometheus_config" {
  filename = "${path.module}/../../../ansible/files/${var.pop_name}-prometheus.yml"
  
  content = yamlencode({
    global = {
      scrape_interval     = "15s"
      evaluation_interval = "15s"
    }
    
    remote_write = [
      {
        url = "${var.prometheus_url}/api/v1/write"
        write_relabel_configs = [
          {
            target_label = "pop"
            replacement  = var.pop_name
          }
        ]
      }
    ]
    
    scrape_configs = [
      {
        job_name = "node"
        static_configs = [
          {
            targets = [for ip in var.instance_ips : "${ip}:9100"]
            labels = {
              pop = var.pop_name
            }
          }
        ]
      },
      {
        job_name = "vpp"
        static_configs = [
          {
            targets = [for ip in var.instance_ips : "${ip}:9482"]
            labels = {
              pop = var.pop_name
            }
          }
        ]
      },
      {
        job_name = "suricata"
        static_configs = [
          {
            targets = [for ip in var.instance_ips : "${ip}:9917"]
            labels = {
              pop = var.pop_name
            }
          }
        ]
      }
    ]
  })
}

# ===========================================
# Grafana Datasource Registration
# ===========================================

resource "null_resource" "register_grafana" {
  triggers = {
    pop_name = var.pop_name
    ips      = join(",", var.instance_ips)
  }
  
  provisioner "local-exec" {
    command = <<-EOF
      curl -X POST "${var.grafana_url}/api/datasources" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $GRAFANA_API_KEY" \
        -d '{
          "name": "${var.pop_name}-prometheus",
          "type": "prometheus",
          "url": "${var.prometheus_url}",
          "access": "proxy",
          "jsonData": {
            "httpMethod": "POST",
            "customQueryParameters": "pop=${var.pop_name}"
          }
        }' || true
    EOF
  }
}

# ===========================================
# Alert Rules
# ===========================================

resource "local_file" "alert_rules" {
  filename = "${path.module}/../../../ansible/files/${var.pop_name}-alerts.yml"
  
  content = yamlencode({
    groups = [
      {
        name = "${var.pop_name}-alerts"
        rules = [
          {
            alert = "InstanceDown"
            expr  = "up{pop=\"${var.pop_name}\"} == 0"
            for   = "5m"
            labels = {
              severity = "critical"
              pop      = var.pop_name
            }
            annotations = {
              summary = "Instance {{ $labels.instance }} down"
              description = "{{ $labels.instance }} of ${var.pop_name} has been down for more than 5 minutes."
            }
          },
          {
            alert = "HighCPU"
            expr  = "100 - (avg by(instance) (rate(node_cpu_seconds_total{mode=\"idle\",pop=\"${var.pop_name}\"}[5m])) * 100) > 80"
            for   = "10m"
            labels = {
              severity = "warning"
              pop      = var.pop_name
            }
            annotations = {
              summary = "High CPU usage on {{ $labels.instance }}"
            }
          },
          {
            alert = "VPPDown"
            expr  = "vpp_up{pop=\"${var.pop_name}\"} == 0"
            for   = "1m"
            labels = {
              severity = "critical"
              pop      = var.pop_name
            }
            annotations = {
              summary = "VPP is down on {{ $labels.instance }}"
            }
          },
          {
            alert = "HighPacketLoss"
            expr  = "rate(vpp_if_drops{pop=\"${var.pop_name}\"}[5m]) > 100"
            for   = "5m"
            labels = {
              severity = "warning"
              pop      = var.pop_name
            }
            annotations = {
              summary = "High packet loss on {{ $labels.interface }}"
            }
          }
        ]
      }
    ]
  })
}

# ===========================================
# Outputs
# ===========================================

output "prometheus_config_path" {
  value = local_file.prometheus_config.filename
}

output "alert_rules_path" {
  value = local_file.alert_rules.filename
}
