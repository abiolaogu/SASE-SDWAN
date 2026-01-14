#cloud-config
# OpenSASE Bare Metal Orchestrator - Universal Cloud-Init
# PoP: ${pop_name}, Role: ${role}

hostname: opensase-${pop_name}-${role == "primary" ? "01" : "02"}
fqdn: opensase-${pop_name}-${role == "primary" ? "01" : "02"}.opensase.io
manage_etc_hosts: true

users:
  - name: opensase
    groups: [sudo, docker]
    shell: /bin/bash
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    ssh_authorized_keys:
      - ${ssh_public_key}

packages:
  - apt-transport-https
  - ca-certificates
  - curl
  - gnupg
  - lsb-release
  - jq
  - htop
  - iotop
  - net-tools
  - linux-tools-common
  - linux-tools-generic
  - numactl
  - cpufrequtils
  - pciutils
  - lshw
  - hwloc
  - ethtool
  - iperf3
  - tcpdump

write_files:
  # VPP repository configuration
  - path: /etc/apt/sources.list.d/fdio.list
    content: |
      deb [trusted=yes] https://packagecloud.io/fdio/release/ubuntu jammy main

  # System tuning for ${nic_speed} Gbps
  - path: /etc/sysctl.d/99-opensase.conf
    content: |
      # Memory - Hugepages for VPP
      vm.nr_hugepages = ${nic_speed >= 100 ? 8192 : 4096}
      vm.hugetlb_shm_group = 0
      kernel.shmmax = 68719476736
      kernel.shmall = 16777216
      vm.swappiness = 1
      
      # Network Buffer Sizes for ${nic_speed}G
      net.core.rmem_max = ${nic_speed >= 100 ? 2147483647 : 536870912}
      net.core.wmem_max = ${nic_speed >= 100 ? 2147483647 : 536870912}
      net.core.rmem_default = ${nic_speed >= 100 ? 536870912 : 16777216}
      net.core.wmem_default = ${nic_speed >= 100 ? 536870912 : 16777216}
      net.core.netdev_max_backlog = ${nic_speed >= 100 ? 2000000 : 250000}
      net.core.optmem_max = 25165824
      
      # TCP Optimization
      net.ipv4.tcp_rmem = 4096 ${nic_speed >= 100 ? 4194304 : 87380} ${nic_speed >= 100 ? 2147483647 : 134217728}
      net.ipv4.tcp_wmem = 4096 ${nic_speed >= 100 ? 4194304 : 65536} ${nic_speed >= 100 ? 2147483647 : 134217728}
      net.ipv4.tcp_mtu_probing = 1
      net.ipv4.tcp_congestion_control = bbr
      net.ipv4.tcp_fastopen = 3
      net.ipv4.tcp_max_syn_backlog = 65536
      
      # Forwarding
      net.ipv4.ip_forward = 1
      net.ipv6.conf.all.forwarding = 1
      net.ipv4.conf.all.rp_filter = 0
      net.ipv4.conf.default.rp_filter = 0
      
      # File limits
      fs.file-max = 2097152
      fs.nr_open = 2097152

  # CPU performance governor
  - path: /etc/default/cpufrequtils
    content: |
      GOVERNOR="performance"

  # OpenSASE PoP configuration
  - path: /etc/opensase/config.yaml
    content: |
      pop_name: ${pop_name}
      role: ${role}
      controller_url: ${controller_url}
      activation_key: ${activation_key}
      
      hardware:
        nic_type: ${nic_type}
        nic_speed_gbps: ${nic_speed}
      
      data_plane:
        type: vpp
        dpdk:
          hugepages: ${nic_speed >= 100 ? 8192 : 4096}
          socket_mem: "${nic_speed >= 100 ? "8192,8192" : "4096,4096"}"
          worker_cores: ${nic_speed >= 100 ? 16 : 8}
          rx_queues: ${nic_speed >= 100 ? 16 : 8}
          tx_queues: ${nic_speed >= 100 ? 16 : 8}
        interfaces: []
      
      security:
        ips_enabled: true
        suricata_mode: inline
      
      tunnels:
        type: wireguard
        listen_port: 51820

  # FlexiEdge configuration
  - path: /etc/flexiwan/agent.conf
    content: |
      {
        "deviceName": "opensase-${pop_name}-${role == "primary" ? "01" : "02"}",
        "dataPlane": "vpp",
        "vppSocketPath": "/run/vpp/cli.sock",
        "managementUrl": "${controller_url}",
        "token": "${activation_key}",
        "logLevel": "info",
        "telemetryInterval": 15,
        "features": {
          "sdwan": true,
          "firewall": true,
          "nat": true,
          "qos": true,
          "wireguard": true
        }
      }

  # VPP startup configuration
  - path: /etc/vpp/startup.conf
    content: |
      unix {
        nodaemon
        cli-listen /run/vpp/cli.sock
        log /var/log/vpp/vpp.log
        full-coredump
        gid vpp
      }
      cpu {
        main-core 0
        corelist-workers 2-${nic_speed >= 100 ? 17 : 9}
        scheduler-policy fifo
        scheduler-priority 80
      }
      dpdk {
        dev default {
          num-rx-queues ${nic_speed >= 100 ? 16 : 8}
          num-tx-queues ${nic_speed >= 100 ? 16 : 8}
          num-rx-desc ${nic_speed >= 100 ? 8192 : 4096}
          num-tx-desc ${nic_speed >= 100 ? 8192 : 4096}
        }
%{ if nic_type != "mellanox_cx5" && nic_type != "mellanox_cx6" ~}
        uio-driver vfio-pci
%{ endif ~}
        socket-mem ${nic_speed >= 100 ? "8192,8192" : "4096,4096"}
        num-mbufs ${nic_speed >= 100 ? 524288 : 262144}
        no-multi-seg
      }
      buffers {
        buffers-per-numa ${nic_speed >= 100 ? 524288 : 262144}
        default data-size 2048
%{ if nic_speed >= 100 ~}
        page-size 2M
%{ endif ~}
      }
      statseg {
        socket-name /var/run/vpp/stats.sock
        size 512M
        per-node-counters on
      }
      plugins {
        plugin dpdk_plugin.so { enable }
        plugin wireguard_plugin.so { enable }
        plugin nat_plugin.so { enable }
        plugin acl_plugin.so { enable }
      }

  # Health check script
  - path: /opt/opensase/health.py
    permissions: '0755'
    content: |
      #!/usr/bin/env python3
      import http.server, json, subprocess, socketserver
      
      class H(http.server.BaseHTTPRequestHandler):
          def log_message(self, format, *args): pass
          def do_GET(self):
              if self.path == '/health':
                  h = self.get_health()
                  code = 200 if h['status'] == 'healthy' else 503
                  self.send_response(code)
                  self.send_header('Content-Type', 'application/json')
                  self.end_headers()
                  self.wfile.write(json.dumps(h, indent=2).encode())
              elif self.path == '/metrics':
                  self.send_metrics()
              else:
                  self.send_response(404)
                  self.end_headers()
          
          def get_health(self):
              services = {}
              for s in ['vpp', 'flexiwan', 'suricata', 'bird']:
                  services[s] = subprocess.run(['systemctl', 'is-active', s],
                      capture_output=True).returncode == 0
              return {
                  'status': 'healthy' if services['vpp'] and services['flexiwan'] else 'unhealthy',
                  'pop': '${pop_name}',
                  'role': '${role}',
                  'nic_type': '${nic_type}',
                  'nic_speed_gbps': ${nic_speed},
                  'services': services
              }
          
          def send_metrics(self):
              self.send_response(200)
              self.send_header('Content-Type', 'text/plain')
              self.end_headers()
              h = self.get_health()
              up = 1 if h['status'] == 'healthy' else 0
              self.wfile.write(f'opensase_up{{pop="{h["pop"]}",role="{h["role"]}"}} {up}\n'.encode())
              self.wfile.write(f'opensase_nic_speed_gbps{{pop="{h["pop"]}"}} {h["nic_speed_gbps"]}\n'.encode())
      
      if __name__ == '__main__':
          with socketserver.TCPServer(('', 8080), H) as s:
              print("OpenSASE Health API on :8080")
              s.serve_forever()

  # Health check systemd service
  - path: /etc/systemd/system/opensase-health.service
    content: |
      [Unit]
      Description=OpenSASE Health Check API
      After=network.target vpp.service
      
      [Service]
      Type=simple
      ExecStart=/usr/bin/python3 /opt/opensase/health.py
      Restart=always
      RestartSec=5
      
      [Install]
      WantedBy=multi-user.target

  # Installation script
  - path: /opt/opensase/install.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      set -euo pipefail
      
      echo "=== OpenSASE PoP ${pop_name} Installation ==="
      echo "Role: ${role}"
      echo "NIC: ${nic_type} @ ${nic_speed} Gbps"
      
      # 1. Apply sysctl
      sysctl -p /etc/sysctl.d/99-opensase.conf
      
      # 2. Setup hugepages
      mkdir -p /dev/hugepages
      mount -t hugetlbfs nodev /dev/hugepages || true
      echo ${nic_speed >= 100 ? 8192 : 4096} > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
      
%{ if nic_type == "mellanox_cx5" || nic_type == "mellanox_cx6" ~}
      # 3. Install Mellanox OFED (for ConnectX NICs)
      echo "Installing Mellanox OFED..."
      wget -q https://content.mellanox.com/ofed/MLNX_OFED-5.9-0.5.6.0/MLNX_OFED_LINUX-5.9-0.5.6.0-ubuntu22.04-x86_64.tgz -O /tmp/mlnx.tgz
      cd /tmp && tar xzf mlnx.tgz
      cd MLNX_OFED_LINUX-* && ./mlnxofedinstall --force --without-fw-update || true
%{ else ~}
      # 3. Load VFIO for Intel NICs
      modprobe vfio-pci
      echo "vfio-pci" >> /etc/modules-load.d/vfio.conf
      
      # Bind NICs to DPDK
      for pci in $(lspci -D | grep -E "(XXV710|X710|E810|ConnectX)" | awk '{print $1}'); do
        echo "Binding $pci to vfio-pci"
        echo "$pci" > /sys/bus/pci/devices/$pci/driver/unbind 2>/dev/null || true
        echo "vfio-pci" > /sys/bus/pci/devices/$pci/driver_override
        echo "$pci" > /sys/bus/pci/drivers/vfio-pci/bind 2>/dev/null || true
      done
%{ endif ~}
      
      # 4. Install VPP
      apt-get update
      apt-get install -y vpp vpp-plugin-dpdk vpp-plugin-wireguard vpp-plugin-acl vpp-plugin-nat
      
      # 5. Install Suricata
      add-apt-repository ppa:oisf/suricata-stable -y
      apt-get update
      apt-get install -y suricata suricata-update
      suricata-update
      
      # 6. Install BIRD for BGP
      apt-get install -y bird2
      
      # 7. Install FlexiEdge
      curl -sL https://deb.flexiwan.com/setup | bash
      mkdir -p /etc/flexiwan
      apt-get install -y flexiwan-router
      
      # 8. Enable and start services
      systemctl daemon-reload
      systemctl enable vpp suricata bird flexiwan opensase-health
      
      systemctl start vpp
      sleep 5
      systemctl start suricata
      systemctl start bird
      systemctl start flexiwan
      systemctl start opensase-health
      
      echo "=== OpenSASE PoP ${pop_name} Installation Complete ==="

runcmd:
  - mkdir -p /opt/opensase/bin
  - mkdir -p /var/log/opensase
  - mkdir -p /etc/opensase
  - /opt/opensase/install.sh 2>&1 | tee /var/log/opensase/install.log

final_message: "OpenSASE PoP ${pop_name} (${role}) ready after $UPTIME seconds"
