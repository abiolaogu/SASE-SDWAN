#cloud-config
# OBMO Cloud-Init Configuration
# PoP: ${pop_name}, Server: ${server_index}/${server_count}

hostname: obmo-${pop_name}-${format("%02d", server_index)}
fqdn: obmo-${pop_name}-${format("%02d", server_index)}.opensase.io
manage_etc_hosts: true

package_update: true
package_upgrade: true

packages:
  - curl
  - wget
  - git
  - jq
  - htop
  - iotop
  - net-tools
  - tcpdump
  - iperf3
  - ethtool
  - pciutils
  - lshw
  - numactl
  - hwloc
  - cpufrequtils
  - python3
  - python3-pip

write_files:
  # Sysctl configuration for 100G
  - path: /etc/sysctl.d/99-obmo-100g.conf
    content: |
      net.core.rmem_max = 2147483647
      net.core.wmem_max = 2147483647
      net.core.rmem_default = 536870912
      net.core.wmem_default = 536870912
      net.core.netdev_max_backlog = 2000000
      net.core.netdev_budget = 100000
      net.ipv4.tcp_rmem = 4096 4194304 2147483647
      net.ipv4.tcp_wmem = 4096 4194304 2147483647
      net.ipv4.tcp_congestion_control = bbr
      net.ipv4.ip_forward = 1
      net.ipv6.conf.all.forwarding = 1
      vm.nr_hugepages = ${vpp_config.hugepages_gb * 512}
      vm.swappiness = 1

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
          corelist-workers 2-${vpp_config.worker_cores + 1}
          scheduler-policy fifo
          scheduler-priority 80
      }
      dpdk {
          dev default {
              num-rx-queues ${vpp_config.rx_queues}
              num-tx-queues ${vpp_config.tx_queues}
              num-rx-desc ${vpp_config.rx_desc}
              num-tx-desc ${vpp_config.tx_desc}
          }
%{ if dpdk_driver != "mlx5_core" }
          uio-driver vfio-pci
%{ endif }
          socket-mem ${vpp_config.hugepages_gb * 512},${vpp_config.hugepages_gb * 512}
          num-mbufs ${vpp_config.buffers}
          no-multi-seg
      }
      buffers {
          buffers-per-numa ${vpp_config.buffers}
          default data-size 2048
%{ if nic_speed >= 100 }
          page-size 2M
%{ endif }
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

  # FlexiEdge configuration
  - path: /etc/flexiwan/agent.conf
    content: |
      {
          "deviceName": "obmo-${pop_name}-${server_index}",
          "dataPlane": "vpp",
          "vppSocketPath": "/run/vpp/cli.sock",
          "managementUrl": "${flexiwan_url}",
          "token": "${flexiwan_token}",
          "logLevel": "info",
          "features": {
              "sdwan": true,
              "firewall": true,
              "nat": true,
              "qos": true,
              "wireguard": true
          }
      }

%{ if enable_bgp }
  # BIRD BGP configuration
  - path: /etc/bird/bird.conf
    content: |
      log syslog all;
      router id from "lo";
      
      define MY_AS = ${bgp_asn};
      
      protocol device { scan time 10; }
      protocol direct { ipv4; interface "lo"; }
      protocol kernel { ipv4 { export all; import none; }; }
      
      protocol static static_anycast {
          ipv4;
          # Anycast routes configured via Ansible
      }
      
      # Provider-specific BGP sessions via Ansible
%{ endif }

  # Health check script
  - path: /opt/obmo-health.py
    permissions: '0755'
    content: |
      #!/usr/bin/env python3
      import http.server, json, subprocess, socketserver
      
      class H(http.server.BaseHTTPRequestHandler):
          def log_message(self, format, *args): pass
          def do_GET(self):
              if self.path == '/health':
                  h = {'status': 'healthy', 'pop': '${pop_name}', 
                       'server': ${server_index}, 'provider': '${provider_type}',
                       'nic_speed': ${nic_speed}}
                  for s in ['vpp', 'flexiwan', 'bird']:
                      h[s] = subprocess.run(['systemctl', 'is-active', s],
                          capture_output=True).returncode == 0
                  h['status'] = 'healthy' if h['vpp'] and h['flexiwan'] else 'unhealthy'
                  self.send_response(200 if h['status'] == 'healthy' else 503)
                  self.send_header('Content-Type', 'application/json')
                  self.end_headers()
                  self.wfile.write(json.dumps(h).encode())
              else:
                  self.send_response(404)
                  self.end_headers()
      
      with socketserver.TCPServer(('', 8080), H) as s:
          s.serve_forever()

  # Health service unit
  - path: /etc/systemd/system/obmo-health.service
    content: |
      [Unit]
      Description=OBMO Health Check
      After=network.target
      [Service]
      ExecStart=/usr/bin/python3 /opt/obmo-health.py
      Restart=always
      [Install]
      WantedBy=multi-user.target

runcmd:
  # Apply sysctl
  - sysctl -p /etc/sysctl.d/99-obmo-100g.conf
  
  # Setup hugepages
  - mkdir -p /dev/hugepages
  - mount -t hugetlbfs nodev /dev/hugepages || true
  
%{ if dpdk_driver == "mlx5_core" }
  # Install Mellanox OFED
  - wget -q https://content.mellanox.com/ofed/MLNX_OFED-5.9-0.5.6.0/MLNX_OFED_LINUX-5.9-0.5.6.0-ubuntu22.04-x86_64.tgz -O /tmp/mlnx.tgz
  - cd /tmp && tar xzf mlnx.tgz && cd MLNX_OFED_LINUX-* && ./mlnxofedinstall --force --without-fw-update || true
%{ else }
  # Load VFIO for Intel NICs
  - modprobe vfio-pci
  - echo "vfio-pci" >> /etc/modules-load.d/vfio.conf
%{ endif }

  # Install VPP
  - curl -sL https://packagecloud.io/install/repositories/fdio/release/script.deb.sh | bash
  - apt-get install -y vpp vpp-plugin-core vpp-plugin-dpdk vpp-plugin-wireguard vpp-plugin-nat vpp-plugin-acl
  
  # Install FlexiEdge
  - curl -sL https://deb.flexiwan.com/setup | bash
  - mkdir -p /etc/flexiwan
  - apt-get install -y flexiwan-router
  
%{ if enable_bgp }
  # Install BIRD
  - apt-get install -y bird2
%{ endif }

  # Enable services
  - systemctl daemon-reload
  - systemctl enable vpp flexiwan obmo-health
%{ if enable_bgp }
  - systemctl enable bird
%{ endif }
  
  # Start services
  - systemctl start vpp
  - sleep 5
  - systemctl start flexiwan
%{ if enable_bgp }
  - systemctl start bird
%{ endif }
  - systemctl start obmo-health

final_message: "OBMO ${pop_name}-${server_index} ready in $UPTIME seconds"
