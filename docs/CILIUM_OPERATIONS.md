# Cilium Operations Guide

## Daily Operations

### Check Cilium Status

```bash
# Cilium status
cilium status

# All Cilium pods
kubectl -n kube-system get pods -l k8s-app=cilium

# Cilium version
cilium version
```

### Check Connectivity

```bash
# Full connectivity test
cilium connectivity test

# Quick health check
cilium status --verbose
```

---

## Hubble (Observability)

### Enable Hubble CLI

```bash
# Install Hubble CLI
export HUBBLE_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/hubble/master/stable.txt)
curl -L --remote-name-all https://github.com/cilium/hubble/releases/download/$HUBBLE_VERSION/hubble-linux-amd64.tar.gz
tar xzvf hubble-linux-amd64.tar.gz
sudo mv hubble /usr/local/bin/

# Port-forward to Hubble Relay
cilium hubble port-forward &
```

### View Flows

```bash
# All flows
hubble observe

# Flows for specific namespace
hubble observe --namespace opensase

# Flows to/from specific pod
hubble observe --pod api-server-xxx

# Only dropped packets
hubble observe --verdict DROPPED

# Follow mode
hubble observe -f

# JSON output
hubble observe --output json
```

### Flow Filters

```bash
# HTTP flows
hubble observe --protocol http

# DNS queries
hubble observe --protocol dns

# TCP connections
hubble observe --protocol tcp

# Specific port
hubble observe --to-port 443
```

---

## Network Policies

### List Policies

```bash
# Cilium network policies
kubectl get ciliumnetworkpolicies -A

# Kubernetes network policies
kubectl get networkpolicies -A
```

### Debug Policy

```bash
# Check endpoint policy
cilium endpoint list
cilium endpoint get <endpoint-id>

# Policy verdict for specific flow
cilium policy trace --src <pod1> --dst <pod2> --dport 80
```

### Apply Policy

```bash
# Example: Allow only HTTPS to api-server
cat <<EOF | kubectl apply -f -
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: api-server-ingress
  namespace: opensase
spec:
  endpointSelector:
    matchLabels:
      app: api-server
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: portal
      toPorts:
        - ports:
            - port: "8080"
              protocol: TCP
EOF
```

---

## Load Balancer

### Check LB Status

```bash
# Cilium LB status
cilium service list

# Maglev backend table
cilium bpf lb list

# XDP status
cilium bpf xdp list
```

### LB IP Allocation

```bash
# Check allocated IPs
kubectl get svc -A -o wide | grep LoadBalancer

# Check Cilium IP pool
kubectl get ippools
```

---

## Cluster Mesh

### Status

```bash
# Cluster mesh status
cilium clustermesh status

# Connected clusters
cilium clustermesh status --wait
```

### Connect Clusters

```bash
# Enable cluster mesh
cilium clustermesh enable

# Connect to another cluster
cilium clustermesh connect --destination-context opensase-fra1

# Disconnect
cilium clustermesh disconnect <cluster-name>
```

### Global Services

```bash
# List global services
kubectl get svc -A -o json | jq '.items[] | select(.metadata.annotations["io.cilium/global-service"]=="true") | .metadata.name'
```

---

## BGP

### Check BGP Status

```bash
# BGP peers
cilium bgp peers

# Advertised routes
cilium bgp routes advertised

# Received routes
cilium bgp routes available
```

---

## Encryption (WireGuard)

### Check Encryption Status

```bash
# WireGuard status
cilium status | grep Encryption

# WireGuard peers
cilium encrypt status

# Node-to-node encryption
cilium bpf tunnel list
```

---

## Troubleshooting

### Cilium Agent Logs

```bash
# All agent logs
kubectl -n kube-system logs -l k8s-app=cilium -f

# Specific node
kubectl -n kube-system logs cilium-xxxxx -f
```

### Endpoint Issues

```bash
# List all endpoints
cilium endpoint list

# Endpoint details
cilium endpoint get <id>

# Regenerate endpoint
cilium endpoint regenerate <id>
```

### Connectivity Issues

```bash
# Check BPF maps
cilium bpf ct list global

# Check NAT
cilium bpf nat list

# Flush connection tracking
cilium bpf ct flush global
```

### DNS Issues

```bash
# Check DNS proxy
cilium bpf proxy list

# DNS resolution test
hubble observe --protocol dns
```

---

## Performance Tuning

### XDP Settings

```yaml
# In cilium values.yaml
loadBalancer:
  acceleration: native  # XDP native mode
  mode: dsr             # Direct Server Return
```

### Resource Limits

```yaml
resources:
  limits:
    cpu: 4000m
    memory: 4Gi
  requests:
    cpu: 100m
    memory: 512Mi
```

### BBR Congestion Control

```yaml
bandwidthManager:
  enabled: true
  bbr: true
```

---

## Upgrade Cilium

```bash
# Check current version
cilium version

# Pre-flight check
cilium upgrade --check

# Upgrade
helm upgrade cilium cilium/cilium \
  --namespace kube-system \
  --values cilium/values.yaml \
  --version 1.15.0

# Verify
cilium status
cilium connectivity test
```

---

## Emergency Procedures

### Disable Cilium (Emergency)

```bash
# Scale down (emergency only!)
kubectl -n kube-system scale daemonset cilium --replicas=0

# Or delete
kubectl -n kube-system delete daemonset cilium
```

### Restore kube-proxy (Fallback)

```bash
# If Cilium fails, restore kube-proxy
kubectl -n kube-system patch daemonset kube-proxy \
  --patch '{"spec":{"template":{"spec":{"containers":[{"name":"kube-proxy","resources":{},"livenessProbe":null}]}}}}'
```
