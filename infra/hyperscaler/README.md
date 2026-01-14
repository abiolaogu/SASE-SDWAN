# ⚠️ HYPERSCALER MVP DEPLOYMENT ⚠️

## 🚨 IMPORTANT NOTICE 🚨

**This infrastructure is for MVP, DEMONSTRATION, and EARLY STARTUP STAGE ONLY.**

### Why This Exists
- Zero upfront capital required
- Pay-per-hour usage (100% Opex)
- Quick deployment for customer demos
- Testing and development environment
- Early-stage startup operations before revenue justifies bare-metal

### Limitations vs Production (Bare-Metal)

| Aspect | Hyperscaler MVP | Bare-Metal Production |
|--------|-----------------|----------------------|
| Throughput | ~10 Gbps max | 100+ Gbps |
| Latency | Variable (+5-20ms) | Consistent (<5ms) |
| Cost per Gbps | ~$0.08-0.12/GB | ~$0.01-0.02/GB |
| DDoS Capacity | Provider-limited | 100+ Gbps scrubbing |
| Kernel Bypass | Not available | DPDK/VPP enabled |
| Cost Model | Usage-based | Fixed monthly |

### When to Migrate to Bare-Metal

Migrate a region when ANY of these conditions are met:
1. Monthly cloud spend exceeds $5,000/region
2. Sustained traffic exceeds 5 Gbps
3. Customer SLAs require <10ms latency
4. DDoS attacks exceed cloud provider limits

### Migration Path

See: [MIGRATION_PLAYBOOK.md](../docs/deployment-strategy/MIGRATION_PLAYBOOK.md)

### Directory Structure

```
/hyperscaler/
├── /aws/           # AWS-specific Terraform
├── /azure/         # Azure-specific Terraform  
├── /gcp/           # GCP-specific Terraform
├── /multi-cloud/   # Cross-cloud orchestration
└── /shared/        # Common modules (adapted for VMs)
```

### Quick Start

```bash
# Deploy MVP stack to AWS us-east-1
cd infra/hyperscaler/aws
terraform init
terraform apply -var="region=us-east-1" -var="environment=demo"

# Estimated cost: ~$500-2000/month for minimal PoP
```

### Cost Estimation

| Component | AWS | Azure | GCP |
|-----------|-----|-------|-----|
| Compute (3x c5.2xlarge) | $750/mo | $720/mo | $700/mo |
| Load Balancer | $20/mo | $25/mo | $20/mo |
| NAT Gateway | $45/mo | $45/mo | $45/mo |
| Data Transfer (1TB) | $90/mo | $87/mo | $85/mo |
| **Total (minimal)** | **~$905/mo** | **~$877/mo** | **~$850/mo** |

---

**DO NOT USE FOR:**
- Production traffic exceeding 10 Gbps
- Customers requiring guaranteed SLAs
- High-security government/financial workloads
- Any deployment where cost exceeds bare-metal equivalent
