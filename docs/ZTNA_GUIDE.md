# OpenZiti ZTNA Guide

Zero Trust Network Access (ZTNA) implementation using OpenZiti.

## The Zero Trust Philosophy: Secure Services, Not IPs

Traditional networking secures **network segments**—firewalls, VLANs, IP allowlists. This assumes:
- Everything inside the network is trusted
- Access is granted by network location
- Applications need open inbound ports

**Zero Trust flips this model:**

| Traditional | Zero Trust (Ziti) |
|-------------|-------------------|
| Secure the network | Secure each service |
| Trust by IP/location | Trust by identity |
| Inbound ports open | No inbound ports ("dark") |
| Firewall rules | Identity policies |
| VPN to access | Outbound-only connections |

### What is a "Dark Service"?

A dark service has **no listening ports**. It cannot be discovered by port scanners. It doesn't exist on the network until an authorized identity requests access.

```
Traditional App:                     Dark Service (Ziti):
                                     
   Internet                             Internet
       │                                    │
       ▼                                    ▼
   ┌───────┐                           ┌───────┐
   │ :443  │ ← Port OPEN               │       │ ← No ports!
   └───────┘                           └───────┘
       │                                    │
    Firewall rules                      Ziti Fabric
    IP allowlists                       (outbound only)
       │                                    │
       ▼                                    ▼
   ┌───────┐                           ┌───────┐
   │  App  │                           │  App  │
   └───────┘                           └───────┘
```

---

## Architecture

```
                    ┌─────────────────────────────────────┐
                    │         Ziti Controller             │
                    │   (Identity, Policy, Routing)       │
                    │          Port 1280                  │
                    └────────────────┬────────────────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              │                      │                      │
              ▼                      ▼                      ▼
    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
    │  Router PoP     │    │  Router A       │    │  Router B       │
    │  (Edge + Fabric)│    │  (Hosts app1)   │    │  (Hosts app2)   │
    │  (10.210.0.10)  │    │  (10.201.0.10)  │    │  (10.202.0.10)  │
    └─────────────────┘    └────────┬────────┘    └────────┬────────┘
                                    │                      │
                                    ▼                      ▼
                    ┌─────────────────┐    ┌─────────────────┐
                    │      app1       │    │      app2       │
                    │  10.201.0.100   │    │  10.202.0.100   │
                    │   (NO PORTS)    │    │   (NO PORTS)    │
                    └─────────────────┘    └─────────────────┘
```

### Services

| Service | DNS Name | Backend | Location |
|---------|----------|---------|----------|
| app1 | `app1.ziti` | 10.201.0.100:80 | Branch A |
| app2 | `app2.ziti` | 10.202.0.100:80 | Branch B |

These apps have **no inbound ports exposed**. They're accessible only through Ziti.

---

## Quick Start

### 1. Start ZTNA Stack

```bash
# Start Ziti controller and routers
make up-ztna

# Wait for controller to initialize (~30s)
sleep 30

# Bootstrap services, policies, and identities
./scripts/ziti-bootstrap.sh
```

### 2. Enroll Test User

```bash
./scripts/ziti-enroll-user.sh
```

This creates an enrolled identity file: `docker/openziti-identities/testuser.json`

### 3. Install Ziti Client

**macOS:**
```bash
brew install openziti/tap/ziti-edge-tunnel
```

**Linux:**
```bash
curl -sS https://get.openziti.io/install.bash | sudo bash
```

**Windows:**
Download Ziti Desktop Edge from https://openziti.io/docs/downloads

### 4. Connect and Access Services

```bash
# Run tunnel with enrolled identity
sudo ziti-edge-tunnel run \
  --identity docker/openziti-identities/testuser.json

# In another terminal, access dark services
curl http://app1.ziti
curl http://app2.ziti/get
```

---

## How It Works

### Service Access Flow

```
┌────────┐      ┌────────────┐      ┌──────────┐      ┌────────┐
│ Client │──1──▶│   Ziti     │──2──▶│  Router  │──3──▶│  App   │
│        │      │ Controller │      │    A     │      │  app1  │
└────────┘      └────────────┘      └──────────┘      └────────┘
                     │
                     ▼
              ┌────────────┐
              │  Validate  │
              │  Identity  │
              │  + Policy  │
              └────────────┘

1. Client presents identity certificate
2. Controller validates identity, checks policy
3. If authorized, establishes encrypted session to router
4. Router forwards to backend app
```

### Key Concepts

| Concept | Description |
|---------|-------------|
| **Identity** | Cryptographic certificate representing a user or device |
| **Service** | Named resource (app1, app2) with backend address |
| **Policy** | Rules defining who can access what |
| **Router** | Fabric node that hosts services or routes traffic |

---

## Identity Management

### Current Setup (Local Identities)

The lab uses local PKI for simplicity:

```bash
# Create identity with enrollment token
ziti edge create identity user alice --role-attributes users -o alice.jwt

# Enroll identity
ziti edge enroll --jwt alice.jwt --out alice.json

# Use identity
ziti-edge-tunnel run --identity alice.json
```

### Keycloak OIDC Integration (Upgrade Path)

OpenZiti supports external JWT signers for OIDC integration:

```bash
# Create external JWT signer
ziti edge create ext-jwt-signer keycloak-signer \
  --issuer "http://localhost:8443/realms/opensase-lab" \
  --audience "ziti-console" \
  --jwks-endpoint "http://keycloak:8080/realms/opensase-lab/protocol/openid-connect/certs"

# Create auth policy using Keycloak
ziti edge create auth-policy keycloak-auth \
  --primary-ext-jwt-allowed \
  --primary-ext-jwt-allowed-signers keycloak-signer
```

See `docs/ZTNA_KEYCLOAK_INTEGRATION.md` for full OIDC setup.

---

## Adding a New Application

**Time: < 5 minutes**

### Step 1: Create Service Config

```bash
# Intercept config - what the client sees
ziti edge create config myapp-intercept-config intercept.v1 \
  '{"protocols":["tcp"],"addresses":["myapp.ziti"],"portRanges":[{"low":443,"high":443}]}'

# Host config - where traffic goes
ziti edge create config myapp-host-config host.v1 \
  '{"protocol":"tcp","address":"10.203.0.50","port":443}'
```

### Step 2: Create Service

```bash
ziti edge create service myapp \
  --configs myapp-intercept-config,myapp-host-config \
  --role-attributes myapp-service
```

### Step 3: Create Policies

```bash
# Which router hosts the service
ziti edge create service-policy myapp-bind Bind \
  --service-roles '@myapp' \
  --identity-roles '#router-c'

# Who can access the service
ziti edge create service-policy myapp-dial Dial \
  --service-roles '@myapp' \
  --identity-roles '#users'
```

### Step 4: Done!

```bash
# Access from enrolled client
curl https://myapp.ziti
```

---

## Client Setup Guide

### Option 1: Ziti Desktop Edge (GUI - Recommended)

1. Download from https://openziti.io/docs/downloads
2. Install and launch
3. Click "Add Identity" → "From File"
4. Select `docker/openziti-identities/testuser.json`
5. Toggle connection ON
6. Open browser to `http://app1.ziti`

### Option 2: Ziti Edge Tunnel (CLI)

```bash
# macOS/Linux
sudo ziti-edge-tunnel run \
  --identity /path/to/testuser.json

# DNS entries are automatically created
# Access services by name
curl http://app1.ziti
```

### Option 3: Docker

```bash
docker run -it --rm \
  --cap-add NET_ADMIN \
  --device /dev/net/tun \
  -v $(pwd)/docker/openziti-identities:/identities \
  openziti/ziti-edge-tunnel \
  run --identity /identities/testuser.json
```

---

## Testing

### Run ZTNA Tests

```bash
./scripts/test-ztna.sh
```

### Manual Tests

```bash
# Verify services exist
docker exec ziti-controller ziti edge list services

# Verify policies
docker exec ziti-controller ziti edge list service-policies

# Test dark service isolation (should fail)
curl http://10.201.0.100  # Should timeout - no direct access!

# Test via Ziti (requires enrolled tunnel)
curl http://app1.ziti    # Should work through Ziti
```

---

## Troubleshooting

### Identity Enrollment Failed

```bash
# Check JWT is valid
cat testuser.jwt | cut -d. -f2 | base64 -d 2>/dev/null | jq

# Re-create identity
ziti edge delete identity testuser
ziti edge create identity user testuser --role-attributes users -o testuser.jwt
```

### Service Not Accessible

```bash
# Check service exists
ziti edge list services | grep app1

# Check policies
ziti edge list service-policies | grep app1

# Check router hosts service
ziti edge list terminators
```

### Tunnel Not Connecting

```bash
# Check controller is reachable
curl -k https://localhost:1280/edge/v1/version

# Check identity file is valid
cat testuser.json | jq '.id'

# Run with debug logging
ziti-edge-tunnel run --identity testuser.json --verbose 4
```

---

## Security Model

| Layer | Protection |
|-------|------------|
| **Identity** | mTLS certificates, no passwords |
| **Authorization** | Policy-based, allow-only |
| **Network** | No inbound ports, outbound-only |
| **Encryption** | End-to-end encryption |
| **Audit** | All access logged with identity |

---

## API Reference

### Ziti CLI (in controller container)

```bash
# Login
docker exec -it ziti-controller ziti edge login localhost:1280 -u admin -p $ZITI_PWD

# List resources
ziti edge list services
ziti edge list identities
ziti edge list service-policies
ziti edge list edge-routers

# Create resources
ziti edge create service <name> --configs <config1>,<config2>
ziti edge create identity user <name> --role-attributes <roles>
ziti edge create service-policy <name> <Dial|Bind> --service-roles <roles> --identity-roles <roles>
```

### REST API

```bash
# Get token
TOKEN=$(curl -sk -X POST https://localhost:1280/edge/management/v1/authenticate \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' | jq -r '.data.token')

# List services
curl -sk https://localhost:1280/edge/management/v1/services \
  -H "zt-session: $TOKEN" | jq
```

---

## Related Documentation

- [Architecture Overview](ARCHITECTURE.md)
- [FlexiWAN Manual Enrollment](FLEXIWAN_MANUAL_ENROLLMENT.md)
- [Security PoP Guide](SECURITY_POP_GUIDE.md)
- [OpenZiti Docs](https://openziti.io/docs)
