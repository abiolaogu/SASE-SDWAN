# DLP-lite

Basic data classification and alerting without full enterprise DLP.

## Overview

DLP-lite provides basic data loss prevention capabilities through pattern-based content classification and alerting.

## Requirements

### Functional
- Classifier library with regex, checksum patterns, entropy checks
- Integration at proxy logs and endpoint file scan demo
- Emit alerts to Wazuh with severity and context
- Safe sample files for testing

### Non-Goals
- Inline content blocking
- ML-based classification
- Full endpoint agent deployment
- Real-time file monitoring

## Quick Start

```bash
# Install
pip install -e components/dlp-lite

# List available classifiers
dlp-lite classifiers list

# Scan text
dlp-lite scan --text "My SSN is 123-45-6789"

# Scan file
dlp-lite scan --file /path/to/document.txt

# Scan proxy logs
dlp-lite scan-logs --source squid --path /var/log/squid/access.log

# Start API server
dlp-lite serve --port 8093
```

## Built-in Classifiers

| Classifier | Pattern Type | Examples |
|------------|--------------|----------|
| SSN (US) | Regex + Luhn | 123-45-6789 |
| Credit Card | Regex + Luhn | 4111-1111-1111-1111 |
| Email | Regex | user@example.com |
| Phone (US) | Regex | (555) 123-4567 |
| API Key | Entropy + Pattern | sk_live_xxxx |
| AWS Key | Regex | AKIA... |
| Private Key | Content Match | -----BEGIN RSA PRIVATE KEY----- |
| Password | Keyword + Context | password=, secret= |

## Severity Levels

| Level | Description | Examples |
|-------|-------------|----------|
| Critical | Immediate risk | Private keys, credentials |
| High | PII or financial data | SSN, credit cards |
| Medium | Contact information | Emails, phones |
| Low | Potentially sensitive | Internal IDs |

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/classifiers` | GET | List classifiers |
| `/api/v1/scan/text` | POST | Scan text content |
| `/api/v1/scan/file` | POST | Scan file content |
| `/api/v1/alerts` | GET | Recent DLP alerts |
| `/health` | GET | Health check |

## Custom Classifiers

Add custom classifiers in YAML format:

```yaml
name: employee-id
description: Internal employee ID
pattern: "EMP-[0-9]{6}"
severity: low
context_required: false
```

## Integration Points

### Proxy Logs (Squid)
- Scans HTTP request/response bodies logged by Squid
- Requires Squid configured with content logging

### Endpoint File Scan
- Scans files in specified directories
- Safe sample files included for testing

## Limitations vs Full DLP

| Feature | DLP-lite | Enterprise DLP |
|---------|----------|----------------|
| Pattern matching | ✓ | ✓ |
| Checksum validation | ✓ | ✓ |
| Entropy analysis | ✓ | ✓ |
| ML classification | ✗ | ✓ |
| Inline blocking | ✗ | ✓ |
| Endpoint agent | ✗ | ✓ |
| Cloud storage scan | ✗ | ✓ |
| Fingerprinting | ✗ | ✓ |
| Policy editor UI | ✗ | ✓ |
