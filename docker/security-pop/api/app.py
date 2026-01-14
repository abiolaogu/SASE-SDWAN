"""
Security PoP Management API - Enhanced
FastAPI-based REST API for managing Suricata, Unbound, Squid, and nftables
Includes Prometheus metrics endpoint
"""

from flask import Flask, jsonify, request
import subprocess
import json
import os
import re
from datetime import datetime
from functools import wraps

app = Flask(__name__)

# ============================================
# Utility Functions
# ============================================

def run_command(cmd, timeout=10):
    """Run a shell command and return output"""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Command timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def read_file_tail(filepath, lines=100):
    """Read last N lines of a file"""
    try:
        result = run_command(f"tail -n {lines} {filepath}")
        return result.get("stdout", "")
    except:
        return ""


# ============================================
# Health & Status Endpoints
# ============================================

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    services = {
        "suricata": check_suricata_status(),
        "unbound": check_unbound_status(),
        "squid": check_squid_status(),
        "nftables": check_nftables_status()
    }
    
    all_healthy = all(s.get("running", False) for s in services.values())
    
    return jsonify({
        "status": "healthy" if all_healthy else "degraded",
        "timestamp": datetime.utcnow().isoformat(),
        "services": services
    })


def check_suricata_status():
    """Check Suricata status"""
    result = run_command("pgrep suricata")
    return {
        "running": result["success"],
        "pid": result.get("stdout", "").split()[0] if result["success"] else None
    }


def check_unbound_status():
    """Check Unbound status"""
    result = run_command("pgrep unbound")
    return {
        "running": result["success"],
        "pid": result.get("stdout", "").split()[0] if result["success"] else None
    }


def check_squid_status():
    """Check Squid status"""
    result = run_command("pgrep squid")
    return {
        "running": result["success"],
        "pid": result.get("stdout", "").split()[0] if result["success"] else None
    }


def check_nftables_status():
    """Check nftables status"""
    result = run_command("nft list tables")
    return {
        "running": result["success"],
        "tables": len(result.get("stdout", "").split("\n")) if result["success"] else 0
    }


# ============================================
# Suricata Endpoints
# ============================================

@app.route('/api/suricata/stats', methods=['GET'])
def suricata_stats():
    """Get Suricata statistics"""
    result = run_command("suricatasc -c 'dump-counters'")
    if result["success"]:
        try:
            # Parse JSON output
            stats = json.loads(result["stdout"])
            return jsonify({"success": True, "stats": stats})
        except:
            return jsonify({"success": True, "raw": result["stdout"]})
    return jsonify({"success": False, "error": result.get("stderr", "Unknown error")})


@app.route('/api/suricata/alerts', methods=['GET'])
def suricata_alerts():
    """Get recent Suricata alerts from EVE JSON"""
    limit = request.args.get('limit', 50, type=int)
    severity = request.args.get('severity', None)
    
    try:
        eve_file = "/var/log/suricata/eve.json"
        if not os.path.exists(eve_file):
            return jsonify({"success": True, "alerts": [], "message": "No alerts yet"})
        
        # Read last N lines and parse alerts
        result = run_command(f"tail -n 1000 {eve_file} | grep '\"event_type\":\"alert\"' | tail -n {limit}")
        
        alerts = []
        for line in result.get("stdout", "").split("\n"):
            if line.strip():
                try:
                    event = json.loads(line)
                    alert = {
                        "timestamp": event.get("timestamp"),
                        "signature": event.get("alert", {}).get("signature"),
                        "severity": event.get("alert", {}).get("severity"),
                        "category": event.get("alert", {}).get("category"),
                        "src_ip": event.get("src_ip"),
                        "dest_ip": event.get("dest_ip"),
                        "proto": event.get("proto")
                    }
                    if severity is None or alert.get("severity") == severity:
                        alerts.append(alert)
                except json.JSONDecodeError:
                    continue
        
        return jsonify({"success": True, "alerts": alerts, "count": len(alerts)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route('/api/suricata/rules/reload', methods=['POST'])
def suricata_reload_rules():
    """Reload Suricata rules"""
    result = run_command("suricatasc -c 'reload-rules'")
    return jsonify({
        "success": result["success"],
        "message": "Rules reloaded" if result["success"] else result.get("stderr", "Failed")
    })


@app.route('/api/suricata/fast-log', methods=['GET'])
def suricata_fast_log():
    """Get fast.log entries"""
    limit = request.args.get('limit', 50, type=int)
    log = read_file_tail("/var/log/suricata/fast.log", limit)
    return jsonify({"success": True, "log": log.split("\n") if log else []})


# ============================================
# Unbound DNS Endpoints
# ============================================

@app.route('/api/dns/stats', methods=['GET'])
def dns_stats():
    """Get Unbound statistics"""
    result = run_command("unbound-control stats")
    if result["success"]:
        stats = {}
        for line in result["stdout"].split("\n"):
            if "=" in line:
                key, value = line.split("=", 1)
                stats[key] = value
        return jsonify({"success": True, "stats": stats})
    return jsonify({"success": False, "error": result.get("stderr", "Unknown error")})


@app.route('/api/dns/flush', methods=['POST'])
def dns_flush():
    """Flush DNS cache"""
    zone = request.json.get('zone', 'all') if request.is_json else 'all'
    if zone == 'all':
        result = run_command("unbound-control flush_zone .")
    else:
        result = run_command(f"unbound-control flush_zone {zone}")
    return jsonify({
        "success": result["success"],
        "message": f"Flushed {zone}" if result["success"] else result.get("stderr", "Failed")
    })


@app.route('/api/dns/query-log', methods=['GET'])
def dns_query_log():
    """Get recent DNS queries"""
    limit = request.args.get('limit', 50, type=int)
    log = read_file_tail("/var/log/unbound/queries.log", limit)
    return jsonify({"success": True, "queries": log.split("\n") if log else []})


# ============================================
# Squid Proxy Endpoints
# ============================================

@app.route('/api/proxy/stats', methods=['GET'])
def proxy_stats():
    """Get Squid statistics"""
    result = run_command("squidclient -h localhost mgr:info")
    if result["success"]:
        return jsonify({"success": True, "stats": result["stdout"]})
    return jsonify({"success": False, "error": result.get("stderr", "Unknown error")})


@app.route('/api/proxy/access-log', methods=['GET'])
def proxy_access_log():
    """Get recent proxy access log entries"""
    limit = request.args.get('limit', 50, type=int)
    log = read_file_tail("/var/log/squid/access.log", limit)
    return jsonify({"success": True, "log": log.split("\n") if log else []})


@app.route('/api/proxy/cache/clear', methods=['POST'])
def proxy_cache_clear():
    """Clear Squid cache"""
    result = run_command("squid -k rotate")
    return jsonify({
        "success": result["success"],
        "message": "Cache rotated" if result["success"] else result.get("stderr", "Failed")
    })


# ============================================
# Firewall Endpoints
# ============================================

@app.route('/api/firewall/rules', methods=['GET'])
def firewall_rules():
    """Get current nftables rules"""
    result = run_command("nft -j list ruleset")
    if result["success"]:
        try:
            rules = json.loads(result["stdout"])
            return jsonify({"success": True, "ruleset": rules})
        except:
            return jsonify({"success": True, "raw": result["stdout"]})
    return jsonify({"success": False, "error": result.get("stderr", "Unknown error")})


@app.route('/api/firewall/counters', methods=['GET'])
def firewall_counters():
    """Get firewall counters"""
    result = run_command("nft list counters")
    return jsonify({
        "success": result["success"],
        "counters": result.get("stdout", "")
    })


@app.route('/api/firewall/block', methods=['POST'])
def firewall_block_ip():
    """Block an IP address"""
    if not request.is_json:
        return jsonify({"success": False, "error": "JSON required"}), 400
    
    ip = request.json.get('ip')
    if not ip:
        return jsonify({"success": False, "error": "IP required"}), 400
    
    # Validate IP format
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(ip_pattern, ip):
        return jsonify({"success": False, "error": "Invalid IP format"}), 400
    
    result = run_command(f"nft add element inet filter blocked_ips {{ {ip} }}")
    return jsonify({
        "success": result["success"],
        "message": f"Blocked {ip}" if result["success"] else result.get("stderr", "Failed")
    })


@app.route('/api/firewall/unblock', methods=['POST'])
def firewall_unblock_ip():
    """Unblock an IP address"""
    if not request.is_json:
        return jsonify({"success": False, "error": "JSON required"}), 400
    
    ip = request.json.get('ip')
    if not ip:
        return jsonify({"success": False, "error": "IP required"}), 400
    
    result = run_command(f"nft delete element inet filter blocked_ips {{ {ip} }}")
    return jsonify({
        "success": result["success"],
        "message": f"Unblocked {ip}" if result["success"] else result.get("stderr", "Failed")
    })


# ============================================
# Prometheus Metrics Endpoint
# ============================================

@app.route('/metrics', methods=['GET'])
def prometheus_metrics():
    """Prometheus-compatible metrics endpoint"""
    metrics = []
    
    # Suricata metrics
    suricata_running = 1 if check_suricata_status()["running"] else 0
    metrics.append(f"security_pop_suricata_running {suricata_running}")
    
    # Get alert count
    try:
        result = run_command("wc -l /var/log/suricata/fast.log 2>/dev/null || echo 0")
        alert_count = int(result.get("stdout", "0").split()[0])
        metrics.append(f"security_pop_suricata_alerts_total {alert_count}")
    except:
        metrics.append("security_pop_suricata_alerts_total 0")
    
    # Unbound metrics
    unbound_running = 1 if check_unbound_status()["running"] else 0
    metrics.append(f"security_pop_unbound_running {unbound_running}")
    
    # Squid metrics
    squid_running = 1 if check_squid_status()["running"] else 0
    metrics.append(f"security_pop_squid_running {squid_running}")
    
    # nftables metrics
    nft_result = run_command("nft list counters 2>/dev/null | grep -c 'counter'")
    nft_counters = int(nft_result.get("stdout", "0")) if nft_result["success"] else 0
    metrics.append(f"security_pop_nftables_counters {nft_counters}")
    
    return "\n".join(metrics), 200, {"Content-Type": "text/plain"}


# ============================================
# Demo Endpoints
# ============================================

@app.route('/api/demo/trigger-alert', methods=['POST'])
def demo_trigger_alert():
    """Trigger a safe demo alert for testing"""
    alert_type = request.json.get('type', 'http') if request.is_json else 'http'
    
    if alert_type == 'http':
        # This will trigger our safe-demo.rules HTTP alert
        result = run_command("curl -s -H 'User-Agent: OpenSASE-Test' http://localhost/opensase-test || true")
        message = "HTTP test alert triggered"
    elif alert_type == 'dns':
        # Trigger DNS alert
        result = run_command("dig @localhost test.opensase.lab || true")
        message = "DNS test alert triggered"
    else:
        return jsonify({"success": False, "error": f"Unknown alert type: {alert_type}"}), 400
    
    return jsonify({
        "success": True,
        "message": message,
        "note": "Check /api/suricata/alerts or fast.log for the alert"
    })


@app.route('/api/demo/test-ips', methods=['GET'])
def demo_test_ips():
    """Return instructions for testing IPS safely"""
    return jsonify({
        "success": True,
        "instructions": [
            {
                "name": "HTTP Test Alert",
                "command": "curl -H 'User-Agent: OpenSASE-Test' http://security-pop/opensase-test",
                "expected": "Alert SID 9000002 in fast.log"
            },
            {
                "name": "DNS Test Alert",
                "command": "dig @10.200.0.1 test.opensase.lab",
                "expected": "Alert SID 9000010 in fast.log"
            },
            {
                "name": "Custom Header Test",
                "command": "curl -H 'X-OpenSASE-Test: true' http://security-pop/anypath",
                "expected": "Alert SID 9000003 in fast.log"
            },
            {
                "name": "View Alerts",
                "command": "docker exec security-pop tail -20 /var/log/suricata/fast.log",
                "expected": "Recent IPS alerts"
            }
        ]
    })


# ============================================
# Main
# ============================================

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False, threaded=True)
