"""
DLP-lite - Wazuh Alert Exporter
"""

import json
import socket
from datetime import datetime
from typing import List
from ..models import DLPAlert, Severity


class WazuhExporter:
    """
    Exports DLP alerts to Wazuh via syslog.
    """
    
    def __init__(
        self, 
        host: str = "localhost",
        port: int = 514,
        protocol: str = "udp"
    ):
        self.host = host
        self.port = port
        self.protocol = protocol
    
    def export(self, alert: DLPAlert) -> bool:
        """
        Export a single alert to Wazuh.
        """
        syslog_message = self._format_alert(alert)
        
        try:
            if self.protocol == "udp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(
                    syslog_message.encode(),
                    (self.host, self.port)
                )
                sock.close()
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.host, self.port))
                sock.send(syslog_message.encode())
                sock.close()
            
            return True
        except Exception as e:
            return False
    
    def export_batch(self, alerts: List[DLPAlert]) -> tuple[int, int]:
        """
        Export multiple alerts.
        
        Returns:
            (success_count, failure_count)
        """
        success = 0
        failure = 0
        
        for alert in alerts:
            if self.export(alert):
                success += 1
            else:
                failure += 1
        
        return success, failure
    
    def _format_alert(self, alert: DLPAlert) -> str:
        """
        Format alert as syslog message with DLP context.
        """
        # Map severity to syslog priority
        priority = self._severity_to_priority(alert.severity)
        
        # Format timestamp
        timestamp = alert.timestamp.strftime("%b %d %H:%M:%S")
        
        # Build message
        message = {
            "dlp_alert": True,
            "id": alert.id,
            "classifier": alert.classifier_name,
            "severity": alert.severity.value,
            "source": alert.source.value,
            "matched_count": alert.matched_count,
            "sample": alert.sample,
            "user": alert.user or "unknown",
            "source_ip": alert.source_ip or "unknown",
            "action": alert.action_taken
        }
        
        if alert.filename:
            message["filename"] = alert.filename
        
        if alert.metadata:
            message["metadata"] = alert.metadata
        
        # Format as syslog
        return f"<{priority}>{timestamp} dlp-lite: {json.dumps(message)}"
    
    def _severity_to_priority(self, severity: Severity) -> int:
        """Map DLP severity to syslog priority."""
        # Facility: local0 (16), Severity: 0-7
        facility = 16
        
        severity_map = {
            Severity.CRITICAL: 2,  # Critical
            Severity.HIGH: 3,      # Error
            Severity.MEDIUM: 4,    # Warning
            Severity.LOW: 5,       # Notice
            Severity.INFO: 6       # Info
        }
        
        sev = severity_map.get(severity, 6)
        return (facility * 8) + sev


class FileExporter:
    """
    Exports DLP alerts to JSON file.
    """
    
    def __init__(self, filepath: str = "/var/log/dlp-lite/alerts.json"):
        self.filepath = filepath
    
    def export(self, alert: DLPAlert) -> bool:
        """Export alert to file."""
        try:
            with open(self.filepath, "a") as f:
                f.write(json.dumps(alert.dict(), default=str) + "\n")
            return True
        except Exception:
            return False
    
    def export_batch(self, alerts: List[DLPAlert]) -> tuple[int, int]:
        """Export multiple alerts."""
        success = 0
        failure = 0
        
        for alert in alerts:
            if self.export(alert):
                success += 1
            else:
                failure += 1
        
        return success, failure
