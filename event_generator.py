#!/usr/bin/env python3
"""
Event Generator Module for Aegis Cloud Security System
Generates mock security events simulating cloud environment activities.
"""

import random
import json
from datetime import datetime, timedelta

class CloudEventGenerator:
    """
    Generates realistic mock security events for cloud environment simulation.
    Produces both normal activities and potential security threats.
    """
    
    def __init__(self):
        """Initialize the event generator with predefined event templates."""
        
        # Normal event templates
        self.normal_events = [
            {
                "event_type": "user_login",
                "severity": "info",
                "description": "User successfully logged in",
                "source_ip": None,  # Will be randomly assigned
                "user_id": None,    # Will be randomly assigned
                "resource": "authentication_service"
            },
            {
                "event_type": "api_call",
                "severity": "info", 
                "description": "Authorized API call executed",
                "source_ip": None,
                "user_id": None,
                "resource": "compute_service"
            },
            {
                "event_type": "file_access",
                "severity": "info",
                "description": "File accessed successfully",
                "source_ip": None,
                "user_id": None,
                "resource": "storage_service"
            },
            {
                "event_type": "system_update",
                "severity": "info",
                "description": "System configuration updated",
                "source_ip": "internal",
                "user_id": "system",
                "resource": "management_service"
            }
        ]
        
        # Threat event templates
        self.threat_events = [
            {
                "event_type": "failed_login",
                "severity": "warning",
                "description": "Multiple failed login attempts detected",
                "source_ip": None,
                "user_id": None,
                "resource": "authentication_service",
                "threat_indicators": ["brute_force", "suspicious_ip"]
            },
            {
                "event_type": "unauthorized_access",
                "severity": "critical",
                "description": "Unauthorized access attempt to restricted resource",
                "source_ip": None,
                "user_id": None,
                "resource": "admin_panel",
                "threat_indicators": ["privilege_escalation", "unauthorized_access"]
            },
            {
                "event_type": "suspicious_api_call",
                "severity": "high",
                "description": "API call from unrecognized source",
                "source_ip": None,
                "user_id": None,
                "resource": "data_service",
                "threat_indicators": ["anomalous_behavior", "suspicious_api_usage"]
            },
            {
                "event_type": "data_exfiltration",
                "severity": "critical",
                "description": "Large data transfer to external location",
                "source_ip": None,
                "user_id": None,
                "resource": "database_service",
                "threat_indicators": ["data_exfiltration", "suspicious_transfer"]
            },
            {
                "event_type": "malware_detection",
                "severity": "critical",
                "description": "Malicious code detected in system",
                "source_ip": None,
                "user_id": None,
                "resource": "endpoint_security",
                "threat_indicators": ["malware", "code_injection"]
            }
        ]
        
        # IP address pools for simulation
        self.normal_ips = [
            "192.168.1.10", "192.168.1.15", "192.168.1.20", "192.168.1.25",
            "10.0.0.5", "10.0.0.10", "10.0.0.15", "172.16.0.5"
        ]
        
        self.suspicious_ips = [
            "203.0.113.45", "198.51.100.23", "203.0.113.78", "198.51.100.67",
            "185.220.101.182", "185.220.102.8", "94.142.241.111"
        ]
        
        # User ID pools
        self.normal_users = [
            "user001", "user002", "user003", "admin001", "service_account_01",
            "developer_01", "analyst_01", "manager_01"
        ]
        
        self.suspicious_users = [
            "temp_user", "guest_user", "unknown_user", "test_account", "backdoor_user"
        ]
    
    def generate_event(self):
        """
        Generate a single mock security event.
        
        Returns:
            dict: A complete security event with all necessary fields
        """
        # Determine if this will be a normal event or a threat (20% chance of threat)
        is_threat = random.random() < 0.2
        
        if is_threat:
            event_template = random.choice(self.threat_events).copy()
            source_ip = random.choice(self.suspicious_ips)
            user_id = random.choice(self.suspicious_users)
        else:
            event_template = random.choice(self.normal_events).copy()
            source_ip = random.choice(self.normal_ips)
            user_id = random.choice(self.normal_users)
        
        # Generate timestamp (current time with slight random variation)
        timestamp = datetime.now() - timedelta(seconds=random.randint(0, 300))
        
        # Build the complete event
        event = {
            "timestamp": timestamp.isoformat(),
            "event_id": f"evt_{random.randint(100000, 999999)}",
            "event_type": event_template["event_type"],
            "severity": event_template["severity"],
            "description": event_template["description"],
            "source_ip": event_template.get("source_ip") or source_ip,
            "user_id": event_template.get("user_id") or user_id,
            "resource": event_template["resource"],
            "metadata": {
                "region": random.choice(["us-east-1", "us-west-2", "eu-central-1"]),
                "service_version": f"v{random.randint(1, 3)}.{random.randint(0, 9)}",
                "session_id": f"sess_{random.randint(1000, 9999)}"
            }
        }
        
        # Add threat indicators if it's a threat event
        if "threat_indicators" in event_template:
            event["threat_indicators"] = event_template["threat_indicators"]
        
        return event
    
    def generate_event_batch(self, count=10):
        """
        Generate a batch of mock security events.
        
        Args:
            count (int): Number of events to generate
            
        Returns:
            list: List of security events
        """
        return [self.generate_event() for _ in range(count)]
    
    def get_event_statistics(self, events):
        """
        Generate statistics for a list of events.
        
        Args:
            events (list): List of events to analyze
            
        Returns:
            dict: Statistics about the events
        """
        if not events:
            return {"total": 0}
        
        stats = {
            "total": len(events),
            "by_severity": {},
            "by_type": {},
            "threat_events": 0
        }
        
        for event in events:
            # Count by severity
            severity = event.get("severity", "unknown")
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
            
            # Count by type
            event_type = event.get("event_type", "unknown")
            stats["by_type"][event_type] = stats["by_type"].get(event_type, 0) + 1
            
            # Count threats
            if "threat_indicators" in event:
                stats["threat_events"] += 1
        
        return stats
