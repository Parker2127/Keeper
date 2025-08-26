#!/usr/bin/env python3
"""
Security Monitor Module for Aegis Cloud Security System
Analyzes events for potential security threats based on predefined rules.
"""

import logging
from datetime import datetime
import json
from aws_integration import AWSIntegration

class SecurityMonitor:
    """
    Core security monitoring engine that analyzes events for potential threats.
    Implements rule-based threat detection with configurable security policies.
    """
    
    def __init__(self):
        """Initialize the security monitor with threat detection rules."""
        self.logger = logging.getLogger('Aegis.SecurityMonitor')
        
        # Initialize AWS integration
        self.aws_integration = AWSIntegration()
        
        # Failed login attempt tracking
        self.failed_login_attempts = {}
        self.max_failed_attempts = 3
        
        # Security rules configuration
        self.security_rules = {
            "critical_keywords": [
                "unauthorized access", "privilege escalation", "data exfiltration",
                "malware", "code injection", "backdoor", "rootkit"
            ],
            "suspicious_keywords": [
                "brute_force", "suspicious", "anomalous", "unrecognized",
                "multiple failed", "unusual activity"
            ],
            "blocked_ips": [
                "203.0.113.45", "185.220.101.182", "94.142.241.111"
            ],
            "restricted_resources": [
                "admin_panel", "database_service", "security_config", "backup_service"
            ],
            "high_risk_users": [
                "temp_user", "guest_user", "unknown_user", "backdoor_user"
            ]
        }
        
        # Threat severity levels
        self.severity_levels = {
            "info": 1,
            "warning": 2, 
            "high": 3,
            "critical": 4
        }
    
    def analyze_event(self, event):
        """
        Analyze a security event for potential threats.
        
        Args:
            event (dict): Security event to analyze
            
        Returns:
            dict or None: Threat information if detected, None otherwise
        """
        if not event:
            return None
        
        # Display the event being analyzed
        self._log_event_analysis(event)
        
        # Run multiple threat detection checks
        threat_info = None
        
        # Check 1: Keyword-based detection
        keyword_threat = self._check_threat_keywords(event)
        if keyword_threat:
            threat_info = keyword_threat
        
        # Check 2: IP-based detection
        ip_threat = self._check_suspicious_ip(event)
        if ip_threat and (not threat_info or ip_threat["risk_score"] > threat_info["risk_score"]):
            threat_info = ip_threat
        
        # Check 3: User-based detection
        user_threat = self._check_suspicious_user(event)
        if user_threat and (not threat_info or user_threat["risk_score"] > threat_info["risk_score"]):
            threat_info = user_threat
        
        # Check 4: Resource access detection
        resource_threat = self._check_restricted_resource(event)
        if resource_threat and (not threat_info or resource_threat["risk_score"] > threat_info["risk_score"]):
            threat_info = resource_threat
        
        # Check 5: Failed login pattern detection
        login_threat = self._check_failed_login_pattern(event)
        if login_threat and (not threat_info or login_threat["risk_score"] > threat_info["risk_score"]):
            threat_info = login_threat
        
        # Check 6: Severity-based detection
        severity_threat = self._check_event_severity(event)
        if severity_threat and (not threat_info or severity_threat["risk_score"] > threat_info["risk_score"]):
            threat_info = severity_threat
        
        # Check 7: Threat indicators
        indicator_threat = self._check_threat_indicators(event)
        if indicator_threat and (not threat_info or indicator_threat["risk_score"] > threat_info["risk_score"]):
            threat_info = indicator_threat
        
        if threat_info:
            self._log_threat_detection(threat_info, event)
            # Send threat data to AWS CloudWatch
            self._send_to_aws(event, threat_info)
        else:
            # Send normal event metrics to CloudWatch
            self._send_event_metrics(event)
        
        return threat_info
    
    def _log_event_analysis(self, event):
        """Log the event being analyzed."""
        print(f"🔍 Analyzing: {event['event_type']} from {event['user_id']} @ {event['source_ip']}")
    
    def _log_threat_detection(self, threat_info, event):
        """Log threat detection with detailed information."""
        risk_level = "🔴 CRITICAL" if threat_info["risk_score"] >= 8 else "🟡 HIGH" if threat_info["risk_score"] >= 6 else "🟠 MEDIUM"
        
        print(f"🚨 THREAT DETECTED: {threat_info['threat_type']}")
        print(f"   Risk Level: {risk_level} (Score: {threat_info['risk_score']}/10)")
        print(f"   Description: {threat_info['description']}")
        print(f"   Event ID: {event['event_id']}")
        print(f"   Source: {event['user_id']} from {event['source_ip']}")
        print(f"   Resource: {event['resource']}")
    
    def _check_threat_keywords(self, event):
        """Check event description for threat-related keywords."""
        description = event.get("description", "").lower()
        
        # Check for critical keywords
        for keyword in self.security_rules["critical_keywords"]:
            if keyword in description:
                return {
                    "threat_type": "KEYWORD_THREAT",
                    "description": f"Critical security keyword detected: '{keyword}'",
                    "risk_score": 9,
                    "detection_method": "keyword_analysis"
                }
        
        # Check for suspicious keywords
        for keyword in self.security_rules["suspicious_keywords"]:
            if keyword in description:
                return {
                    "threat_type": "SUSPICIOUS_ACTIVITY",
                    "description": f"Suspicious activity keyword detected: '{keyword}'",
                    "risk_score": 6,
                    "detection_method": "keyword_analysis"
                }
        
        return None
    
    def _check_suspicious_ip(self, event):
        """Check if the source IP is on the blocked list."""
        source_ip = event.get("source_ip")
        
        if source_ip in self.security_rules["blocked_ips"]:
            return {
                "threat_type": "MALICIOUS_IP",
                "description": f"Request from known malicious IP: {source_ip}",
                "risk_score": 8,
                "detection_method": "ip_reputation"
            }
        
        return None
    
    def _check_suspicious_user(self, event):
        """Check if the user is flagged as high risk."""
        user_id = event.get("user_id")
        
        if user_id in self.security_rules["high_risk_users"]:
            return {
                "threat_type": "HIGH_RISK_USER",
                "description": f"Activity from high-risk user account: {user_id}",
                "risk_score": 7,
                "detection_method": "user_profile_analysis"
            }
        
        return None
    
    def _check_restricted_resource(self, event):
        """Check if access attempt is to a restricted resource."""
        resource = event.get("resource")
        
        if resource in self.security_rules["restricted_resources"]:
            return {
                "threat_type": "RESTRICTED_RESOURCE_ACCESS",
                "description": f"Access attempt to restricted resource: {resource}",
                "risk_score": 7,
                "detection_method": "resource_access_control"
            }
        
        return None
    
    def _check_failed_login_pattern(self, event):
        """Track and detect failed login patterns."""
        if event.get("event_type") != "failed_login":
            return None
        
        source_ip = event.get("source_ip")
        user_id = event.get("user_id")
        key = f"{user_id}@{source_ip}"
        
        # Track failed attempts
        if key not in self.failed_login_attempts:
            self.failed_login_attempts[key] = 0
        
        self.failed_login_attempts[key] += 1
        
        if self.failed_login_attempts[key] >= self.max_failed_attempts:
            return {
                "threat_type": "BRUTE_FORCE_ATTACK",
                "description": f"Multiple failed login attempts detected ({self.failed_login_attempts[key]} attempts)",
                "risk_score": 8,
                "detection_method": "behavioral_analysis"
            }
        
        return None
    
    def _check_event_severity(self, event):
        """Check event severity level for automatic threat classification."""
        severity = event.get("severity", "info")
        severity_score = self.severity_levels.get(severity, 1)
        
        if severity_score >= 4:  # Critical
            return {
                "threat_type": "CRITICAL_SECURITY_EVENT",
                "description": f"Critical severity event detected: {event.get('description')}",
                "risk_score": 9,
                "detection_method": "severity_analysis"
            }
        elif severity_score >= 3:  # High
            return {
                "threat_type": "HIGH_RISK_EVENT",
                "description": f"High severity event detected: {event.get('description')}",
                "risk_score": 7,
                "detection_method": "severity_analysis"
            }
        
        return None
    
    def _check_threat_indicators(self, event):
        """Check for explicit threat indicators in the event."""
        threat_indicators = event.get("threat_indicators", [])
        
        if not threat_indicators:
            return None
        
        # Assess risk based on threat indicators
        risk_score = min(10, 5 + len(threat_indicators) * 2)
        
        return {
            "threat_type": "THREAT_INDICATORS_DETECTED",
            "description": f"Multiple threat indicators present: {', '.join(threat_indicators)}",
            "risk_score": risk_score,
            "detection_method": "threat_intelligence"
        }
    
    def get_monitoring_statistics(self):
        """Get current monitoring statistics."""
        return {
            "failed_login_tracking": len(self.failed_login_attempts),
            "active_rules": len(self.security_rules),
            "detection_methods": [
                "keyword_analysis", "ip_reputation", "user_profile_analysis",
                "resource_access_control", "behavioral_analysis", 
                "severity_analysis", "threat_intelligence"
            ]
        }
    
    def reset_monitoring_state(self):
        """Reset monitoring state (useful for testing or maintenance)."""
        self.failed_login_attempts.clear()
        self.logger.info("Monitoring state reset completed")
    
    def _send_to_aws(self, event, threat_info):
        """Send threat information to AWS CloudWatch and trigger Lambda functions."""
        try:
            # Prepare threat data for AWS
            threat_data = {
                'event_id': event.get('event_id'),
                'threat_type': threat_info.get('threat_type'),
                'risk_score': threat_info.get('risk_score'),
                'source_ip': event.get('source_ip'),
                'user_id': event.get('user_id'),
                'resource': event.get('resource'),
                'description': threat_info.get('description'),
                'event_type': event.get('event_type'),
                'severity': 'critical' if threat_info.get('risk_score', 0) >= 8 else 'high'
            }
            
            # Send threat alert to CloudWatch
            self.aws_integration.send_threat_alert(threat_data)
            
            # Send security metrics
            self.aws_integration.send_security_metric(threat_data)
            
            # Trigger Lambda function for high-risk threats
            if threat_info.get('risk_score', 0) >= 8:
                self.aws_integration.trigger_lambda_response(threat_data)
            
            # Send detailed logs to CloudWatch Logs
            log_group = '/aegis/security-events'
            stream_name = f"threats-{datetime.now().strftime('%Y-%m-%d')}"
            
            # Create log stream if needed
            self.aws_integration.create_log_stream(log_group, stream_name)
            
            # Send comprehensive log data
            log_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'event': event,
                'threat_info': threat_info,
                'aws_integration': True
            }
            
            self.aws_integration.send_security_log(log_group, stream_name, log_data)
            
        except Exception as e:
            self.logger.error(f"❌ Failed to send threat data to AWS: {e}")
    
    def _send_event_metrics(self, event):
        """Send normal event metrics to AWS CloudWatch."""
        try:
            # Send basic event metrics for monitoring
            event_data = {
                'event_type': event.get('event_type'),
                'severity': event.get('severity', 'info'),
                'source_ip': event.get('source_ip'),
                'risk_score': 1  # Normal events have low risk score
            }
            
            self.aws_integration.send_security_metric(event_data)
            
        except Exception as e:
            self.logger.error(f"❌ Failed to send event metrics to AWS: {e}")
    
    def get_aws_health_status(self):
        """Get AWS integration health status."""
        return self.aws_integration.get_health_status()
