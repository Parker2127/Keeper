"""
AWS CloudWatch and Lambda Integration Module for Aegis Security System

This module provides integration with AWS services for enhanced cloud monitoring
and automated response capabilities.
"""

import boto3
import json
import logging
import time
from datetime import datetime
from typing import Dict, Any, Optional

class AWSIntegration:
    """Handles AWS CloudWatch metrics and Lambda function invocations"""
    
    def __init__(self):
        """Initialize AWS clients"""
        self.logger = logging.getLogger('Aegis.AWS')
        
        try:
            # Initialize AWS clients
            self.cloudwatch = boto3.client('cloudwatch')
            self.lambda_client = boto3.client('lambda')
            self.logs_client = boto3.client('logs')
            
            # Test AWS connectivity
            self._test_aws_connection()
            self.logger.info("✅ AWS integration initialized successfully")
            
        except Exception as e:
            self.logger.error(f"❌ AWS initialization failed: {e}")
            self.cloudwatch = None
            self.lambda_client = None
            self.logs_client = None
    
    def _test_aws_connection(self):
        """Test AWS connectivity and permissions"""
        try:
            # Simple test call to verify credentials
            self.cloudwatch.list_metrics(MaxRecords=1)
            self.logger.info("🔗 AWS CloudWatch connection verified")
        except Exception as e:
            self.logger.warning(f"⚠️  CloudWatch test failed: {e}")
    
    def send_security_metric(self, event_data: Dict[str, Any]) -> bool:
        """Send security event metrics to CloudWatch"""
        if not self.cloudwatch:
            return False
        
        try:
            # Extract key metrics from event
            event_type = event_data.get('event_type', 'unknown')
            severity = event_data.get('severity', 'info')
            source_ip = event_data.get('source_ip', 'unknown')
            risk_score = event_data.get('risk_score', 0)
            
            # Create CloudWatch metrics
            metrics = [
                {
                    'MetricName': 'SecurityEvents',
                    'Dimensions': [
                        {'Name': 'EventType', 'Value': event_type},
                        {'Name': 'Severity', 'Value': severity}
                    ],
                    'Value': 1,
                    'Unit': 'Count',
                    'Timestamp': datetime.utcnow()
                },
                {
                    'MetricName': 'ThreatRiskScore',
                    'Dimensions': [
                        {'Name': 'SourceIP', 'Value': source_ip},
                        {'Name': 'EventType', 'Value': event_type}
                    ],
                    'Value': risk_score,
                    'Unit': 'None',
                    'Timestamp': datetime.utcnow()
                }
            ]
            
            # Send metrics to CloudWatch
            response = self.cloudwatch.put_metric_data(
                Namespace='Aegis/Security',
                MetricData=metrics
            )
            
            self.logger.info(f"📊 Metrics sent to CloudWatch for {event_type} event")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Failed to send CloudWatch metrics: {e}")
            return False
    
    def send_threat_alert(self, threat_data: Dict[str, Any]) -> bool:
        """Send high-priority threat alerts to CloudWatch"""
        if not self.cloudwatch:
            return False
        
        try:
            # Create alarm-triggering metric for critical threats
            if threat_data.get('risk_score', 0) >= 7:
                self.cloudwatch.put_metric_data(
                    Namespace='Aegis/Alerts',
                    MetricData=[
                        {
                            'MetricName': 'CriticalThreats',
                            'Dimensions': [
                                {'Name': 'ThreatType', 'Value': threat_data.get('threat_type', 'unknown')},
                                {'Name': 'SourceIP', 'Value': threat_data.get('source_ip', 'unknown')}
                            ],
                            'Value': 1,
                            'Unit': 'Count',
                            'Timestamp': datetime.utcnow()
                        }
                    ]
                )
                
                self.logger.info(f"🚨 Critical threat alert sent to CloudWatch: {threat_data.get('threat_type')}")
                return True
                
        except Exception as e:
            self.logger.error(f"❌ Failed to send threat alert: {e}")
            return False
    
    def trigger_lambda_response(self, threat_data: Dict[str, Any]) -> bool:
        """Trigger AWS Lambda function for automated threat response"""
        if not self.lambda_client:
            return False
        
        # Lambda function name for threat response (would need to be created in AWS)
        function_name = 'aegis-threat-response'
        
        try:
            # Prepare payload for Lambda function
            payload = {
                'threat_type': threat_data.get('threat_type'),
                'risk_score': threat_data.get('risk_score'),
                'source_ip': threat_data.get('source_ip'),
                'event_id': threat_data.get('event_id'),
                'timestamp': datetime.utcnow().isoformat(),
                'resource': threat_data.get('resource'),
                'description': threat_data.get('description')
            }
            
            # Invoke Lambda function asynchronously for high-risk threats
            if threat_data.get('risk_score', 0) >= 8:
                response = self.lambda_client.invoke(
                    FunctionName=function_name,
                    InvocationType='Event',  # Asynchronous invocation
                    Payload=json.dumps(payload)
                )
                
                self.logger.info(f"🚀 Lambda function triggered for threat: {threat_data.get('event_id')}")
                return True
            
        except self.lambda_client.exceptions.ResourceNotFoundException:
            self.logger.warning(f"⚠️  Lambda function '{function_name}' not found - would need to be created in AWS")
            return False
        except Exception as e:
            self.logger.error(f"❌ Failed to trigger Lambda function: {e}")
            return False
    
    def create_log_stream(self, log_group: str, stream_name: str) -> bool:
        """Create CloudWatch log stream for security events"""
        if not self.logs_client:
            return False
        
        try:
            # Create log group if it doesn't exist
            try:
                self.logs_client.create_log_group(logGroupName=log_group)
            except self.logs_client.exceptions.ResourceAlreadyExistsException:
                pass  # Log group already exists
            
            # Create log stream
            try:
                self.logs_client.create_log_stream(
                    logGroupName=log_group,
                    logStreamName=stream_name
                )
                self.logger.info(f"📝 Created CloudWatch log stream: {stream_name}")
                return True
            except self.logs_client.exceptions.ResourceAlreadyExistsException:
                return True  # Stream already exists
                
        except Exception as e:
            self.logger.error(f"❌ Failed to create log stream: {e}")
            return False
    
    def send_security_log(self, log_group: str, stream_name: str, log_data: Dict[str, Any]) -> bool:
        """Send detailed security logs to CloudWatch Logs"""
        if not self.logs_client:
            return False
        
        try:
            # Prepare log event
            log_event = {
                'timestamp': int(time.time() * 1000),
                'message': json.dumps(log_data, default=str)
            }
            
            # Send log to CloudWatch
            self.logs_client.put_log_events(
                logGroupName=log_group,
                logStreamName=stream_name,
                logEvents=[log_event]
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Failed to send security log: {e}")
            return False
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get AWS integration health status"""
        return {
            'cloudwatch_available': self.cloudwatch is not None,
            'lambda_available': self.lambda_client is not None,
            'logs_available': self.logs_client is not None,
            'aws_region': boto3.Session().region_name if self.cloudwatch else 'unknown'
        }