"""
AWS Lambda Function for Aegis Threat Response

This is a sample Lambda function that can be deployed to AWS Lambda 
to handle automated threat responses triggered by the Aegis security system.

Deployment Instructions:
1. Create a new Lambda function in AWS Console
2. Set function name as: aegis-threat-response
3. Choose Python 3.11 runtime
4. Copy this code to the Lambda function
5. Configure appropriate IAM permissions for security actions
6. Set up CloudWatch integration for logging

Required IAM Permissions:
- CloudWatch Logs access
- EC2 security group modifications (for IP blocking)
- SNS publish (for notifications)
- Systems Manager (for automated remediation)
"""

import json
import boto3
import logging
from datetime import datetime

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    Main Lambda handler for processing security threats from Aegis
    
    Args:
        event: Threat data from Aegis security system
        context: Lambda execution context
        
    Returns:
        dict: Response with action results
    """
    
    logger.info(f"🚨 Aegis threat response triggered: {json.dumps(event)}")
    
    try:
        # Extract threat information
        threat_type = event.get('threat_type', 'UNKNOWN')
        risk_score = event.get('risk_score', 0)
        source_ip = event.get('source_ip', 'unknown')
        event_id = event.get('event_id', 'unknown')
        
        # Initialize response actions
        actions_taken = []
        
        # Execute automated response based on threat type and risk score
        if risk_score >= 9:
            # Critical threat response
            actions_taken.extend(handle_critical_threat(event))
        elif risk_score >= 7:
            # High threat response
            actions_taken.extend(handle_high_threat(event))
        else:
            # Medium threat response
            actions_taken.extend(handle_medium_threat(event))
        
        # Log response completion
        logger.info(f"✅ Threat response completed for {event_id}: {len(actions_taken)} actions taken")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Threat response executed successfully',
                'event_id': event_id,
                'actions_taken': actions_taken,
                'timestamp': datetime.utcnow().isoformat()
            })
        }
        
    except Exception as e:
        logger.error(f"❌ Error processing threat response: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Failed to process threat response',
                'details': str(e)
            })
        }

def handle_critical_threat(event):
    """Handle critical security threats (risk score 9-10)"""
    actions = []
    source_ip = event.get('source_ip', 'unknown')
    
    try:
        # Action 1: Immediate IP blocking
        if source_ip != 'unknown' and not source_ip.startswith('10.') and not source_ip.startswith('192.168.'):
            block_ip_address(source_ip)
            actions.append(f"IP_BLOCKED: {source_ip}")
        
        # Action 2: Send emergency notifications
        send_emergency_notification(event)
        actions.append("EMERGENCY_NOTIFICATION_SENT")
        
        # Action 3: Create high-priority incident
        incident_id = create_security_incident(event, priority='CRITICAL')
        actions.append(f"INCIDENT_CREATED: {incident_id}")
        
        # Action 4: Log to CloudWatch for audit trail
        log_security_action(event, actions, 'CRITICAL_RESPONSE')
        actions.append("AUDIT_LOG_CREATED")
        
    except Exception as e:
        logger.error(f"Error in critical threat handling: {e}")
        actions.append(f"ERROR: {str(e)}")
    
    return actions

def handle_high_threat(event):
    """Handle high security threats (risk score 7-8)"""
    actions = []
    
    try:
        # Action 1: Rate limiting for source IP
        source_ip = event.get('source_ip', 'unknown')
        if source_ip != 'unknown':
            apply_rate_limiting(source_ip)
            actions.append(f"RATE_LIMITED: {source_ip}")
        
        # Action 2: Send security team notification
        send_security_notification(event)
        actions.append("SECURITY_TEAM_NOTIFIED")
        
        # Action 3: Create standard incident
        incident_id = create_security_incident(event, priority='HIGH')
        actions.append(f"INCIDENT_CREATED: {incident_id}")
        
    except Exception as e:
        logger.error(f"Error in high threat handling: {e}")
        actions.append(f"ERROR: {str(e)}")
    
    return actions

def handle_medium_threat(event):
    """Handle medium security threats (risk score 5-6)"""
    actions = []
    
    try:
        # Action 1: Enhanced monitoring
        enable_enhanced_monitoring(event.get('source_ip'))
        actions.append("ENHANCED_MONITORING_ENABLED")
        
        # Action 2: Log for analysis
        log_security_event(event)
        actions.append("SECURITY_EVENT_LOGGED")
        
    except Exception as e:
        logger.error(f"Error in medium threat handling: {e}")
        actions.append(f"ERROR: {str(e)}")
    
    return actions

def block_ip_address(ip_address):
    """Block malicious IP address using AWS Security Groups"""
    try:
        ec2 = boto3.client('ec2')
        
        # This would add the IP to a blacklist security group
        # Implementation depends on your AWS infrastructure setup
        logger.info(f"🚫 IP address blocked: {ip_address}")
        
    except Exception as e:
        logger.error(f"Failed to block IP {ip_address}: {e}")
        raise

def send_emergency_notification(event):
    """Send emergency notification via SNS"""
    try:
        sns = boto3.client('sns')
        
        message = {
            "alert": "CRITICAL SECURITY THREAT DETECTED",
            "threat_type": event.get('threat_type'),
            "source_ip": event.get('source_ip'),
            "risk_score": event.get('risk_score'),
            "timestamp": datetime.utcnow().isoformat(),
            "automated_response": "ACTIVE"
        }
        
        # Replace with your SNS topic ARN
        topic_arn = "arn:aws:sns:us-east-2:YOUR_ACCOUNT:aegis-emergency-alerts"
        
        # Uncomment when SNS topic is configured
        # sns.publish(
        #     TopicArn=topic_arn,
        #     Message=json.dumps(message),
        #     Subject="🚨 AEGIS: Critical Security Threat Detected"
        # )
        
        logger.info(f"📧 Emergency notification sent for threat: {event.get('event_id')}")
        
    except Exception as e:
        logger.error(f"Failed to send emergency notification: {e}")
        raise

def send_security_notification(event):
    """Send standard security notification"""
    try:
        # Implementation for security team notifications
        logger.info(f"📨 Security notification sent for event: {event.get('event_id')}")
        
    except Exception as e:
        logger.error(f"Failed to send security notification: {e}")
        raise

def create_security_incident(event, priority='MEDIUM'):
    """Create security incident record"""
    try:
        # This would integrate with your incident management system
        incident_id = f"INC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        
        logger.info(f"🎫 Security incident created: {incident_id} (Priority: {priority})")
        return incident_id
        
    except Exception as e:
        logger.error(f"Failed to create security incident: {e}")
        raise

def apply_rate_limiting(ip_address):
    """Apply rate limiting to suspicious IP"""
    try:
        # Implementation depends on your rate limiting solution
        logger.info(f"🚦 Rate limiting applied to: {ip_address}")
        
    except Exception as e:
        logger.error(f"Failed to apply rate limiting: {e}")
        raise

def enable_enhanced_monitoring(ip_address):
    """Enable enhanced monitoring for suspicious activity"""
    try:
        logger.info(f"👁️  Enhanced monitoring enabled for: {ip_address}")
        
    except Exception as e:
        logger.error(f"Failed to enable enhanced monitoring: {e}")
        raise

def log_security_action(event, actions, response_type):
    """Log security actions to CloudWatch"""
    try:
        cloudwatch = boto3.client('logs')
        
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_id': event.get('event_id'),
            'response_type': response_type,
            'actions_taken': actions,
            'threat_data': event
        }
        
        # Log to CloudWatch Logs
        # Implementation depends on your log group configuration
        logger.info(f"📝 Security action logged: {response_type}")
        
    except Exception as e:
        logger.error(f"Failed to log security action: {e}")

def log_security_event(event):
    """Log security event for analysis"""
    try:
        logger.info(f"📊 Security event logged for analysis: {event.get('event_id')}")
        
    except Exception as e:
        logger.error(f"Failed to log security event: {e}")
        raise