#!/usr/bin/env python3
"""
Aegis Security Dashboard Web Server
Flask application that serves the security dashboard and provides API endpoints.
"""

import os
import json
import threading
import time
from flask import Flask, jsonify, send_from_directory, send_file, request
from flask_cors import CORS
from datetime import datetime

# Import existing security monitoring components
from security_monitor import SecurityMonitor
from event_generator import CloudEventGenerator
from response_handler import ResponseHandler

app = Flask(__name__, static_folder='aegis-dashboard/dist', static_url_path='')
CORS(app)

# Global variables for monitoring
security_monitor = None
event_generator = None
response_handler = None
monitoring_thread = None
monitoring_active = False

# Stats tracking
stats = {
    'events_processed': 0,
    'threats_detected': 0,
    'responses_executed': 0,
    'system_health': 'Active',
    'last_update': datetime.now().isoformat()
}

def background_monitoring():
    """Background thread for security monitoring"""
    global stats, monitoring_active
    
    while monitoring_active:
        try:
            # Generate and analyze events
            event = event_generator.generate_event()
            stats['events_processed'] += 1
            
            threat_detected = security_monitor.analyze_event(event)
            
            if threat_detected:
                stats['threats_detected'] += 1
                response_handler.handle_threat(threat_detected, event)
                stats['responses_executed'] += 1
            
            stats['last_update'] = datetime.now().isoformat()
            
            # Wait before next event
            time.sleep(2)
            
        except Exception as e:
            print(f"Monitoring error: {e}")
            time.sleep(5)

@app.route('/')
def index():
    """Serve the main dashboard"""
    try:
        return send_file('aegis-dashboard/dist/index.html')
    except:
        # Fallback if built files don't exist
        return jsonify({
            'message': 'Aegis Security Dashboard',
            'status': 'active',
            'build_required': True
        })

@app.route('/health')
def health_check():
    """Health check endpoint for deployment"""
    return jsonify({
        'status': 'healthy',
        'service': 'aegis-security-dashboard',
        'timestamp': datetime.now().isoformat(),
        'monitoring': monitoring_active
    }), 200

@app.route('/api/metrics')
def get_metrics():
    """API endpoint for real-time security metrics"""
    return jsonify(stats)

@app.route('/api/status')
def get_status():
    """API endpoint for system status"""
    aws_status = security_monitor.get_aws_health_status() if security_monitor else {}
    
    return jsonify({
        'system_health': stats['system_health'],
        'monitoring_active': monitoring_active,
        'events_processed': stats['events_processed'],
        'threats_detected': stats['threats_detected'],
        'aws_integration': aws_status.get('cloudwatch_available', False),
        'aws_region': aws_status.get('aws_region', 'N/A'),
        'last_update': stats['last_update']
    })

@app.route('/api/events')
def get_recent_events():
    """API endpoint for recent security events (mock data for demo)"""
    recent_events = [
        {
            'id': f'evt_{i}',
            'type': 'user_login' if i % 3 == 0 else 'api_call' if i % 3 == 1 else 'file_access',
            'severity': 'low' if i % 4 != 0 else 'high',
            'timestamp': datetime.now().isoformat(),
            'source': f'user{i%3+1}@company.com',
            'ip_address': f'192.168.1.{20+i%10}'
        }
        for i in range(10)
    ]
    return jsonify(recent_events)

@app.route('/api/monitoring/toggle', methods=['POST'])
def toggle_monitoring():
    """Toggle security monitoring on/off"""
    global monitoring_active
    monitoring_active = not monitoring_active
    
    return jsonify({
        'status': 'success',
        'monitoring_active': monitoring_active,
        'message': f'Monitoring {"started" if monitoring_active else "stopped"}'
    })

@app.route('/api/threats/respond', methods=['POST'])
def manual_threat_response():
    """Manual threat response trigger"""
    data = request.get_json()
    threat_id = data.get('threat_id')
    action = data.get('action', 'quarantine')
    
    # Simulate threat response
    response_actions = {
        'quarantine': 'System quarantined successfully',
        'block_ip': 'IP address blocked in firewall',
        'reset_credentials': 'User credentials reset',
        'isolate_network': 'Network segment isolated'
    }
    
    stats['responses_executed'] += 1
    
    return jsonify({
        'status': 'success',
        'threat_id': threat_id,
        'action_taken': action,
        'message': response_actions.get(action, 'Action executed'),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/settings/alert-threshold', methods=['POST'])
def set_alert_threshold():
    """Set custom alert threshold"""
    data = request.get_json()
    threshold = data.get('threshold', 7)
    
    # Store threshold (in a real app, this would be in a database)
    app.config['ALERT_THRESHOLD'] = threshold
    
    return jsonify({
        'status': 'success',
        'threshold': threshold,
        'message': f'Alert threshold set to {threshold}/10'
    })

@app.route('/api/investigation/details/<event_id>')
def get_event_details(event_id):
    """Get detailed information about a specific event"""
    # Mock detailed investigation data
    details = {
        'event_id': event_id,
        'full_log': f'Detailed logs for event {event_id}...',
        'network_trace': {
            'source_location': 'External',
            'protocol': 'HTTPS',
            'payload_size': '2.3KB',
            'duration': '245ms'
        },
        'user_context': {
            'recent_activity': ['login', 'file_access', 'api_call'],
            'risk_score': 8.5,
            'location': 'Unknown'
        },
        'recommendations': [
            'Monitor user activity closely',
            'Verify user identity',
            'Check for additional suspicious behavior'
        ]
    }
    
    return jsonify(details)

@app.route('/<path:path>')
def serve_static_files(path):
    """Serve static files from the React build"""
    try:
        return send_from_directory('aegis-dashboard/dist', path)
    except:
        # Fallback to index.html for client-side routing
        try:
            return send_file('aegis-dashboard/dist/index.html')
        except:
            return jsonify({'error': 'Static files not found', 'build_required': True}), 404

def initialize_monitoring():
    """Initialize security monitoring components"""
    global security_monitor, event_generator, response_handler, monitoring_thread, monitoring_active
    
    try:
        # Initialize components
        security_monitor = SecurityMonitor()
        event_generator = CloudEventGenerator()
        response_handler = ResponseHandler()
        
        # Start background monitoring (initially stopped for user control)
        monitoring_active = False
        monitoring_thread = threading.Thread(target=background_monitoring, daemon=True)
        monitoring_thread.start()
        
        print("🛡️  Security monitoring initialized successfully")
        
    except Exception as e:
        print(f"⚠️  Warning: Could not initialize security monitoring: {e}")
        print("🌐 Web server will run in dashboard-only mode")

if __name__ == '__main__':
    print("🌐 Starting Aegis Security Dashboard Web Server...")
    
    # Initialize monitoring (optional, web server works without it)
    initialize_monitoring()
    
    # Get port from environment or default to 5000
    port = int(os.environ.get('PORT', 5000))
    
    print(f"🚀 Server starting on port {port}")
    print(f"📊 Dashboard: http://localhost:{port}")
    print(f"❤️  Health check: http://localhost:{port}/health")
    
    app.run(host='0.0.0.0', port=port, debug=False)