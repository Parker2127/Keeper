#!/usr/bin/env python3
"""
Aegis Cloud Security System - Main Execution Loop
A simplified proof-of-concept automated cloud security monitoring system.
"""

import time
import logging
from event_generator import CloudEventGenerator
from security_monitor import SecurityMonitor
from response_handler import ResponseHandler

def setup_logging():
    """Configure logging for the Aegis system."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logging.getLogger('Aegis')

def main():
    """
    Main execution loop for the Aegis cloud security monitoring system.
    Continuously generates events, monitors for threats, and responds to incidents.
    """
    logger = setup_logging()
    
    # Initialize system components
    event_generator = CloudEventGenerator()
    security_monitor = SecurityMonitor()
    response_handler = ResponseHandler()
    
    # Log AWS integration status
    aws_status = security_monitor.get_aws_health_status()
    if aws_status['cloudwatch_available']:
        logger.info(f"☁️  AWS CloudWatch integration active (Region: {aws_status['aws_region']})")
    else:
        logger.warning("⚠️  AWS CloudWatch integration unavailable")
    
    logger.info("🛡️  Aegis Cloud Security System Starting...")
    logger.info("🔍 Beginning continuous threat monitoring...")
    
    print("\n" + "="*60)
    print("🛡️  AEGIS CLOUD SECURITY SYSTEM")
    print("="*60)
    print("Status: ACTIVE - Monitoring cloud environment...")
    print("Press Ctrl+C to stop monitoring\n")
    
    event_count = 0
    threat_count = 0
    
    try:
        
        while True:
            # Generate a mock security event
            event = event_generator.generate_event()
            event_count += 1
            
            # Process the event through security monitoring
            threat_detected = security_monitor.analyze_event(event)
            
            if threat_detected:
                threat_count += 1
                # Trigger automated response
                response_handler.handle_threat(threat_detected, event)
                
                # Add some delay after threat response
                time.sleep(2)
            
            # Display monitoring status periodically
            if event_count % 10 == 0:
                print(f"📊 Status: {event_count} events processed, {threat_count} threats detected")
            
            # Wait before processing next event (simulate realistic monitoring interval)
            time.sleep(1.5)
            
    except KeyboardInterrupt:
        print(f"\n🛑 Monitoring stopped by user")
        print(f"📈 Final Statistics:")
        print(f"   • Total events processed: {event_count}")
        print(f"   • Total threats detected: {threat_count}")
        if event_count > 0:
            print(f"   • Success rate: {((event_count - threat_count) / event_count * 100):.1f}% normal events")
        logger.info("Aegis system shutdown completed")

if __name__ == "__main__":
    main()
