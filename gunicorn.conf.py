# Gunicorn configuration for production deployment
import os

# Server socket
bind = "0.0.0.0:5000"
backlog = 2048

# Worker processes
workers = 1
worker_class = "sync"
worker_connections = 1000
timeout = 30
keepalive = 2

# Logging
loglevel = "info"
accesslog = "-"
errorlog = "-"
capture_output = True

# Process naming
proc_name = "aegis-dashboard"

# Auto-restart workers
max_requests = 1000
max_requests_jitter = 100

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Performance
preload_app = True