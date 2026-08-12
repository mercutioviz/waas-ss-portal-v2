"""Gunicorn production configuration."""

# Server socket
bind = 'unix:/home/admin/waas-ss-portal-v2/waas-portal-v2.sock'

# Worker processes
# Single worker required for Flask-SocketIO without a message queue (Redis).
# Gevent handles concurrency via greenlets, so one worker is sufficient.
worker_class = 'geventwebsocket.gunicorn.workers.GeventWebSocketWorker'
workers = 1

preload_app = True

# Timeouts
timeout = 120
graceful_timeout = 30
keepalive = 5

# Logging
accesslog = 'logs/gunicorn-access.log'
errorlog = 'logs/gunicorn-error.log'
loglevel = 'info'

# Process naming
proc_name = 'waas-portal-v2'

# Security
limit_request_line = 8190
limit_request_fields = 100
