"""
Gunicorn Configuration for Production Deployment

This configuration file provides production-ready settings for running
the ESP API Gateway with Gunicorn WSGI server.

Usage:
    gunicorn --config gunicorn.conf.py run_api:app

Environment Variables:
    WORKERS: Number of worker processes (default: CPU cores * 2 + 1)
    WORKER_CLASS: Worker class type (default: gevent for WebSocket support)
    API_PORT: Port to bind (default: 5000)
    LOG_LEVEL: Logging level (default: info)
"""

import multiprocessing
import os

# Server socket
bind = f"0.0.0.0:{os.getenv('API_PORT', '5000')}"
backlog = 2048

# Worker processes
workers = int(os.getenv('WORKERS', multiprocessing.cpu_count() * 2 + 1))
worker_class = os.getenv('WORKER_CLASS', 'gevent')  # For WebSocket/async support
worker_connections = 1000
max_requests = 1000  # Restart workers after N requests (prevents memory leaks)
max_requests_jitter = 50  # Randomize restart to avoid thundering herd
threads = 1

# Timeouts
timeout = 120  # 2 minutes for long-running scan operations
graceful_timeout = 30
keepalive = 5

# Logging
accesslog = '-'  # Log to stdout
errorlog = '-'   # Log to stderr
loglevel = os.getenv('LOG_LEVEL', 'info').lower()
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Process naming
proc_name = 'esp-api-gateway'

# Server mechanics
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# SSL/TLS (if terminating SSL at application level - not recommended, use nginx)
keyfile = os.getenv('SSL_KEY', None)
certfile = os.getenv('SSL_CERT', None)

# Server hooks
def on_starting(server):
    """Called just before the master process is initialized."""
    server.log.info("🚀 Starting ESP API Gateway with Gunicorn")
    server.log.info(f"Workers: {workers} ({worker_class})")
    server.log.info(f"Binding to: {bind}")

def on_reload(server):
    """Called to recycle workers during a reload."""
    server.log.info("♻️  Reloading workers...")

def when_ready(server):
    """Called just after the server is started."""
    server.log.info("✅ ESP API Gateway is ready to accept connections")

def on_exit(server):
    """Called just before exiting."""
    server.log.info("👋 ESP API Gateway shutting down")

def worker_int(worker):
    """Called when a worker receives SIGINT or SIGQUIT."""
    worker.log.info(f"Worker {worker.pid} received interrupt signal")

def worker_abort(worker):
    """Called when a worker times out."""
    worker.log.warning(f"⚠️  Worker {worker.pid} timed out and will be restarted")

# Pre-load application (improves startup time and memory sharing)
preload_app = False  # Set to True if your app is fork-safe

# Environment variables
raw_env = []
if os.getenv('FLASK_ENV'):
    raw_env.append(f"FLASK_ENV={os.getenv('FLASK_ENV')}")
