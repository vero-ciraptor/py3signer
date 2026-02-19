"""Gunicorn configuration for py3signer."""

import multiprocessing
import os
import shutil
import tempfile

# Multi-process metrics directory
PROMETHEUS_MULTIPROC_DIR = os.getenv(
    "PROMETHEUS_MULTIPROC_DIR",
    tempfile.mkdtemp(prefix="prometheus_multiproc_")
)
os.environ["PROMETHEUS_MULTIPROC_DIR"] = PROMETHEUS_MULTIPROC_DIR

# Server socket
bind = os.getenv("PY3SIGNER_BIND", "0.0.0.0:8080")

# Worker processes - use 2-4 workers per CPU core for I/O bound workloads
# For crypto signing (CPU bound), 1-2 workers per core is better
workers = int(os.getenv("PY3SIGNER_WORKERS", multiprocessing.cpu_count()))

# Worker class for aiohttp
worker_class = "aiohttp.GunicornWebWorker"

# Worker connections (for async workers)
worker_connections = int(os.getenv("PY3SIGNER_WORKER_CONNECTIONS", "1000"))

# Timeout for graceful worker restart (seconds)
timeout = int(os.getenv("PY3SIGNER_TIMEOUT", "30"))

# Keep-alive timeout (seconds)
keepalive = int(os.getenv("PY3SIGNER_KEEPALIVE", "5"))

# Logging
loglevel = os.getenv("PY3SIGNER_LOG_LEVEL", "info")
accesslog = os.getenv("PY3SIGNER_ACCESS_LOG", "-")  # "-" means stdout
errorlog = os.getenv("PY3SIGNER_ERROR_LOG", "-")     # "-" means stderr

# Process naming
proc_name = "py3signer"

# Server mechanics
daemon = False
pidfile = None

# SSL (optional)
keyfile = os.getenv("PY3SIGNER_TLS_KEY")
certfile = os.getenv("PY3SIGNER_TLS_CERT")

# Worker lifecycle - reload workers after N requests to prevent memory leaks
# Set to 0 to disable
max_requests = int(os.getenv("PY3SIGNER_MAX_REQUESTS", "0"))
max_requests_jitter = int(os.getenv("PY3SIGNER_MAX_REQUESTS_JITTER", "0"))

# Graceful timeout for worker shutdown
graceful_timeout = int(os.getenv("PY3SIGNER_GRACEFUL_TIMEOUT", "30"))

# Preload app for faster fork-based worker spawning
preload_app = os.getenv("PY3SIGNER_PRELOAD_APP", "false").lower() == "true"

# Statsd metrics (optional)
# statsd_host = os.getenv("PY3SIGNER_STATSD_HOST")
# statsd_prefix = os.getenv("PY3SIGNER_STATSD_PREFIX", "py3signer")


def on_starting(server):
    """Called just before the master process is initialized."""
    pass


def on_reload(server):
    """Called when receiving SIGHUP."""
    pass


def when_ready(server):
    """Called just after the server is started."""
    pass


def worker_int(worker):
    """Called when a worker receives SIGINT or SIGQUIT."""
    pass


def worker_abort(worker):
    """Called when a worker receives SIGABRT."""
    pass


def on_exit(server):
    """Called just before exiting gunicorn."""
    # Clean up prometheus multiproc directory
    prom_dir = os.environ.get("PROMETHEUS_MULTIPROC_DIR")
    if prom_dir and os.path.exists(prom_dir):
        try:
            shutil.rmtree(prom_dir)
        except Exception:
            pass  # Best effort cleanup
