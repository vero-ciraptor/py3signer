#!/bin/sh
# Entrypoint script for py3signer with gunicorn multi-worker support

# Mark that we're running under gunicorn (detected by config module)
export GUNICORN_CMD_ARGS=""

# Default configuration via environment variables
export PY3SIGNER_HOST="${PY3SIGNER_HOST:-0.0.0.0}"
export PY3SIGNER_PORT="${PY3SIGNER_PORT:-8080}"
export PY3SIGNER_LOG_LEVEL="${PY3SIGNER_LOG_LEVEL:-INFO}"

# Set prometheus multiproc directory for multi-worker metrics
export PROMETHEUS_MULTIPROC_DIR="${PROMETHEUS_MULTIPROC_DIR:-/tmp/prometheus_multiproc}"

# Run gunicorn with aiohttp worker
exec uv run gunicorn \
    -k aiohttp.GunicornWebWorker \
    -c gunicorn.conf.py \
    "py3signer.wsgi:create_app()"
