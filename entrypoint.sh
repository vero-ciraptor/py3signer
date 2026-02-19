#!/bin/sh
# Entrypoint script for py3signer with gunicorn multi-worker support
# Supports both env vars and CLI args (converted to env vars)

# Mark that we're running under gunicorn (detected by config module)
export GUNICORN_CMD_ARGS=""

# Parse CLI arguments and convert to environment variables
# Supports: --port, --host, --log-level, --auth-token, --key-store-path, etc.
while [ $# -gt 0 ]; do
    case "$1" in
        --host)
            export PY3SIGNER_HOST="$2"
            shift 2
            ;;
        --host=*)
            export PY3SIGNER_HOST="${1#*=}"
            shift
            ;;
        -p|--port)
            export PY3SIGNER_PORT="$2"
            shift 2
            ;;
        --port=*)
            export PY3SIGNER_PORT="${1#*=}"
            shift
            ;;
        --log-level)
            export PY3SIGNER_LOG_LEVEL="$2"
            shift 2
            ;;
        --log-level=*)
            export PY3SIGNER_LOG_LEVEL="${1#*=}"
            shift
            ;;
        --auth-token)
            export PY3SIGNER_AUTH_TOKEN="$2"
            shift 2
            ;;
        --auth-token=*)
            export PY3SIGNER_AUTH_TOKEN="${1#*=}"
            shift
            ;;
        --key-store-path)
            export PY3SIGNER_KEY_STORE_PATH="$2"
            shift 2
            ;;
        --key-store-path=*)
            export PY3SIGNER_KEY_STORE_PATH="${1#*=}"
            shift
            ;;
        --keystores-path)
            export PY3SIGNER_KEYSTORES_PATH="$2"
            shift 2
            ;;
        --keystores-path=*)
            export PY3SIGNER_KEYSTORES_PATH="${1#*=}"
            shift
            ;;
        --keystores-passwords-path)
            export PY3SIGNER_KEYSTORES_PASSWORDS_PATH="$2"
            shift 2
            ;;
        --keystores-passwords-path=*)
            export PY3SIGNER_KEYSTORES_PASSWORDS_PATH="${1#*=}"
            shift
            ;;
        --tls-cert)
            export PY3SIGNER_TLS_CERT="$2"
            shift 2
            ;;
        --tls-cert=*)
            export PY3SIGNER_TLS_CERT="${1#*=}"
            shift
            ;;
        --tls-key)
            export PY3SIGNER_TLS_KEY="$2"
            shift 2
            ;;
        --tls-key=*)
            export PY3SIGNER_TLS_KEY="${1#*=}"
            shift
            ;;
        --metrics-port)
            export PY3SIGNER_METRICS_PORT="$2"
            shift 2
            ;;
        --metrics-port=*)
            export PY3SIGNER_METRICS_PORT="${1#*=}"
            shift
            ;;
        --metrics-host)
            export PY3SIGNER_METRICS_HOST="$2"
            shift 2
            ;;
        --metrics-host=*)
            export PY3SIGNER_METRICS_HOST="${1#*=}"
            shift
            ;;
        *)
            # Unknown argument, skip
            shift
            ;;
    esac
done

# Default configuration via environment variables (if not set by CLI)
export PY3SIGNER_HOST="${PY3SIGNER_HOST:-0.0.0.0}"
export PY3SIGNER_PORT="${PY3SIGNER_PORT:-8080}"
export PY3SIGNER_LOG_LEVEL="${PY3SIGNER_LOG_LEVEL:-INFO}"

# Set prometheus multiproc directory for multi-worker metrics
export PROMETHEUS_MULTIPROC_DIR="${PROMETHEUS_MULTIPROC_DIR:-/tmp/prometheus_multiproc}"

# Build bind address for gunicorn from host:port
export PY3SIGNER_BIND="${PY3SIGNER_HOST}:${PY3SIGNER_PORT}"

# Run gunicorn with aiohttp worker
exec uv run gunicorn \
    -k aiohttp.GunicornWebWorker \
    -c gunicorn.conf.py \
    "py3signer.wsgi:create_app()"
