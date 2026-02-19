# Multi-Worker Configuration

py3signer now supports running with multiple workers using **gunicorn** with the aiohttp worker class.

## Quick Start

```bash
# Run with default settings (workers = CPU count)
docker run -p 8080:8080 py3signer:devnet

# Run with specific worker count
docker run -p 8080:8080 -e PY3SIGNER_WORKERS=4 py3signer:devnet

# Run with custom bind address
docker run -p 8080:8080 -e PY3SIGNER_BIND=0.0.0.0:8080 py3signer:devnet
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PY3SIGNER_WORKERS` | `CPU_COUNT` | Number of worker processes |
| `PY3SIGNER_BIND` | `0.0.0.0:8080` | Bind address and port |
| `PY3SIGNER_WORKER_CONNECTIONS` | `1000` | Max connections per worker |
| `PY3SIGNER_TIMEOUT` | `30` | Worker timeout (seconds) |
| `PY3SIGNER_KEEPALIVE` | `5` | Keep-alive timeout (seconds) |
| `PY3SIGNER_LOG_LEVEL` | `info` | Log level (debug/info/warning/error) |
| `PY3SIGNER_MAX_REQUESTS` | `0` | Max requests before worker restart (0 = disabled) |
| `PY3SIGNER_GRACEFUL_TIMEOUT` | `30` | Graceful shutdown timeout |
| `PY3SIGNER_PRELOAD_APP` | `false` | Preload app in master process |
| `PY3SIGNER_TLS_CERT` | - | TLS certificate path |
| `PY3SIGNER_TLS_KEY` | - | TLS key path |

## Worker Recommendations

- **CPU-bound workloads** (BLS signing): Use `1-2 workers per CPU core`
- **I/O-bound workloads**: Use `2-4 workers per CPU core`
- **Memory constrained**: Reduce workers to limit memory usage

## Running Locally (without Docker)

```bash
# Install dependencies
pip install -e ".[dev]"

# Run with gunicorn
gunicorn py3signer.wsgi:create_app \
    -k aiohttp.GunicornWebWorker \
    -w 4 \
    -b 0.0.0.0:8080

# Or use the config file
gunicorn py3signer.wsgi:create_app -c gunicorn.conf.py
```

## Metrics

Prometheus metrics are available at `/metrics` on the main port (8080) in multi-worker mode.

## Modern Alternative: Granian

For even better performance, consider migrating to [Granian](https://github.com/emmett-framework/granian) - a Rust-based HTTP server. This would require:

1. Refactoring to ASGI (using FastAPI or Starlette)
2. Installing granian: `pip install granian`
3. Running: `granian --workers 4 --interface asgi py3signer.asgi:app`

Granian is significantly faster than gunicorn and written in Rust (like py3signer's BLS signing core).
