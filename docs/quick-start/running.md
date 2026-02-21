# Running py3signer

!!! danger "Experimental Software"

    **DO NOT use py3signer in production with real validators.**

    Running multiple instances with the same keys **WILL result in slashing**.

    See [Risks](../introduction/risks.md) for details.

## Basic Usage

Start py3signer with default settings:

```bash
uv run python -m py3signer
```

This starts the server on `127.0.0.1:8080` with the metrics endpoint on `127.0.0.1:8081`.

## Command Line Options

### Network Binding

```bash
# Bind to all interfaces (use with caution)
uv run python -m py3signer --host 0.0.0.0

# Use a custom port
uv run python -m py3signer --port 9000

# Custom host and port
uv run python -m py3signer --host 0.0.0.0 --port 9000
```

!!! warning "Network Exposure"

    Using `--host 0.0.0.0` exposes py3signer to the network. Ensure you have appropriate firewall rules in place.

### Logging

```bash
# Debug logging
uv run python -m py3signer --log-level DEBUG

# Quiet mode (errors only)
uv run python -m py3signer --log-level ERROR
```

Available levels: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`

### Metrics

```bash
# Custom metrics port
uv run python -m py3signer --metrics-port 9090

# Bind metrics to specific interface
uv run python -m py3signer --metrics-host 0.0.0.0 --metrics-port 9090
```

## Loading Keystores

### Managed Keystores (Data Directory)

The recommended approach for persistent keystores:

```bash
# Load keystores from a directory at startup
uv run python -m py3signer --data-dir ./my-keystores
```

Directory structure:

```
my-keystores/
└── keystores/
    ├── keystore-0.json      # EIP-2335 keystore
    ├── keystore-0.txt       # Password file
    ├── keystore-1.json
    ├── keystore-1.txt
    └── ...
```

Keystore files (`.json`) and their corresponding password files (`.txt`) must share the same base name.

### Input-Only Keystores (External)

For keystores that should **not** be copied to the managed storage:

```bash
uv run python -m py3signer \
  --keystores-path ./external-keys \
  --keystores-passwords-path ./external-passwords
```

These keystores are loaded into memory but **never written to disk** in decrypted form.

### Combined Example

```bash
uv run python -m py3signer \
  --data-dir ./persistent-keystores \
  --keystores-path ./external-keys \
  --keystores-passwords-path ./external-passwords \
  --host 0.0.0.0 \
  --port 8080 \
  --log-level INFO
```

## Worker Processes

py3signer uses multiple worker processes for handling concurrent requests:

```bash
# Use 8 worker processes (default is CPU count)
uv run python -m py3signer --workers 8
```

Or via environment variable:

```bash
PY3SIGNER_WORKERS=8 uv run python -m py3signer
```

## Health Check

Verify the server is running:

```bash
curl http://localhost:8080/health
```

Expected response:

```json
{"status": "healthy"}
```

## Using with a Validator Client

Configure your validator client to use py3signer as its remote signer:

### Lighthouse Example

```bash
lighthouse validator \
  --beacon-nodes http://localhost:5052 \
  --remote-signer-url http://localhost:8080 \
  --use-remote-signer
```

### Prysm Example

```bash
validator \
  --beacon-rpc-provider=localhost:4000 \
  --remote-signer-url=http://localhost:8080 \
  --remote-signer-cert-path="" \
  --validators-external-signer-public-keys="*"
```

### Teku Example

```yaml
# teku.yaml
validator-remote-signer-url: "http://localhost:8080"
validator-external-signer-public-keys: ["*"]
```

## Runtime Management

### Graceful Shutdown

Send `SIGINT` (Ctrl+C) for graceful shutdown:

```bash
# Running in foreground
uv run python -m py3signer
^C  # Press Ctrl+C to stop
```

### Background Process

```bash
# Start in background
uv run python -m py3signer --data-dir ./keystores > py3signer.log 2>&1 &
echo $! > py3signer.pid

# Stop
kill $(cat py3signer.pid)
```

### Systemd Service

Example service file:

```ini
# /etc/systemd/system/py3signer.service
[Unit]
Description=py3signer Remote BLS Signer
After=network.target

[Service]
Type=simple
User=py3signer
Group=py3signer
WorkingDirectory=/opt/py3signer
ExecStart=/opt/py3signer/.venv/bin/python -m py3signer --data-dir /var/lib/py3signer
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

!!! warning "Production Use"

    While systemd can manage py3signer, remember that **py3signer is experimental software** not suitable for production validators with real ETH at stake.

## Monitoring

### Prometheus Metrics

Metrics are available at `http://localhost:8081/metrics` by default:

```bash
# View raw metrics
curl http://localhost:8081/metrics
```

Key metrics include:

- `py3signer_sign_requests_total` – Total signing requests
- `py3signer_sign_errors_total` – Total signing errors
- `py3signer_keys_loaded` – Number of loaded keys
- HTTP request latency and throughput

### Logs

py3signer logs to stderr. Key events to watch for:

```
INFO - Loaded N keystores from managed storage
INFO - Starting py3signer server
INFO - Loaded N external keystores
WARNING - Failed to load keystore ...
ERROR - Failed to add keystore ... to storage
```

## Troubleshooting

### Port Already in Use

```bash
# Check what's using port 8080
lsof -i :8080

# Use a different port
uv run python -m py3signer --port 8082
```

### Keystore Loading Failures

Enable debug logging to see detailed error messages:

```bash
uv run python -m py3signer --data-dir ./keystores --log-level DEBUG
```

Common issues:

- Password file missing or has wrong name
- Keystore file is malformed
- Permission denied on keystore files

### Connection Refused

If your validator client can't connect:

1. Verify py3signer is running: `curl http://localhost:8080/health`
2. Check firewall rules if using `--host 0.0.0.0`
3. Ensure the validator client is using the correct URL
