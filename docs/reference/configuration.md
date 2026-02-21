# Configuration

py3signer is configured via command-line arguments. There is no configuration file.

!!! danger "Experimental Software"

    **Do not use py3signer with production validators.** See [Risks](../introduction/risks.md).

## CLI Reference

### `--host`

The HTTP server listen address.

- **Default:** `127.0.0.1`
- **Example:** `--host 0.0.0.0`

!!! warning "Network Exposure"

    Using `0.0.0.0` exposes py3signer to the network. Ensure appropriate firewall protection.

---

### `--port` / `-p`

The HTTP server port.

- **Default:** `8080`
- **Example:** `--port 9000`

---

### `--metrics-host`

The metrics server listen address.

- **Default:** `127.0.0.1`
- **Example:** `--metrics-host 0.0.0.0`

---

### `--metrics-port`

The metrics server port.

- **Default:** `8081`
- **Example:** `--metrics-port 9090`

---

### `--data-dir`

Path to a directory containing managed keystores.

- **Default:** `None`
- **Example:** `--data-dir ./my-keystores`

When provided, py3signer loads keystores from `{data_dir}/keystores/` at startup and persists any keystores imported via the API.

**Directory Structure:**

```
data-dir/
└── keystores/
    ├── keystore-0.json      # EIP-2335 keystore
    ├── keystore-0.txt       # Password file (same base name)
    ├── keystore-1.json
    └── keystore-1.txt
```

---

### `--keystores-path`

Path to a directory containing input-only keystore `.json` files.

- **Default:** `None`
- **Example:** `--keystores-path ./external/keys`

These keystores are loaded at startup but **not** persisted to the data directory. Useful for loading keys from external storage without copying them.

**Requires:** `--keystores-passwords-path`

---

### `--keystores-passwords-path`

Path to a directory containing input-only password `.txt` files.

- **Default:** `None`
- **Example:** `--keystores-passwords-path ./external/passwords`

Password files must share the same base name as their corresponding keystore files.

**Requires:** `--keystores-path`

---

### `--log-level`

The logging level.

- **Default:** `INFO`
- **Choices:** `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`
- **Example:** `--log-level DEBUG`

---

### `--workers` / `-w`

Number of worker processes for handling concurrent requests.

- **Default:** Number of CPU cores
- **Example:** `--workers 8`

Alternatively, set via environment variable:

```bash
export PY3SIGNER_WORKERS=8
uv run python -m py3signer
```

---

### `--help` / `-h`

Show help message and exit.

## Environment Variables

### `PY3SIGNER_WORKERS`

Sets the number of worker processes. Overrides the `--workers` flag if both are set.

```bash
export PY3SIGNER_WORKERS=4
uv run python -m py3signer
```

### `PROMETHEUS_MULTIPROC_DIR`

Directory for Prometheus multi-process metrics. Automatically set when using multiple workers.

**Note:** This is set automatically by py3signer when workers > 1. You typically don't need to set this manually.

## Configuration Examples

### Development

```bash
# Local development with debug logging
uv run python -m py3signer \
  --log-level DEBUG \
  --port 8080
```

### Testnet with Managed Keystores

```bash
# Load keystores at startup
uv run python -m py3signer \
  --data-dir /var/lib/py3signer/keystores \
  --host 0.0.0.0 \
  --port 8080 \
  --log-level INFO
```

### External Keystores Only

```bash
# Load keystores from external location (not persisted)
uv run python -m py3signer \
  --keystores-path /mnt/external/keys \
  --keystores-passwords-path /mnt/external/passwords \
  --host 127.0.0.1 \
  --port 8080
```

### Combined Setup

```bash
# Both managed and external keystores
uv run python -m py3signer \
  --data-dir /var/lib/py3signer \
  --keystores-path /mnt/external/keys \
  --keystores-passwords-path /mnt/external/passwords \
  --host 0.0.0.0 \
  --port 8080 \
  --metrics-port 9090 \
  --workers 8 \
  --log-level INFO
```

## Validation

py3signer validates configuration at startup and exits with an error if any settings are invalid:

```bash
# Invalid port
$ uv run python -m py3signer --port 99999
Error: port must be between 1 and 65535, got 99999

# Missing password path
$ uv run python -m py3signer --keystores-path ./keys
Error: --keystores-passwords-path must be provided when --keystores-path is set

# Non-existent directory
$ uv run python -m py3signer --data-dir /nonexistent
Error: data_dir does not exist: /nonexistent
```

## Default Configuration Summary

| Setting | Default Value |
|---------|---------------|
| Host | `127.0.0.1` |
| Port | `8080` |
| Metrics Host | `127.0.0.1` |
| Metrics Port | `8081` |
| Log Level | `INFO` |
| Workers | CPU count |
| Data Directory | None |
| Keystores Path | None |
| Passwords Path | None |
