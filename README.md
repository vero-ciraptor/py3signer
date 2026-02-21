# py3signer

A high-performance remote BLS signer for Ethereum Consensus Layer with a hybrid Python/Rust architecture.

⚠️ **No Slashing Protection**: This signer has no slashing protection. Running multiple validators with the same keys will result in slashing.

## Overview

py3signer implements the [Keymanager API](https://ethereum.github.io/keymanager-APIs/) for importing BLS12-381 keys and signing Ethereum consensus data:

- **Python layer** ([Litestar](https://litestar.dev/)): HTTP server, request routing, business logic
- **Rust layer** ([PyO3](https://pyo3.rs/)): High-performance BLS signing via the battle-tested [`blst`](https://github.com/supranational/blst) library

## Features

- **EIP-2335 Keystore Support** – Import password-encrypted BLS keystores
- **Keymanager API** – Compatible with Web3Signer/Lighthouse APIs
- **In-Memory Key Storage** – Keys never touch disk in decrypted form
- **Multiple Signing Domains** – Attestations, blocks, RANDAO, exits, sync committee, and more
- **Prometheus Metrics** – Built-in observability
- **Bulk Loading** – Load keystores at startup from configurable paths

## Requirements

- Python 3.14+
- Rust toolchain (for building the extension)
- [uv](https://github.com/astral-sh/uv)

## Quick Start

```bash
# Install dependencies and build
cd py3signer
uv sync
uv run maturin develop

# Start server
uv run python -m py3signer

# Or with keystores pre-loaded
uv run python -m py3signer --data-dir ./keystores
```

## Usage

```bash
# Basic usage
uv run python -m py3signer

# Custom host/port
uv run python -m py3signer --host 0.0.0.0 --port 9000

# Load keystores at startup
uv run python -m py3signer --data-dir ./keystores

# Input-only keystores (not persisted)
uv run python -m py3signer \
  --keystores-path ./keys \
  --keystores-passwords-path ./passwords
```

## API

py3signer implements the standard [Keymanager API](https://ethereum.github.io/keymanager-APIs/):

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/eth/v1/keystores` | GET | List imported keystores |
| `/eth/v1/keystores` | POST | Import keystores |
| `/eth/v1/keystores` | DELETE | Delete keystores |
| `/api/v1/eth2/sign/{pubkey}` | POST | Sign data |

Metrics are available at `/metrics` (default port 8081).

## Development

```bash
# Run tests
uv run pytest

# Type checking
uv run mypy py3signer

# Linting
uv run ruff check py3signer

# Format
uv run ruff format py3signer
```

## Architecture

```
┌─────────────┐      HTTP       ┌─────────────────┐     PyO3 FFI     ┌─────────────┐
│   Client    │ ─────────────── │  Python/Litestar │ ─────────────── │  Rust/blst  │
└─────────────┘                 └─────────────────┘                 └─────────────┘
                                      │                                    │
                                 ┌────┴────┐                          ┌──┴──┐
                                 │ handlers│                          │sign │
                                 │ storage │                          │verify
                                 │ metrics │                          │aggregate
                                 └─────────┘                          └─────┘
```

## Security

- **No Slashing Protection** – The signer validates request format but does not prevent double-signing
- **In-Memory Keys Only** – Decrypted keys are never written to disk
- **Network Binding** – Defaults to `127.0.0.1`; use `0.0.0.0` only behind a firewall
- **Key Permissions** – Ensure keystore files have restrictive permissions (600)

## License

MIT License – see [LICENSE](LICENSE) for details.
