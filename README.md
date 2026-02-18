# py3signer

A Remote BLS Signer for Ethereum Consensus Layer with a hybrid Python/Rust architecture.

**⚠️ No Slashing Protection**: This signer signs whatever is requested. Run multiple validator clients with the same keys at your own risk.

## Overview

py3signer implements the standard Keymanager API for importing BLS12-381 keys and signing Ethereum consensus layer data. It combines:

- **Python layer (aiohttp)**: HTTP server, request routing, business logic, configuration
- **Rust layer (PyO3)**: High-performance BLS signing operations using battle-tested `blst` library

## Features

- **EIP-2335 Keystore Support**: Import password-encrypted BLS keystores
- **Keymanager API**: Compatible with Web3Signer/Lighthouse API
- **In-Memory Key Storage**: Keys are never persisted decrypted to disk
- **Multiple Signing Domains**: Support for attestations, blocks, RANDAO, exits, etc.
- **Optional TLS**: HTTPS support with certificate configuration
- **Authentication**: Optional bearer token authentication
- **Health Endpoint**: Kubernetes-compatible health checks

## Requirements

- Python 3.12+
- Rust toolchain (for building the extension)
- [uv](https://github.com/astral-sh/uv) - Python package manager

## Installation

### Prerequisites

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Development Setup

```bash
# Clone the repository
git clone https://github.com/example/py3signer.git
cd py3signer

# Run setup script
./setup.sh

# Or manually:
uv sync
uv run maturin develop
```

### Production Installation

```bash
# Build wheel
uv run maturin build --release

# Install from wheel
uv pip install dist/py3signer_core*.whl
```

### Docker

```bash
# Build image
docker build -t py3signer:latest .

# Run
docker run -p 8080:8080 py3signer:latest

# With custom arguments
docker run -p 8080:8080 py3signer:latest --host 0.0.0.0 --port 8080
```

## Usage

### Quick Start

```bash
# Start server on default port 8080
uv run python -m py3signer

# With custom host/port
uv run python -m py3signer --host 0.0.0.0 --port 9000

# With TLS
uv run python -m py3signer --tls-cert cert.pem --tls-key key.pem

# With authentication
uv run python -m py3signer --auth-token mysecrettoken
```

### Using Makefile shortcuts

```bash
# Sync dependencies and build
make dev

# Run server
make run

# Run with debug logging
make run-debug

# Run tests
make test
```

### TLS Configuration

For HTTPS support:

```bash
uv run python -m py3signer --tls-cert cert.pem --tls-key key.pem
```

### Authentication

For API authentication:

```bash
uv run python -m py3signer --auth-token mysecrettoken
```

## API Reference

### Health Check

```bash
curl http://localhost:8080/health
```

Response:
```json
{
  "status": "healthy",
  "keys_loaded": 0
}
```

### List Keystores

```bash
curl http://localhost:8080/eth/v1/keystores
```

Response:
```json
{
  "data": [
    {
      "validating_pubkey": "a99a76ed...",
      "derivation_path": "m/12381/3600/0/0/0",
      "readonly": false
    }
  ]
}
```

### Import Keystores

```bash
curl -X POST http://localhost:8080/eth/v1/keystores \
  -H "Content-Type: application/json" \
  -d '{
    "keystores": ["$(cat keystore.json)"],
    "passwords": ["keystore_password"]
  }'
```

Response:
```json
{
  "data": [
    {
      "status": "imported",
      "message": "Successfully imported keystore..."
    }
  ]
}
```

### Delete Keystores

```bash
curl -X DELETE http://localhost:8080/eth/v1/keystores \
  -H "Content-Type: application/json" \
  -d '{
    "pubkeys": ["a99a76ed..."]
  }'
```

Response:
```json
{
  "data": [
    {
      "status": "deleted",
      "message": "Successfully deleted keystore..."
    }
  ]
}
```

### Sign Data

```bash
curl -X POST http://localhost:8080/api/v1/eth2/sign/a99a76ed... \
  -H "Content-Type: application/json" \
  -d '{
    "signingRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "domain_name": "beacon_attester"
  }'
```

Response:
```json
{
  "signature": "0x8f5c5b5e7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4"
}
```

### Domain Names

Available signing domains:

- `beacon_proposer` - Beacon block proposal
- `beacon_attester` - Attestation
- `randao` - RANDAO reveal
- `deposit` - Deposit
- `voluntary_exit` - Voluntary exit
- `selection_proof` - Selection proof
- `aggregate_and_proof` - Aggregate and proof
- `sync_committee` - Sync committee
- `sync_committee_selection_proof` - Sync committee selection proof
- `contribution_and_proof` - Contribution and proof

You can also specify a custom domain as 4 hex bytes:

```bash
curl -X POST http://localhost:8080/api/v1/eth2/sign/a99a76ed... \
  -H "Content-Type: application/json" \
  -d '{
    "signingRoot": "0x...",
    "domain": "0x01000000"
  }'
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Client                               │
└─────────────────────────┬───────────────────────────────────┘
                          │ HTTP/HTTPS
┌─────────────────────────▼───────────────────────────────────┐
│  Python Layer (aiohttp)                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   server.py  │  │ handlers.py  │  │  config.py   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  storage.py  │  │  signer.py   │  │ keystore.py  │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────┬───────────────────────────────────┘
                          │ PyO3 FFI
┌─────────────────────────▼───────────────────────────────────┐
│  Rust Layer (PyO3)                                          │
│  ┌───────────────────────────────────────────────────────┐  │
│  │           py3signer_core (blst library)               │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐     │  │
│  │  │ SecretKey   │ │ PublicKey   │ │ Signature   │     │  │
│  │  └─────────────┘ └─────────────┘ └─────────────┘     │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐     │  │
│  │  │    sign     │ │   verify    │ │  aggregate  │     │  │
│  │  └─────────────┘ └─────────────┘ └─────────────┘     │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Testing

### Python Tests

```bash
# Run all tests
uv run pytest

# With coverage
uv run pytest --cov=py3signer --cov-report=html

# Specific test file
uv run pytest tests/test_api.py
```

### Rust Tests

```bash
cd rust/py3signer_core
cargo test
```

### Integration Tests

```bash
# Start server in one terminal
uv run python -m py3signer --log-level DEBUG

# In another terminal, run test script
./examples/test_api.sh
```

## Project Structure

```
py3signer/
├── Cargo.toml                    # Rust workspace
├── pyproject.toml                # Python package + uv config
├── uv.lock                       # uv lock file (generated)
├── README.md                     # This file
├── LICENSE                       # MIT License
├── Makefile                      # Common tasks with uv
├── Dockerfile                    # Multi-stage Docker build
├── rust/
│   └── py3signer_core/           # PyO3 extension
├── py3signer/                    # Python package
│   ├── __init__.py
│   ├── __main__.py               # Entry point
│   ├── cli.py                    # CLI interface
│   ├── server.py                 # aiohttp setup
│   ├── handlers.py               # HTTP routes (msgspec)
│   ├── config.py                 # Configuration (msgspec)
│   ├── signer.py                 # Signing logic
│   ├── keystore.py               # EIP-2335 handling
│   └── storage.py                # In-memory key storage
├── tests/                        # pytest suite
└── examples/                     # Examples and test data
```

## Tech Stack

- **HTTP Server**: aiohttp
- **Validation**: msgspec (fast, efficient struct-based validation)
- **Configuration**: CLI arguments with msgspec Struct
- **BLS Crypto**: blst (Rust via PyO3)
- **Package Management**: uv
- **Build**: maturin

## Security Considerations

**⚠️ IMPORTANT**: This signer has NO SLASHING PROTECTION. It will sign whatever is requested.

1. **No Slashing Protection**: This signer validates request format but does not prevent double-signing. Use at your own risk.
2. **In-Memory Keys**: Decrypted keys are stored only in memory and never written to disk
3. **Authentication**: Use the `--auth-token` option in production
4. **TLS**: Enable HTTPS with `--tls-cert` and `--tls-key` for production
5. **Network Binding**: Bind to `127.0.0.1` by default - use `0.0.0.0` only behind a firewall
6. **Key Permissions**: Ensure keystore files have restrictive permissions (600)

## Development Commands

```bash
# Sync dependencies
uv sync

# Build Rust extension
uv run maturin develop

# Run server
uv run python -m py3signer

# Run tests
uv run pytest

# Linting and formatting
uv run ruff check py3signer tests
uv run ruff format py3signer tests
uv run mypy py3signer

# Lock dependencies
uv lock

# Show dependency tree
uv tree
```

## License

MIT License - see LICENSE file for details.

## References

- [EIP-2335: BLS12-381 Keystore](https://eips.ethereum.org/EIPS/eip-2335)
- [Keymanager API Specification](https://ethereum.github.io/keymanager-APIs/)
- [Web3Signer](https://github.com/Consensys/web3signer)
- [Lighthouse](https://github.com/sigp/lighthouse)
- [blst library](https://github.com/supranational/blst)
- [msgspec](https://jcristharif.com/msgspec/)
- [uv - Python package manager](https://github.com/astral-sh/uv)
