# Installation

!!! danger "Experimental Software"

    Before installing, please read [Why py3signer](../introduction/why_py3signer.md) and [Risks](../introduction/risks.md).

    **DO NOT use py3signer with production validators.**

## Requirements

- Python 3.14+
- Rust toolchain (for building the native extension)
- [uv](https://github.com/astral-sh/uv){:target="_blank"} (recommended) or pip

## Install Rust

If you don't have Rust installed:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

Verify the installation:

```bash
rustc --version
cargo --version
```

## Install uv

`uv` is the recommended Python package manager for py3signer:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Or with pip:

```bash
pip install uv
```

## Clone and Build

```bash
# Clone the repository
git clone https://github.com/serenita-org/py3signer.git
cd py3signer

# Sync dependencies and build the Rust extension
uv sync
uv run maturin develop
```

The `maturin develop` command builds the Rust extension and installs it in development mode.

## Verify Installation

Test that everything is working:

```bash
# Run tests
uv run pytest

# Check the CLI help
uv run python -m py3signer --help
```

You should see output like:

```
usage: py3signer [-h] [--host HOST] [-p PORT] [--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                 [--metrics-port METRICS_PORT] [--metrics-host METRICS_HOST]
                 [--data-dir DATA_DIR] [--keystores-path KEYSTORES_PATH]
                 [--keystores-passwords-path KEYSTORES_PASSWORDS_PATH] [-w WORKERS]

py3signer - A Remote BLS Signer for Ethereum

options:
  ...
```

## Alternative: Using pip

If you prefer not to use `uv`:

```bash
# Clone the repository
git clone https://github.com/serenita-org/py3signer.git
cd py3signer

# Create a virtual environment
python3.14 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Build the Rust extension
pip install maturin
maturin develop
```

## Development Dependencies

For development work, install additional tools:

```bash
uv sync  # Includes dev dependencies from pyproject.toml
```

Development tools include:

- `pytest` – Testing framework
- `ruff` – Linting and formatting
- `mypy` – Type checking
- `maturin` – Rust extension building

## Docker (Optional)

A Dockerfile is included for containerized deployments:

```bash
# Build the image
docker build -t py3signer .

# Run (example)
docker run -p 8080:8080 py3signer
```

See the [Dockerfile](https://github.com/serenita-org/py3signer/blob/main/Dockerfile){:target="_blank"} for details.

## Troubleshooting

### Rust Build Failures

If `maturin develop` fails:

1. Ensure Rust is up to date:
   ```bash
   rustup update
   ```

2. Check that you have the required Python development headers:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install python3-dev

   # macOS (should be included with Xcode)
   xcode-select --install
   ```

### Python Version Issues

py3signer requires Python 3.14+. Check your version:

```bash
python --version
```

If your system Python is older, use `uv` or a version manager like `pyenv`.

### Permission Errors

If you encounter permission errors with `uv`:

```bash
# Ensure uv's binary directory is in your PATH
export PATH="$HOME/.cargo/bin:$PATH"
```

## Next Steps

Once installed, see [Running py3signer](running.md) to start the server.
