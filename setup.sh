#!/bin/bash
# Setup script for py3signer development environment

set -e

echo "Setting up py3signer development environment..."

# Check for required tools
echo "Checking prerequisites..."

if ! command -v uv &> /dev/null; then
    echo "Error: uv is not installed. Install it from https://github.com/astral-sh/uv"
    exit 1
fi

if ! command -v cargo &> /dev/null; then
    echo "Error: Rust/Cargo is not installed. Install from https://rustup.rs"
    exit 1
fi

echo "✓ uv found"
echo "✓ cargo found"

# Check Python version
PYTHON_VERSION=$(uv run python --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
REQUIRED_VERSION="3.12"

if [ "$PYTHON_VERSION" != "$REQUIRED_VERSION" ]; then
    echo "Warning: Python $PYTHON_VERSION detected. Python $REQUIRED_VERSION+ is required."
fi

# Create virtual environment and sync dependencies
echo ""
echo "Creating virtual environment and syncing dependencies..."
uv sync

# Build Rust extension
echo ""
echo "Building Rust extension with maturin..."
uv run maturin develop

echo ""
echo "✓ Setup complete!"
echo ""
echo "To run the server:"
echo "  uv run python -m py3signer"
echo ""
echo "To run tests:"
echo "  uv run pytest"
echo ""
echo "To build for production:"
echo "  uv run maturin build --release"
