# py3signer Makefile - Using uv for Python management

.PHONY: all build test clean docker install dev fmt lint sync

# Default target
all: build

# Sync dependencies with uv
sync:
	uv sync

# Build the Rust extension
develop:
	uv run maturin develop

build:
	uv run maturin build --release

# Install in development mode
dev: sync
	uv run maturin develop

# Run with uv
run:
	uv run python -m py3signer

run-debug:
	uv run python -m py3signer --log-level DEBUG

# Testing
test: test-rust test-python

test-rust:
	cd rust/py3signer_core && cargo test

test-python: dev
	uv run pytest

test-cov: dev
	uv run pytest --cov=py3signer --cov-report=html --cov-report=term

# Code quality
fmt:
	cd rust/py3signer_core && cargo fmt
	uv run ruff format py3signer tests

lint:
	cd rust/py3signer_core && cargo clippy -- -D warnings
	uv run ruff check py3signer tests
	uv run mypy py3signer

# Docker
docker-build:
	docker build -t py3signer:latest .

docker-run:
	docker run -p 8080:8080 py3signer:latest

# Cleanup
clean:
	cd rust/py3signer_core && cargo clean
	rm -rf build/ dist/ *.egg-info/ .pytest_cache/ .coverage htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.so" -delete
	rm -f uv.lock

# Lock dependencies
lock:
	uv lock

# Show dependency tree
tree:
	uv tree

# Upgrade all dependencies
upgrade:
	uv sync --upgrade
