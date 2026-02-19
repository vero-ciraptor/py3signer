# Multi-stage Dockerfile for py3signer using uv
# Stage 1: Build Rust extension
# Stage 2: Python runtime with uv

# Stage 1: Build
FROM python:3.12-slim-bookworm AS builder

# Use bash with pipefail for safer pipe operations
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Install Rust toolchain and build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl=7.88.* \
    build-essential=12.* \
    pkg-config=1.8.* \
    libssl-dev=3.0.* \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Set workdir
WORKDIR /build

# Copy project files
COPY Cargo.toml .
COPY rust/ rust/
COPY py3signer/__init__.py py3signer/__init__.py
COPY pyproject.toml .
COPY README.md .

# Create virtual environment, install maturin, and build the Rust extension
RUN uv venv && \
    uv pip install maturin && \
    uv run maturin build --release -o dist

# Stage 2: Runtime
FROM python:3.12-slim-bookworm

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3=3.0.* \
    ca-certificates=2023* \
    && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Create non-root user
RUN groupadd -r py3signer && useradd -r -g py3signer py3signer

# Set workdir
WORKDIR /app

# Copy Python package
COPY py3signer/ py3signer/

# Copy built extension from builder
COPY --from=builder /build/dist/*.whl /tmp/

# Create virtual environment, install dependencies, clean up, and create cache directory
RUN uv venv && \
    uv pip install /tmp/*.whl "litestar[standard]>=2.15.0" "granian>=2.0.0" "msgspec>=0.19.0" "prometheus-client>=0.21.0" && \
    rm /tmp/*.whl && \
    mkdir -p /app/.cache/uv && chown -R py3signer:py3signer /app/.cache

# Change to non-root user
USER py3signer

# Set uv cache directory (writable by py3signer user)
ENV UV_CACHE_DIR=/app/.cache/uv

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

# Set entrypoint using py3signer CLI (which uses Granian internally)
ENTRYPOINT ["uv", "run", "python", "-m", "py3signer"]

# Default arguments
CMD ["--host", "0.0.0.0", "--port", "8080"]
