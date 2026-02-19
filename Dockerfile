ARG PYTHON_IMAGE_TAG="3.14-slim-bookworm"
ARG RUST_IMAGE_TAG="1.93-bookworm"
ARG UV_IMAGE_TAG="0.10"

# uv image
FROM ghcr.io/astral-sh/uv:${UV_IMAGE_TAG} AS uv-image

# Rust toolchain image
FROM docker.io/library/rust:${RUST_IMAGE_TAG} AS rust-toolchain

# Build stage
FROM docker.io/library/python:${PYTHON_IMAGE_TAG} AS build

WORKDIR /build

# Install build dependencies
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy Rust toolchain from official image
COPY --from=rust-toolchain /usr/local/cargo /usr/local/cargo
COPY --from=rust-toolchain /usr/local/rustup /usr/local/rustup
ENV PATH="/usr/local/cargo/bin:${PATH}"
ENV RUSTUP_HOME="/usr/local/rustup"

# Install maturin
RUN --mount=from=uv-image,source=/uv,target=/bin/uv \
    --mount=type=cache,target=/root/.cache/uv \
    uv pip install --system maturin

# Copy project files
COPY Cargo.toml .
COPY rust/ rust/
COPY py3signer/__init__.py py3signer/__init__.py
COPY pyproject.toml .
COPY README.md .

# Build Rust extension
RUN --mount=type=cache,target=/root/.cache/uv \
    maturin build --release -o dist

# Runtime stage
FROM docker.io/library/python:${PYTHON_IMAGE_TAG}

# Create non-root user
RUN groupadd -g 1000 py3signer && \
    useradd --no-create-home --shell /bin/false -u 1000 -g py3signer py3signer

WORKDIR /app

# Install runtime dependencies and Python package
RUN --mount=from=uv-image,source=/uv,target=/bin/uv \
    --mount=from=build,source=/build/dist,target=/tmp/dist \
    --mount=type=cache,target=/root/.cache/uv \
    uv pip install --system /tmp/dist/*.whl

# Copy application code
COPY --chown=py3signer:py3signer py3signer/ py3signer/

# Switch to non-root user
USER py3signer

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

ENTRYPOINT ["python", "-m", "py3signer"]
CMD ["--host", "0.0.0.0", "--port", "8080"]
