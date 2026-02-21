ARG PYTHON_IMAGE_TAG="3.14-slim-bookworm"
ARG RUST_IMAGE_TAG="1.93-bookworm"
ARG UV_IMAGE_TAG="0.10"

# uv image
FROM ghcr.io/astral-sh/uv:${UV_IMAGE_TAG} AS uv-image

# Rust toolchain image
FROM docker.io/library/rust:${RUST_IMAGE_TAG} AS rust-toolchain

# Build stage
FROM docker.io/library/python:${PYTHON_IMAGE_TAG} AS build

WORKDIR /py3signer

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
RUN rustup default stable

# Copy all project files
COPY . .

# Install dependencies and build (maturin compiles Rust extension automatically)
RUN --mount=from=uv-image,source=/uv,target=/bin/uv \
    --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --compile-bytecode

# Runtime stage
FROM docker.io/library/python:${PYTHON_IMAGE_TAG}

ENV PATH="/py3signer/.venv/bin:$PATH"

WORKDIR /py3signer

RUN groupadd -g 1000 py3signer && \
    useradd --no-create-home --shell /bin/false -u 1000 -g py3signer py3signer && \
    chown -R py3signer:py3signer /py3signer

COPY --from=build --chown=py3signer:py3signer /py3signer/.venv /py3signer/.venv
COPY --chown=py3signer:py3signer py3signer/ py3signer/

USER py3signer

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

ENTRYPOINT ["python", "-m", "py3signer"]
CMD ["--host", "0.0.0.0", "--port", "8080"]
