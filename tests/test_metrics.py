"""Tests for Prometheus metrics functionality."""

from collections.abc import AsyncGenerator

import pytest
from litestar import Litestar
from litestar.testing import AsyncTestClient

from py3signer import metrics
from py3signer.metrics import MetricsController
from py3signer.storage import KeyStorage


@pytest.fixture
async def metrics_client() -> AsyncGenerator[AsyncTestClient]:
    """Create a test client for metrics server."""
    app = Litestar(route_handlers=[MetricsController], debug=False)
    async with AsyncTestClient(app) as client:
        yield client


@pytest.mark.asyncio
async def test_metrics_endpoint_returns_prometheus_format(
    metrics_client: AsyncTestClient,
) -> None:
    """Test that /metrics endpoint returns Prometheus format."""
    resp = await metrics_client.get("/metrics")
    assert resp.status_code == 200

    content_type = resp.headers.get("content-type", "")
    assert "text/plain" in content_type

    text = resp.text
    # Check for expected metrics
    assert "py3signer_build_info" in text
    assert "signing_requests_total" in text
    assert "signing_duration_seconds" in text
    assert "signing_errors_total" in text
    assert "keys_loaded" in text
    assert "http_requests_total" in text
    assert "http_request_duration_seconds" in text


@pytest.mark.asyncio
async def test_metrics_endpoint_health(metrics_client: AsyncTestClient) -> None:
    """Test metrics server health endpoint."""
    resp = await metrics_client.get("/health")
    assert resp.status_code == 200

    data = resp.json()
    assert data["status"] == "healthy"


@pytest.mark.asyncio
async def test_keys_loaded_gauge(metrics_client: AsyncTestClient) -> None:
    """Test that keys_loaded gauge reflects key count."""
    # Start fresh with 0 keys
    metrics.KEYS_LOADED.set(0)

    resp = await metrics_client.get("/metrics")
    text = resp.text
    assert "keys_loaded 0.0" in text

    # Create storage and add keys
    storage = KeyStorage()

    from py3signer_core import generate_random_key

    for _ in range(3):
        sk = generate_random_key()
        pk = sk.public_key()
        storage.add_key(pk, sk)

    # Check gauge updated
    resp = await metrics_client.get("/metrics")
    text = resp.text
    assert "keys_loaded 3.0" in text

    # Remove a key
    pk_hex = next(iter(storage._keys.keys()))
    storage.remove_key(pk_hex)

    # Check gauge updated
    resp = await metrics_client.get("/metrics")
    text = resp.text
    assert "keys_loaded 2.0" in text

    # Cleanup
    storage.clear()


def test_metrics_content_type() -> None:
    """Test metrics content type helper."""
    content_type = metrics.get_metrics_content_type()
    assert "text/plain" in content_type


def test_metrics_output() -> None:
    """Test metrics output generation."""
    output = metrics.get_metrics_output()
    assert isinstance(output, bytes)
    assert b"py3signer_build_info" in output
