"""Tests for Prometheus metrics functionality."""

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer

from py3signer.config import Config
from py3signer.server import create_app
from py3signer.storage import KeyStorage
from py3signer.signer import Signer
from py3signer.metrics_server import MetricsServer, create_metrics_app
from py3signer import metrics
import json


@pytest_asyncio.fixture
async def metrics_client():
    """Create a test client for metrics server."""
    app = create_metrics_app()
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    yield client
    await client.close()


@pytest.mark.asyncio
async def test_metrics_endpoint_returns_prometheus_format(metrics_client):
    """Test that /metrics endpoint returns Prometheus format."""
    resp = await metrics_client.get("/metrics")
    assert resp.status == 200
    
    content_type = resp.content_type
    assert "text/plain" in content_type
    
    text = await resp.text()
    # Check for expected metrics
    assert "py3signer_build_info" in text
    assert "signing_requests_total" in text
    assert "signing_duration_seconds" in text
    assert "signing_errors_total" in text
    assert "keys_loaded" in text
    assert "http_requests_total" in text
    assert "http_request_duration_seconds" in text


@pytest.mark.asyncio
async def test_metrics_endpoint_health(metrics_client):
    """Test metrics server health endpoint."""
    resp = await metrics_client.get("/health")
    assert resp.status == 200
    
    data = await resp.json()
    assert data["status"] == "healthy"


@pytest.mark.asyncio
async def test_keys_loaded_gauge(metrics_client):
    """Test that keys_loaded gauge reflects key count."""
    # Start fresh with 0 keys
    metrics.KEYS_LOADED.set(0)
    
    resp = await metrics_client.get("/metrics")
    text = await resp.text()
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
    text = await resp.text()
    assert "keys_loaded 3.0" in text
    
    # Remove a key
    pk_hex = list(storage._keys.keys())[0]
    storage.remove_key(pk_hex)
    
    # Check gauge updated
    resp = await metrics_client.get("/metrics")
    text = await resp.text()
    assert "keys_loaded 2.0" in text
    
    # Cleanup
    storage.clear()


@pytest.mark.asyncio
async def test_metrics_server_start_stop():
    """Test metrics server can start and stop."""
    server = MetricsServer(host="127.0.0.1", port=18081)
    
    # Start server
    await server.start()
    
    # Verify it's running by making a request
    import aiohttp
    async with aiohttp.ClientSession() as session:
        async with session.get("http://127.0.0.1:18081/metrics") as resp:
            assert resp.status == 200
            text = await resp.text()
            assert "py3signer_build_info" in text
    
    # Stop server
    await server.stop()


@pytest.mark.asyncio
async def test_metrics_server_context_manager():
    """Test metrics server context manager."""
    import aiohttp
    
    async with MetricsServer(host="127.0.0.1", port=18082) as server:
        async with aiohttp.ClientSession() as session:
            async with session.get("http://127.0.0.1:18082/metrics") as resp:
                assert resp.status == 200


def test_metrics_content_type():
    """Test metrics content type helper."""
    from py3signer.metrics import get_metrics_content_type
    content_type = get_metrics_content_type()
    assert "text/plain" in content_type


def test_metrics_output():
    """Test metrics output generation."""
    from py3signer.metrics import get_metrics_output
    output = get_metrics_output()
    assert isinstance(output, bytes)
    assert b"py3signer_build_info" in output
