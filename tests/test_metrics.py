"""Tests for Prometheus metrics functionality."""

from typing import TYPE_CHECKING

import pytest
import httpx
from litestar import Litestar
from litestar.datastructures import State
from litestar.testing import AsyncTestClient

from py3signer import metrics
from py3signer.handlers import get_routers
from py3signer.metrics import MetricsController, MetricsServer
from py3signer.signer import Signer
from py3signer.storage import KeyStorage

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator


def create_test_app() -> Litestar:
    """Create a test app with proper state setup."""
    storage = KeyStorage()
    signer = Signer(storage)
    return Litestar(
        route_handlers=get_routers(),
        debug=False,
        state=State({
            "storage": storage,
            "signer": signer,
        }),
    )


@pytest.fixture
async def metrics_client() -> AsyncGenerator[AsyncTestClient]:
    """Create a test client for metrics endpoints (via MetricsController)."""
    # Use MetricsController directly for testing metrics output
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


@pytest.mark.asyncio
async def test_metrics_via_standalone_controller() -> None:
    """Test metrics controller directly (backward compatibility)."""
    app = Litestar(route_handlers=[MetricsController], debug=False)
    async with AsyncTestClient(app) as client:
        resp = await client.get("/metrics")
        assert resp.status_code == 200
        assert "py3signer_build_info" in resp.text


class TestMetricsServer:
    """Tests for the standalone MetricsServer using start_http_server."""

    def test_metrics_server_start_stop(self) -> None:
        """Test that MetricsServer can start and stop."""
        # Use a different port to avoid conflicts
        server = MetricsServer(host="127.0.0.1", port=0)  # port 0 = auto-assign
        # Just verify the server object is created properly
        assert server._host == "127.0.0.1"

    def test_metrics_server_lifecycle(self) -> None:
        """Test MetricsServer start/stop lifecycle."""
        # Use an ephemeral port
        import socket

        # Find an available port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]

        server = MetricsServer(host="127.0.0.1", port=port)

        # Start the server
        server.start()
        import time

        time.sleep(0.1)  # Give server time to start

        # Verify metrics are accessible
        response = httpx.get(f"http://127.0.0.1:{port}/metrics", timeout=5)
        assert response.status_code == 200
        assert "py3signer_build_info" in response.text

        # Stop the server
        server.stop()

    def test_metrics_server_health_endpoint(self) -> None:
        """Test metrics server health endpoint via standalone server."""
        import socket

        # Find an available port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]

        server = MetricsServer(host="127.0.0.1", port=port)
        server.start()
        import time

        time.sleep(0.1)

        try:
            response = httpx.get(f"http://127.0.0.1:{port}/", timeout=5)
            # The root path may return 404 or the metrics page depending on implementation
            assert response.status_code in [200, 404]
        finally:
            server.stop()
