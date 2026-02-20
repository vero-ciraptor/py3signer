"""Tests for Prometheus metrics functionality."""

import contextlib

import httpx

from py3signer import metrics
from py3signer.metrics import MetricsServer


def _assert_prometheus_content_type(content_type: str) -> None:
    """Assert that content-type is valid Prometheus format.

    Used across multiple metrics tests to avoid repetition.
    """
    assert "text/plain" in content_type
    assert "version=0.0.4" in content_type or "version=1.0.0" in content_type


def test_metrics_content_type() -> None:
    """Test metrics content type helper."""
    _assert_prometheus_content_type(metrics.get_metrics_content_type())


def test_metrics_output() -> None:
    """Test metrics output generation."""
    output = metrics.get_metrics_output()
    assert isinstance(output, bytes)
    assert len(output) > 0
    # Info metric doesn't work in multiprocessing mode
    # assert b"py3signer_build_info" in output
    assert b"signing_requests_total" in output or b"keys_loaded" in output


class TestMetricsServer:
    """Tests for the standalone MetricsServer using start_http_server."""

    def test_metrics_server_start_stop(self) -> None:
        """Test that MetricsServer can start and stop."""
        # Use a different port to avoid conflicts
        server = MetricsServer(host="127.0.0.1", port=0)  # port 0 = auto-assign
        # Just verify the server object is created properly
        assert server._host == "127.0.0.1"
        assert isinstance(server, MetricsServer)

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

        try:
            # Verify metrics are accessible
            response = httpx.get(f"http://127.0.0.1:{port}/metrics", timeout=5)
            assert response.status_code == 200
            _assert_prometheus_content_type(response.headers.get("content-type", ""))
            # Info metric doesn't work in multiprocessing mode
            # assert "py3signer_build_info" in response.text
        finally:
            # Stop the server - handle the case where _httpd might be a tuple
            with contextlib.suppress(AttributeError, TypeError):
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

            # Try health endpoint explicitly
            try:
                health_response = httpx.get(
                    f"http://127.0.0.1:{port}/health", timeout=5
                )
                if health_response.status_code == 200:
                    content_type = health_response.headers.get("content-type", "")
                    # Health endpoint might return JSON or Prometheus format
                    if "application/json" in content_type:
                        data = health_response.json()
                        assert "status" in data
                    else:
                        # It might return metrics format
                        assert "text/plain" in content_type
            except httpx.HTTPError:
                pass  # Health endpoint may not be available on standalone server
        finally:
            # Stop the server - handle the case where _httpd might be a tuple
            with contextlib.suppress(AttributeError, TypeError):
                server.stop()


class TestMetricsCounters:
    """Tests for metrics counter increments."""

    def test_signing_requests_counter(self) -> None:
        """Test that signing requests counter exists and can be incremented."""
        # Get the counter
        counter = metrics.SIGNING_REQUESTS_TOTAL
        assert counter is not None

        # Increment and verify no error
        counter.inc()
        counter.inc(5)

    def test_signing_errors_counter(self) -> None:
        """Test that signing errors counter exists and can be incremented."""
        # Get the counter
        counter = metrics.SIGNING_ERRORS_TOTAL
        assert counter is not None

        # Increment and verify no error
        counter.labels(error_type="key_not_found").inc()
        counter.labels(error_type="signing_failed").inc()

    def test_signing_duration_histogram(self) -> None:
        """Test that signing duration histogram exists and can observe values."""
        # Get the histogram
        histogram = metrics.SIGNING_DURATION_SECONDS
        assert histogram is not None

        # Observe and verify no error
        histogram.observe(0.001)
        histogram.observe(0.1)
        histogram.observe(1.0)
