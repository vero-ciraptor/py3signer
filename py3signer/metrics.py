"""Prometheus metrics for py3signer with Litestar.

This module defines and exposes all Prometheus metrics used by py3signer.
Metrics are opt-in and only collected when --metrics-enabled is set.
"""

import logging
import threading
import time
from typing import Any

from litestar import Controller, get
from litestar.response import Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    Info,
    generate_latest,
)

logger = logging.getLogger(__name__)

# Create a dedicated registry for py3signer metrics
REGISTRY = CollectorRegistry()

# Application info
APP_INFO = Info(
    "py3signer_build_info",
    "Build information about py3signer",
    registry=REGISTRY,
)
APP_INFO.info({"version": "0.1.0", "name": "py3signer"})

# Signing metrics
SIGNING_REQUESTS_TOTAL = Counter(
    "signing_requests_total",
    "Total number of signing requests",
    ["key_type"],
    registry=REGISTRY,
)

SIGNING_DURATION_SECONDS = Histogram(
    "signing_duration_seconds",
    "Time spent performing signing operations",
    ["key_type"],
    buckets=[0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
    registry=REGISTRY,
)

SIGNING_ERRORS_TOTAL = Counter(
    "signing_errors_total",
    "Total number of signing errors",
    ["error_type"],
    registry=REGISTRY,
)

# Key metrics
KEYS_LOADED = Gauge(
    "keys_loaded",
    "Number of keys currently loaded",
    registry=REGISTRY,
)

# HTTP metrics
HTTP_REQUESTS_TOTAL = Counter(
    "http_requests_total",
    "Total number of HTTP requests",
    ["method", "endpoint", "status"],
    registry=REGISTRY,
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "http_request_duration_seconds",
    "Time spent processing HTTP requests",
    ["method", "endpoint"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
    registry=REGISTRY,
)


def get_metrics_output() -> bytes:
    """Generate Prometheus-formatted metrics output."""
    return generate_latest(REGISTRY)


def get_metrics_content_type() -> str:
    """Get the content type for Prometheus metrics."""
    return CONTENT_TYPE_LATEST


# Litestar middleware for tracking metrics


class PrometheusMiddleware:
    """Middleware to track HTTP request metrics."""

    async def __call__(self, request: Any, handler: Any) -> Any:
        """Process request and track metrics."""
        start_time = time.perf_counter()
        method = request.method
        endpoint = request.url.path
        status = "500"

        try:
            response = await handler(request)
            status = str(response.status_code)
            return response
        except Exception as e:
            # Try to get status from exception
            if hasattr(e, "status_code"):
                status = str(e.status_code)
            raise
        finally:
            duration = time.perf_counter() - start_time
            HTTP_REQUEST_DURATION_SECONDS.labels(method=method, endpoint=endpoint).observe(duration)
            HTTP_REQUESTS_TOTAL.labels(method=method, endpoint=endpoint, status=status).inc()


# Metrics HTTP controller


class MetricsController(Controller):  # type: ignore[misc]
    """Prometheus metrics HTTP endpoints."""

    path = "/"

    @get("/metrics")  # type: ignore[untyped-decorator]
    async def metrics(self) -> Response:
        """Handler for the /metrics endpoint."""
        return Response(
            content=get_metrics_output(),
            headers={"Content-Type": get_metrics_content_type()},
        )

    @get("/health")  # type: ignore[untyped-decorator]
    async def health(self) -> dict[str, str]:
        """Health check for metrics server."""
        return {"status": "healthy"}


# Standalone metrics server for multi-process scenarios using threaded HTTP server

class MetricsServer:
    """Standalone Prometheus metrics HTTP server using basic threaded HTTP server."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8081) -> None:
        self._host = host
        self._port = port
        self._server = None
        self._thread = None
        self._running = False

    async def start(self) -> None:
        """Start the metrics server in a background thread."""
        from http.server import HTTPServer, BaseHTTPRequestHandler

        class MetricsHandler(BaseHTTPRequestHandler):
            """HTTP handler for metrics endpoint."""

            def log_message(self, format, *args):
                # Suppress default logging
                pass

            def do_GET(self):
                if self.path == "/metrics":
                    self.send_response(200)
                    self.send_header("Content-Type", get_metrics_content_type())
                    self.end_headers()
                    self.wfile.write(get_metrics_output())
                elif self.path == "/health":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"status": "healthy"}')
                else:
                    self.send_response(404)
                    self.end_headers()

        def run_server():
            """Run the HTTP server."""
            self._server = HTTPServer((self._host, self._port), MetricsHandler)
            logger.info(f"Metrics server running at http://self._host:self._port/metrics")
            while self._running:
                try:
                    self._server.handle_request()
                except Exception:
                    break

        self._running = True
        self._thread = threading.Thread(target=run_server, daemon=True)
        self._thread.start()
        logger.info(f"Metrics server started at http://self._host:self._port/metrics")

    async def stop(self) -> None:
        """Stop the metrics server."""
        self._running = False
        if self._server:
            # Close the server socket to wake up the thread
            try:
                self._server.server_close()
            except Exception:
                pass
            self._server = None
        if self._thread:
            self._thread.join(timeout=2)
        logger.info("Metrics server stopped")
