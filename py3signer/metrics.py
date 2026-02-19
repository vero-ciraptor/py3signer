"""Prometheus metrics for py3signer with standalone HTTP server.

This module defines and exposes all Prometheus metrics used by py3signer.
Metrics are served on a separate port using prometheus_client's built-in HTTP server.
"""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING

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
    start_http_server,
)

if TYPE_CHECKING:
    from socketserver import ThreadingMixIn
    from wsgiref.types import WSGIApplication

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


# Metrics HTTP controller for backward compatibility (used by tests and direct imports)


class MetricsController(Controller):  # type: ignore[misc]
    """Prometheus metrics HTTP endpoints.

    Note: In production, metrics are served on a separate port via the
    standalone metrics server. This controller is kept for backward
    compatibility and testing purposes.
    """

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


# Standalone metrics server using prometheus_client's built-in HTTP server


class MetricsServer:
    """Standalone Prometheus metrics HTTP server using prometheus_client.start_http_server.

    This runs the metrics endpoint on a separate port from the main API,
    allowing metrics to be scraped independently.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8081) -> None:
        self._host = host
        self._port = port
        self._httpd: ThreadingMixIn | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the metrics server in a background thread.

        This uses prometheus_client.start_http_server() which creates a
        threaded HTTP server that serves metrics from the global registry.
        """
        # Start the server in a daemon thread
        self._thread = threading.Thread(
            target=self._run_server,
            daemon=True,
        )
        self._thread.start()
        logger.info(
            f"Metrics server started at http://{self._host}:{self._port}/metrics",
        )

    def _run_server(self) -> None:
        """Run the HTTP server (called in background thread)."""
        try:
            self._httpd = start_http_server(
                port=self._port,
                addr=self._host,
                registry=REGISTRY,
            )
        except Exception:
            logger.exception("Failed to start metrics server")
            raise

    def stop(self) -> None:
        """Stop the metrics server."""
        if self._httpd is not None:
            # The httpd from start_http_server is a ThreadingHTTPServer
            # We need to shut it down gracefully
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except Exception:
                logger.exception("Error stopping metrics server")
            finally:
                self._httpd = None

        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

        logger.info("Metrics server stopped")
