"""Prometheus metrics for py3signer with standalone HTTP server.

This module defines and exposes all Prometheus metrics used by py3signer.
Metrics are served on a separate port using prometheus_client's built-in HTTP server.
"""

from __future__ import annotations

import logging
import os
import tempfile
import threading
from pathlib import Path
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
    from http.server import ThreadingHTTPServer
    from wsgiref.simple_server import WSGIServer

logger = logging.getLogger(__name__)

# Multi-process metrics support
MULTIPROC_DIR: Path | None = None


def setup_multiproc_dir() -> Path:
    """Set up Prometheus multi-process metrics directory.

    Must be called BEFORE importing prometheus_client in multi-process mode.
    This creates a temporary directory that all worker processes use to
    share metric data via files.

    Returns:
        Path to the multi-process metrics directory.
    """
    global MULTIPROC_DIR

    # Use existing dir if already set
    existing = os.environ.get("PROMETHEUS_MULTIPROC_DIR")
    if existing:
        MULTIPROC_DIR = Path(existing)
        logger.info(f"Using existing Prometheus multi-process metrics dir: {existing}")
        return MULTIPROC_DIR

    # Create a temp directory for multi-process metrics
    temp_dir = tempfile.mkdtemp(prefix="py3signer_metrics_")
    MULTIPROC_DIR = Path(temp_dir)
    os.environ["PROMETHEUS_MULTIPROC_DIR"] = temp_dir

    logger.info(f"Set up Prometheus multi-process metrics dir: {temp_dir}")
    return MULTIPROC_DIR


def cleanup_multiproc_dir() -> None:
    """Remove stale metrics files from multi-process directory.

    Should be called on startup in the main process before starting workers.
    """
    global MULTIPROC_DIR

    multiproc_dir = MULTIPROC_DIR or os.environ.get("PROMETHEUS_MULTIPROC_DIR")
    if not multiproc_dir:
        return

    multiproc_path = Path(multiproc_dir)
    if not multiproc_path.exists():
        return

    # Remove all gauge files (they contain pid-specific data)
    for gauge_file in multiproc_path.glob("gauge_*.db"):
        try:
            gauge_file.unlink()
            logger.debug(f"Removed stale gauge file: {gauge_file}")
        except OSError:
            pass

    logger.info(f"Cleaned up Prometheus multi-process metrics dir: {multiproc_dir}")


def get_multiproc_dir() -> Path | None:
    """Get the current multi-process metrics directory.

    Returns:
        Path to the multi-process metrics directory, or None if not set.
    """
    global MULTIPROC_DIR
    if MULTIPROC_DIR is not None:
        return MULTIPROC_DIR
    existing = os.environ.get("PROMETHEUS_MULTIPROC_DIR")
    if existing:
        MULTIPROC_DIR = Path(existing)
        return MULTIPROC_DIR
    return None


# Check if we're in multi-process mode (workers > 1)
_workers_env = os.environ.get("PY3SIGNER_WORKERS", "1")
_is_multiprocess = int(_workers_env) > 1

# Get or set up multi-process directory if needed
_multiproc_dir = get_multiproc_dir()
if _is_multiprocess and _multiproc_dir is None:
    _multiproc_dir = setup_multiproc_dir()

# Create registry - use MultiProcessCollector if in multi-process mode
if _is_multiprocess:
    from prometheus_client import multiprocess

    # In multi-process mode, use the default registry which is aware of
    # PROMETHEUS_MULTIPROC_DIR and will use MultiProcessCollector automatically
    # when generate_latest() is called without an explicit registry
    REGISTRY = CollectorRegistry()
    multiprocess.MultiProcessCollector(REGISTRY, path=str(_multiproc_dir))  # type: ignore[no-untyped-call]
    logger.info(
        f"Enabled Prometheus multi-process metrics mode ({_workers_env} workers, dir={_multiproc_dir})"
    )
else:
    REGISTRY = CollectorRegistry()
    logger.debug("Using single-process Prometheus metrics mode")

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
    registry=REGISTRY,
)

SIGNING_DURATION_SECONDS = Histogram(
    "signing_duration_seconds",
    "Time spent performing signing operations",
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
# Use 'max' mode since all workers load the same keys - max gives the correct count
KEYS_LOADED = Gauge(
    "keys_loaded",
    "Number of keys currently loaded",
    registry=REGISTRY,
    multiprocess_mode="max",
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
        self._httpd: WSGIServer | ThreadingHTTPServer | None = None
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
            # start_http_server returns a tuple of (server, thread)
            server, _ = start_http_server(
                port=self._port,
                addr=self._host,
                registry=REGISTRY,
            )
            self._httpd = server
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
