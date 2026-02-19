"""Prometheus metrics for py3signer.

This module defines and exposes all Prometheus metrics used by py3signer.
Metrics are opt-in and only collected when --metrics-enabled is set.

For multi-worker (gunicorn) deployments, set PROMETHEUS_MULTIPROC_DIR to a
writable directory for metrics aggregation across workers.
"""

import logging
import os
import time
from collections.abc import Awaitable, Callable

from aiohttp import web
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    Info,
    generate_latest,
)

# Try to import multiprocess support for gunicorn
try:
    from prometheus_client import multiprocess

    MULTIPROC_SUPPORT = True
except ImportError:
    MULTIPROC_SUPPORT = False

logger = logging.getLogger(__name__)


def get_registry() -> CollectorRegistry:
    """Get the appropriate registry for the current deployment mode.
    
    In multi-worker (gunicorn) mode with PROMETHEUS_MULTIPROC_DIR set,
    returns a multi-process registry. Otherwise returns the default registry.
    """
    if MULTIPROC_SUPPORT and os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
        return CollectorRegistry()
    return CollectorRegistry()


# Create the registry
REGISTRY = get_registry()

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
    # In multi-process mode, use the multiprocess collector
    if MULTIPROC_SUPPORT and os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)
        return generate_latest(registry)
    return generate_latest(REGISTRY)


def get_metrics_content_type() -> str:
    """Get the content type for Prometheus metrics."""
    return CONTENT_TYPE_LATEST


# HTTP middleware for tracking metrics


@web.middleware
async def metrics_middleware(
    request: web.Request, handler: Callable[[web.Request], Awaitable[web.StreamResponse]]
) -> web.StreamResponse:
    """Middleware to track HTTP request metrics."""
    start_time = time.perf_counter()
    status = "500"

    try:
        response = await handler(request)
        status = str(response.status)
        return response
    except web.HTTPException as e:
        status = str(e.status)
        raise
    finally:
        duration = time.perf_counter() - start_time

        # Get the route path pattern if available
        if request.match_info.route and request.match_info.route.resource:
            endpoint = request.match_info.route.resource.canonical
        else:
            # Fallback: sanitize path to prevent high cardinality
            endpoint = request.path
            parts = endpoint.rstrip("/").split("/")
            if parts and len(parts[-1]) > 20:
                parts[-1] = "{identifier}"
                endpoint = "/".join(parts)

        HTTP_REQUEST_DURATION_SECONDS.labels(method=request.method, endpoint=endpoint).observe(
            duration
        )
        HTTP_REQUESTS_TOTAL.labels(method=request.method, endpoint=endpoint, status=status).inc()


def setup_metrics_middleware(app: web.Application) -> None:
    """Add metrics middleware to the application."""
    app.middlewares.append(metrics_middleware)


# Metrics HTTP server


async def metrics_handler(request: web.Request) -> web.Response:
    """Handler for the /metrics endpoint."""
    return web.Response(
        body=get_metrics_output(), headers={"Content-Type": get_metrics_content_type()}
    )


async def metrics_health_handler(request: web.Request) -> web.Response:
    """Health check for metrics server."""
    return web.json_response({"status": "healthy"})


def create_metrics_app() -> web.Application:
    """Create the metrics application."""
    app = web.Application()
    app.router.add_get("/metrics", metrics_handler)
    app.router.add_get("/health", metrics_health_handler)
    return app


class MetricsServer:
    """Prometheus metrics HTTP server."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8081) -> None:
        self._host = host
        self._port = port
        self._runner: web.AppRunner | None = None

    async def start(self) -> None:
        """Start the metrics server."""
        app = create_metrics_app()
        self._runner = web.AppRunner(app)
        await self._runner.setup()

        site = web.TCPSite(self._runner, host=self._host, port=self._port)
        await site.start()

        logger.info(f"Metrics server running at http://{self._host}:{self._port}/metrics")

    async def stop(self) -> None:
        """Stop the metrics server."""
        if self._runner:
            await self._runner.cleanup()
            logger.info("Metrics server stopped")

    async def __aenter__(self) -> "MetricsServer":
        await self.start()
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.stop()
