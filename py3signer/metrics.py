"""Prometheus metrics for py3signer.

This module defines and exposes all Prometheus metrics used by py3signer.
Metrics are opt-in and only collected when --metrics-enabled is set.
"""

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    Info,
    generate_latest,
)

# Create a dedicated registry for py3signer metrics
REGISTRY = CollectorRegistry()

# Application info
APP_INFO = Info(
    "py3signer_build_info",
    "Build information about py3signer",
    registry=REGISTRY,
)
APP_INFO.info(
    {
        "version": "0.1.0",
        "name": "py3signer",
    }
)

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


def get_metrics_output():
    """Generate Prometheus-formatted metrics output."""
    return generate_latest(REGISTRY)


def get_metrics_content_type():
    """Get the content type for Prometheus metrics."""
    return CONTENT_TYPE_LATEST
