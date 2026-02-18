"""aiohttp middleware for Prometheus metrics.

This module provides middleware for tracking HTTP request metrics.
"""

import time
import logging
from typing import Callable, Awaitable

from aiohttp import web

from .metrics import HTTP_REQUESTS_TOTAL, HTTP_REQUEST_DURATION_SECONDS

logger = logging.getLogger(__name__)


@web.middleware
async def metrics_middleware(
    request: web.Request,
    handler: Callable[[web.Request], Awaitable[web.StreamResponse]]
) -> web.StreamResponse:
    """Middleware to track HTTP request metrics.
    
    Tracks:
    - Total requests by method, endpoint pattern, and status code
    - Request duration by method and endpoint pattern
    
    Note: The endpoint label uses the route path pattern (e.g., "/api/v1/eth2/sign/{identifier}")
    rather than the actual URL to prevent cardinality explosion.
    """
    start_time = time.perf_counter()
    
    try:
        response = await handler(request)
        status = str(response.status)
    except web.HTTPException as e:
        status = str(e.status)
        raise
    finally:
        duration = time.perf_counter() - start_time
        
        # Get the route path pattern if available, otherwise use the path
        if request.match_info.route and request.match_info.route.resource:
            endpoint = request.match_info.route.resource.canonical  # e.g., "/api/v1/eth2/sign/{identifier}"
        else:
            # Fallback to the path, but sanitize to prevent high cardinality
            endpoint = request.path
            # Remove potential identifiers from path
            parts = endpoint.rstrip("/").split("/")
            if parts and len(parts[-1]) > 20:
                # Likely a pubkey or identifier, replace with placeholder
                parts[-1] = "{identifier}"
                endpoint = "/".join(parts)
        
        method = request.method
        
        # Track request duration
        HTTP_REQUEST_DURATION_SECONDS.labels(
            method=method,
            endpoint=endpoint
        ).observe(duration)
        
        # Track request count
        HTTP_REQUESTS_TOTAL.labels(
            method=method,
            endpoint=endpoint,
            status=status
        ).inc()
    
    return response


def setup_metrics_middleware(app: web.Application) -> None:
    """Add metrics middleware to the application.
    
    Note: This should be called after all routes are registered so that
    the route info is available in the middleware.
    """
    app.middlewares.append(metrics_middleware)
