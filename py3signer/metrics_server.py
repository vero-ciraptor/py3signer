"""Prometheus metrics HTTP server.

This module provides a separate aiohttp server for exposing Prometheus metrics
on a dedicated port.
"""

import asyncio
import logging
from aiohttp import web

from .metrics import get_metrics_output, get_metrics_content_type

logger = logging.getLogger(__name__)


async def metrics_handler(request: web.Request) -> web.Response:
    """Handler for the /metrics endpoint."""
    return web.Response(
        body=get_metrics_output(),
        headers={"Content-Type": get_metrics_content_type()}
    )


async def health_handler(request: web.Request) -> web.Response:
    """Health check for metrics server."""
    return web.json_response({"status": "healthy"})


def create_metrics_app() -> web.Application:
    """Create the metrics application."""
    app = web.Application()
    app.router.add_get("/metrics", metrics_handler)
    app.router.add_get("/health", health_handler)
    return app


class MetricsServer:
    """Prometheus metrics HTTP server."""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8081) -> None:
        self._host = host
        self._port = port
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None
        self._logger = logging.getLogger(__name__)
    
    async def start(self) -> None:
        """Start the metrics server."""
        app = create_metrics_app()
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        
        self._site = web.TCPSite(self._runner, host=self._host, port=self._port)
        await self._site.start()
        
        self._logger.info(f"Metrics server running at http://{self._host}:{self._port}/metrics")
    
    async def stop(self) -> None:
        """Stop the metrics server."""
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
            self._site = None
            self._logger.info("Metrics server stopped")
    
    async def __aenter__(self) -> "MetricsServer":
        await self.start()
        return self
    
    async def __aexit__(self, *args: object) -> None:
        await self.stop()
