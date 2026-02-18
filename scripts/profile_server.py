#!/usr/bin/env python3
"""aiohttp server setup with profiling support."""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import asyncio
import logging
import ssl

from aiohttp import web

from py3signer.bulk_loader import load_keystores_from_directory
from py3signer.config import Config
from py3signer.handlers_profiled import ProfilingAPIHandler, setup_routes
from py3signer.metrics import MetricsServer, setup_metrics_middleware
from py3signer.signer import Signer
from py3signer.storage import KeyStorage

logger = logging.getLogger(__name__)

# Typed app keys to avoid NotAppKeyWarning
APP_KEY_STORAGE: web.AppKey[KeyStorage] = web.AppKey("storage", KeyStorage)
APP_KEY_SIGNER: web.AppKey[Signer] = web.AppKey("signer", Signer)


def create_app(config: Config) -> web.Application:
    """Create and configure the aiohttp application with profiling."""
    # Create components
    storage = KeyStorage(keystore_path=config.key_store_path)
    signer = Signer(storage)
    handler = ProfilingAPIHandler(storage, signer, auth_token=config.auth_token)

    # Load keystores from directory if configured
    if config.key_store_path:
        success, failures = load_keystores_from_directory(config.key_store_path, storage)
        logger.info(f"Loaded {success} keystores from {config.key_store_path}")
        if failures > 0:
            logger.warning(f"Failed to load {failures} keystores")

    # Create app
    app = web.Application()

    # Store components in app for access using typed AppKey
    app[APP_KEY_STORAGE] = storage
    app[APP_KEY_SIGNER] = signer

    # Setup routes
    setup_routes(app, handler)

    # Setup metrics middleware (after routes are registered)
    setup_metrics_middleware(app)

    return app


async def run_server(config: Config) -> None:
    """Run the aiohttp server with profiling enabled."""
    logger.info(f"Starting py3signer (with profiling) on {config.host}:{config.port}")

    # Create app
    app = create_app(config)

    # Setup SSL if configured
    ssl_context: ssl.SSLContext | None = None
    if config.tls_cert and config.tls_key:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(str(config.tls_cert), str(config.tls_key))
        logger.info("TLS enabled")

    # Run server
    runner = web.AppRunner(app)
    await runner.setup()

    site = web.TCPSite(runner, host=config.host, port=config.port, ssl_context=ssl_context)

    await site.start()

    protocol = "https" if ssl_context else "http"
    logger.info(f"Server running at {protocol}://{config.host}:{config.port}")
    logger.info("PROFILING MODE: Sign endpoint returns timing data in _profile field")

    # Start metrics server if enabled
    metrics_server = MetricsServer(host=config.metrics_host, port=config.metrics_port)
    await metrics_server.start()

    logger.info("Press Ctrl+C to stop")

    # Keep running
    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        pass
    finally:
        await metrics_server.stop()
        await runner.cleanup()


if __name__ == "__main__":
    from py3signer.config import Config
    import argparse

    parser = argparse.ArgumentParser(description="Run py3signer with profiling")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind to")
    parser.add_argument("--keystore-path", help="Path to keystores")

    args = parser.parse_args()

    config = Config(
        host=args.host,
        port=args.port,
        key_store_path=args.keystore_path,
    )

    try:
        asyncio.run(run_server(config))
    except KeyboardInterrupt:
        logger.info("Server stopped")
