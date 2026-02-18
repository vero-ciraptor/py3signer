"""aiohttp server setup."""

import asyncio
import logging
import ssl

from aiohttp import web

from .bulk_loader import load_keystores_from_directory
from .config import Config
from .handlers import APIHandler, setup_routes
from .metrics_middleware import setup_metrics_middleware
from .metrics_server import MetricsServer
from .signer import Signer
from .storage import KeyStorage

logger = logging.getLogger(__name__)

# Typed app keys to avoid NotAppKeyWarning
APP_KEY_STORAGE: web.AppKey[KeyStorage] = web.AppKey("storage", KeyStorage)
APP_KEY_SIGNER: web.AppKey[Signer] = web.AppKey("signer", Signer)


def create_app(config: Config) -> web.Application:
    """Create and configure the aiohttp application."""
    # Create components
    storage = KeyStorage()
    signer = Signer(storage)
    handler = APIHandler(storage, signer, auth_token=config.auth_token)

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
    """Run the aiohttp server."""
    logger.info(f"Starting py3signer on {config.host}:{config.port}")

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

    # Start metrics server if enabled
    metrics_server: MetricsServer | None = None
    if config.metrics_enabled:
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
        if metrics_server:
            await metrics_server.stop()
        await runner.cleanup()
