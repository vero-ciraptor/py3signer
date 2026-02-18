"""aiohttp server setup."""

import asyncio
import logging
import ssl
from pathlib import Path

from aiohttp import web

from .config import Config
from .storage import KeyStorage
from .signer import Signer
from .handlers import APIHandler, setup_routes

logger = logging.getLogger(__name__)


def create_app(config: Config) -> web.Application:
    """Create and configure the aiohttp application."""
    # Create components
    storage = KeyStorage()
    signer = Signer(storage)
    handler = APIHandler(storage, signer, auth_token=config.auth_token)
    
    # Create app
    app = web.Application()
    
    # Store components in app for access
    app["storage"] = storage
    app["signer"] = signer
    
    # Setup routes
    setup_routes(app, handler)
    
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
    
    site = web.TCPSite(
        runner,
        host=config.host,
        port=config.port,
        ssl_context=ssl_context
    )
    
    await site.start()
    
    protocol = "https" if ssl_context else "http"
    logger.info(f"Server running at {protocol}://{config.host}:{config.port}")
    logger.info("Press Ctrl+C to stop")
    
    # Keep running
    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        pass
    finally:
        await runner.cleanup()
