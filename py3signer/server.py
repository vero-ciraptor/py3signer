"""Litestar server setup with Granian ASGI server."""

import logging
import ssl
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from litestar import Litestar

from .bulk_loader import load_input_only_keystores, load_keystores_from_directory
from .config import Config
from .handlers import get_routers
from .signer import Signer
from .storage import KeyStorage

logger = logging.getLogger(__name__)


def create_app(
    config: Config | None = None,
    storage: KeyStorage | None = None,
    signer: Signer | None = None,
) -> Litestar:
    """Create and configure the Litestar application."""

    # If config is provided but storage/signer are not, create them
    if config is not None and (storage is None or signer is None):
        storage = KeyStorage(keystore_path=config.key_store_path)
        signer = Signer(storage)

        # Load keystores from key_store_path if configured (persistent keystores)
        if config.key_store_path:
            success, failures = load_keystores_from_directory(config.key_store_path, storage)
            logger.info(f"Loaded {success} keystores from {config.key_store_path}")
            if failures > 0:
                logger.warning(f"Failed to load {failures} keystores")

        # Load input-only keystores from separate directories if configured
        if config.keystores_path and config.keystores_passwords_path:
            success, failures = load_input_only_keystores(
                config.keystores_path, config.keystores_passwords_path, storage
            )
            logger.info(f"Loaded {success} input-only keystores from {config.keystores_path}")
            if failures > 0:
                logger.warning(f"Failed to load {failures} input-only keystores")

    # Fallback for when storage/signer are passed directly (e.g., tests)
    if storage is None:
        storage = KeyStorage()
    if signer is None:
        signer = Signer(storage)

    auth_token = config.auth_token if config else None

    @asynccontextmanager
    async def lifespan(app: Litestar) -> AsyncGenerator[None, None]:
        """Lifespan context manager for startup/shutdown."""
        logger.info("Starting py3signer server")
        yield
        logger.info("Stopping py3signer server")

    # Create the Litestar app
    app = Litestar(
        route_handlers=get_routers(),
        lifespan=[lifespan],
        debug=False,
        state={
            "storage": storage,
            "signer": signer,
            "auth_token": auth_token,
        },
    )

    return app


async def run_server(config: Config) -> None:
    """Run the Litestar server with Granian."""
    logger.info(f"Starting py3signer on {config.host}:{config.port}")

    # Create app
    app = create_app(config)

    # Setup SSL if configured
    ssl_context: ssl.SSLContext | None = None
    if config.tls_cert and config.tls_key:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(str(config.tls_cert), str(config.tls_key))
        logger.info("TLS enabled")

    # Import Granian
    from granian import Granian
    from granian.constants import Interfaces

    # Run with Granian ASGI
    server = Granian(
        target=app,
        address=config.host,
        port=config.port,
        interface=Interfaces.ASGI,
        ssl_context=ssl_context,
        workers=1,  # Default to single worker for now
    )

    protocol = "https" if ssl_context else "http"
    logger.info(f"Server running at {protocol}://{config.host}:{config.port}")
    logger.info("Press Ctrl+C to stop")

    try:
        server.serve()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
