"""Litestar server setup with Granian ASGI server."""

import logging
import multiprocessing
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from granian import Granian
from granian.constants import Interfaces
from litestar import Litestar
from litestar.datastructures import State

from .bulk_loader import (
    import_keystores_from_separate_directories,
    load_keystores_from_directory,
)
from .handlers import get_routers
from .metrics import MetricsServer
from .signer import Signer
from .storage import KeyStorage

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from .config import Config

logger = logging.getLogger(__name__)


def create_app(
    config: Config | None = None,
    storage: KeyStorage | None = None,
    signer: Signer | None = None,
) -> Litestar:
    """Create and configure the Litestar application."""
    # If config is provided but storage/signer are not, create them
    if config is not None and (storage is None or signer is None):
        storage = KeyStorage(data_dir=config.data_dir)
        signer = Signer(storage)

        # Load keystores from unified storage (data_dir/keystores)
        if config.data_dir:
            keystores_dir = config.data_dir / "keystores"
            if keystores_dir.exists():
                success, failures = load_keystores_from_directory(
                    keystores_dir,
                    storage,
                )
                logger.info(f"Loaded {success} keystores from {keystores_dir}")
                if failures > 0:
                    logger.warning(f"Failed to load {failures} keystores")
            else:
                logger.info(f"Keystores directory does not exist yet: {keystores_dir}")

        # Import keystores from --keystores-path (if provided)
        # These are imported (copied) to the unified storage location
        if config.keystores_path and config.keystores_passwords_path:
            # If data_dir is set, import to unified storage
            if config.data_dir:
                logger.info(
                    f"Importing keystores from {config.keystores_path} "
                    f"to unified storage at {config.data_dir / 'keystores'}"
                )
                success, failures = import_keystores_from_separate_directories(
                    config.keystores_path,
                    config.keystores_passwords_path,
                    storage,
                )
                logger.info(f"Imported {success} keystores from external path")
                if failures > 0:
                    logger.warning(f"Failed to import {failures} keystores")
            else:
                # No data_dir - load without persistence (backward compatibility)
                logger.warning(
                    "No --data-dir configured, loading keystores without persistence"
                )
                success, failures = load_keystores_from_directory(
                    config.keystores_path,
                    storage,
                )
                logger.info(f"Loaded {success} keystores (no persistence)")
                if failures > 0:
                    logger.warning(f"Failed to load {failures} keystores")

    # Fallback for when storage/signer are passed directly (e.g., tests)
    if storage is None:
        storage = KeyStorage()
    if signer is None:
        signer = Signer(storage)

    @asynccontextmanager
    async def lifespan(_app: Litestar) -> AsyncGenerator[None]:
        """Lifespan context manager for startup/shutdown."""
        logger.info("Starting py3signer server")
        yield
        logger.info("Stopping py3signer server")

    # Create the Litestar app
    return Litestar(
        route_handlers=get_routers(),
        lifespan=[lifespan],
        debug=False,
        state=State(
            {
                "storage": storage,
                "signer": signer,
            },
        ),
    )


async def run_server(config: Config) -> None:
    """Run the Litestar server with Granian."""
    logger.info(f"Starting py3signer on {config.host}:{config.port}")

    # Import asgi module to store config
    from . import asgi

    asgi.store_config_in_env(config)

    # Run with Granian ASGI using factory pattern for multi-worker support
    workers = getattr(config, "workers", multiprocessing.cpu_count())

    # Map py3signer log levels to Granian log levels
    granian_log_level = config.log_level.lower()

    server = Granian(
        target="py3signer.asgi:app",
        address=config.host,
        port=config.port,
        interface=Interfaces.ASGI,
        workers=workers,
        log_level=granian_log_level,
    )

    # Start metrics server in the main process (not workers)
    metrics_server = MetricsServer(host=config.metrics_host, port=config.metrics_port)
    metrics_server.start()

    try:
        server.serve()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        metrics_server.stop()
