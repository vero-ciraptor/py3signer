"""Gunicorn application factory for py3signer."""

import asyncio
import logging

from aiohttp import web

from py3signer.bulk_loader import load_input_only_keystores, load_keystores_from_directory
from py3signer.config import Config, get_config
from py3signer.handlers import APIHandler, setup_routes
from py3signer.metrics import (
    get_metrics_content_type,
    get_metrics_output,
    setup_metrics_middleware,
)
from py3signer.signer import Signer
from py3signer.storage import KeyStorage

logger = logging.getLogger(__name__)

# Typed app keys
APP_KEY_STORAGE: web.AppKey[KeyStorage] = web.AppKey("storage", KeyStorage)
APP_KEY_SIGNER: web.AppKey[Signer] = web.AppKey("signer", Signer)


def setup_logging(log_level: str) -> None:
    """Configure logging."""
    logging.basicConfig(
        level=getattr(logging, log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


async def metrics_handler(request: web.Request) -> web.Response:
    """Handler for Prometheus metrics endpoint."""
    return web.Response(
        body=get_metrics_output(),
        headers={"Content-Type": get_metrics_content_type()},
    )


def create_aiohttp_app(config: Config | None = None) -> web.Application:
    """Create and configure the aiohttp application for gunicorn."""
    if config is None:
        config = get_config()

    setup_logging(config.normalized_log_level)

    # Create components
    storage = KeyStorage(keystore_path=config.key_store_path)
    signer = Signer(storage)
    handler = APIHandler(storage, signer, auth_token=config.auth_token)

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

    # Create app
    app = web.Application()

    # Store components in app
    app[APP_KEY_STORAGE] = storage
    app[APP_KEY_SIGNER] = signer

    # Setup routes
    setup_routes(app, handler)

    # Add metrics endpoint to main app (for gunicorn multi-worker compatibility)
    app.router.add_get("/metrics", metrics_handler)

    # Setup metrics middleware
    setup_metrics_middleware(app)

    return app


# Gunicorn entry point - expects a factory function
def app_factory() -> web.Application:
    """Factory function for gunicorn with aiohttp worker."""
    return create_aiohttp_app()


# For gunicorn config as a callable module
def create_app() -> web.Application:
    """Alternative factory name for gunicorn."""
    return create_aiohttp_app()
