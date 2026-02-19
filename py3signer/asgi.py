"""ASGI entry point for Granian.

This module provides the ASGI application for Granian server.
The app is lazily initialized on first request to load configuration.
"""

import logging
import os
from pathlib import Path

from litestar import Litestar

from .config import Config
from .server import create_app

logger = logging.getLogger(__name__)

# Global app instance (lazily initialized)
_litestar_app: Litestar | None = None


def _load_config_from_env() -> Config:
    """Load configuration from environment variables."""
    kwargs: dict = {}

    if host := os.environ.get("PY3SIGNER_HOST"):
        kwargs["host"] = host
    if port := os.environ.get("PY3SIGNER_PORT"):
        kwargs["port"] = int(port)
    if tls_cert := os.environ.get("PY3SIGNER_TLS_CERT"):
        kwargs["tls_cert"] = Path(tls_cert)
    if tls_key := os.environ.get("PY3SIGNER_TLS_KEY"):
        kwargs["tls_key"] = Path(tls_key)
    if log_level := os.environ.get("PY3SIGNER_LOG_LEVEL"):
        kwargs["log_level"] = log_level
    if auth_token := os.environ.get("PY3SIGNER_AUTH_TOKEN"):
        kwargs["auth_token"] = auth_token
    if key_store_path := os.environ.get("PY3SIGNER_KEY_STORE_PATH"):
        kwargs["key_store_path"] = Path(key_store_path)
    if keystores_path := os.environ.get("PY3SIGNER_KEYSTORES_PATH"):
        kwargs["keystores_path"] = Path(keystores_path)
    if keystores_passwords_path := os.environ.get("PY3SIGNER_KEYSTORES_PASSWORDS_PATH"):
        kwargs["keystores_passwords_path"] = Path(keystores_passwords_path)

    return Config(**kwargs)


def _get_app() -> Litestar:
    """Get or create the Litestar application."""
    global _litestar_app

    if _litestar_app is None:
        # Setup basic logging
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )

        # Load configuration from environment
        config = _load_config_from_env()
        logger.info(f"Loaded configuration: host={config.host}, port={config.port}")

        # Create the app
        _litestar_app = create_app(config)

    return _litestar_app


async def app(scope, receive, send):
    """ASGI application entry point.

    This is called by Granian and delegates to the Litestar app.
    """
    litestar_app = _get_app()
    await litestar_app(scope, receive, send)
