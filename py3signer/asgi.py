"""ASGI entry point for Granian multi-worker support.

This module provides the ASGI application for Granian.
Configuration is loaded from environment variables set by the main process.
"""

import json
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

import msgspec

from .config import Config

# Set up multi-process metrics BEFORE importing anything that uses prometheus_client
# This must happen before server/storage/metrics imports
_config = json.loads(os.environ.get("PY3SIGNER_CONFIG", "{}"))
_workers = _config.get("workers", 1)
if _workers > 1:
    from .metrics import setup_multiproc_dir

    setup_multiproc_dir()

from .server import create_app  # noqa: E402

if TYPE_CHECKING:
    from collections.abc import Callable

    from litestar import Litestar
    from litestar.types import LifeSpanScope, Scope

logger = logging.getLogger(__name__)


def load_config_from_env() -> Config | None:
    """Load configuration from environment variable."""
    config_json = os.environ.get("PY3SIGNER_CONFIG")
    if not config_json:
        return None

    try:
        config_dict = json.loads(config_json)
        # Convert string paths back to Path objects
        if config_dict.get("data_dir"):
            config_dict["data_dir"] = Path(config_dict["data_dir"])
        if config_dict.get("keystores_path"):
            config_dict["keystores_path"] = Path(config_dict["keystores_path"])
        if config_dict.get("keystores_passwords_path"):
            config_dict["keystores_passwords_path"] = Path(
                config_dict["keystores_passwords_path"],
            )
        return msgspec.convert(config_dict, Config)
    except Exception as e:
        logger.error(f"Failed to load config from environment: {e}")
        return None


def store_config_in_env(config: Config) -> None:
    """Store configuration in environment variable for worker processes."""
    config_dict = {
        "host": config.host,
        "port": config.port,
        "log_level": config.log_level,
        "metrics_host": config.metrics_host,
        "metrics_port": config.metrics_port,
        "data_dir": str(config.data_dir) if config.data_dir else None,
        "keystores_path": str(config.keystores_path) if config.keystores_path else None,
        "keystores_passwords_path": (
            str(config.keystores_passwords_path)
            if config.keystores_passwords_path
            else None
        ),
        "workers": config.workers,
    }
    os.environ["PY3SIGNER_CONFIG"] = json.dumps(config_dict)


# Global app instance (created once per worker)
_app_instance: Litestar | None = None


def get_app() -> Litestar:
    """Get or create the Litestar app instance."""
    global _app_instance
    if _app_instance is None:
        config = load_config_from_env()
        if config is None:
            raise RuntimeError(
                "Configuration not found. Use 'python -m py3signer' to start the server properly.",
            )

        # Setup logging
        logging.basicConfig(
            level=getattr(logging, config.normalized_log_level),
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )

        _app_instance = create_app(config)

    return _app_instance


# ASGI application callable
# Granian calls this with (scope, receive, send)
async def app(
    scope: Scope | LifeSpanScope,
    receive: Callable[..., Any],
    send: Callable[..., Any],
) -> None:
    """ASGI application entry point."""
    litestar_app = get_app()
    await litestar_app(scope, receive, send)
