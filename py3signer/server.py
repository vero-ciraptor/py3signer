"""Litestar server setup with Granian ASGI server."""

from __future__ import annotations

import logging
import os
import tempfile
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

# Set up multi-process metrics BEFORE importing anything that uses prometheus_client
# This must be done early so both main process and workers use the same setup
# Default to 4 workers for multi-process mode (can be overridden by PY3SIGNER_WORKERS env var)
_workers_env = os.environ.get("PY3SIGNER_WORKERS", "4")
_workers = int(_workers_env)
if _workers > 1:
    # Set the env var so workers can also see it
    os.environ["PY3SIGNER_WORKERS"] = str(_workers)
    if not os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
        _temp_dir = tempfile.mkdtemp(prefix="py3signer_metrics_")
        os.environ["PROMETHEUS_MULTIPROC_DIR"] = _temp_dir

from granian import Granian  # noqa: E402
from granian.constants import Interfaces  # noqa: E402
from litestar import Litestar  # noqa: E402
from litestar.datastructures import State  # noqa: E402, TC002
from litestar.di import Provide  # noqa: E402

from .bulk_loader import load_external_keystores  # noqa: E402
from .handlers import get_routers  # noqa: E402
from .signer import Signer  # noqa: E402
from .storage import KeyStorage  # noqa: E402

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator
    from pathlib import Path

    from .config import Config

logger = logging.getLogger(__name__)


# Dependency providers for Litestar DI


def provide_storage(state: State) -> KeyStorage:
    """Provide KeyStorage from application state.

    This dependency provider allows handlers to receive KeyStorage
    via dependency injection instead of accessing request.app.state directly.
    """
    result: KeyStorage = state["storage"]
    return result


def provide_signer(state: State) -> Signer:
    """Provide Signer from application state.

    This dependency provider allows handlers to receive Signer
    via dependency injection instead of accessing request.app.state directly.
    """
    result: Signer = state["signer"]
    return result


def _load_managed_keystores(
    directory: Path,
    storage: KeyStorage,
) -> tuple[int, int]:
    """Load all managed keystores from a directory into storage.

    Each .json keystore file must have a matching .txt file with the same base name
    containing the plaintext password.

    Args:
        directory: Path to directory containing keystore files
        storage: KeyStorage instance to load keys into

    Returns:
        Tuple of (success_count, failure_count)

    """
    from .bulk_loader import load_keystore_with_password, scan_keystore_directory
    from .keystore import KeystoreError

    keystores = scan_keystore_directory(directory)

    success_count = 0
    failure_count = 0

    for base_name, keystore_path in keystores.items():
        password_path = keystore_path.with_suffix(".txt")

        try:
            result = load_keystore_with_password(
                keystore_path,
                password_path,
            )

            # Add as managed key (already in managed storage)
            storage.add_key(
                result.pubkey,
                result.secret_key,
                result.path,
                result.description,
                keystore_json=keystore_path.read_text(),
                password=result.password,
            )

            logger.info(f"Loaded managed keystore: {base_name}")
            success_count += 1
        except KeystoreError as e:
            logger.error(f"Failed to load keystore {base_name}: {e}")
            failure_count += 1
        except ValueError as e:
            logger.error(f"Failed to add keystore {base_name} to storage: {e}")
            failure_count += 1
        except Exception as e:
            logger.error(f"Unexpected error loading keystore {base_name}: {e}")
            failure_count += 1

    logger.info(
        f"Managed keystore loading complete: {success_count} succeeded, {failure_count} failed",
    )
    return success_count, failure_count


def create_app(
    config: Config | None = None,
    storage: KeyStorage | None = None,
    signer: Signer | None = None,
) -> Litestar:
    """Create and configure the Litestar application."""
    # If config is provided but storage/signer are not, create them
    if config is not None and (storage is None or signer is None):
        storage = KeyStorage(
            data_dir=config.data_dir,
            external_keystores_path=config.keystores_path,
        )
        signer = Signer(storage)

        # Load keystores from managed storage (data_dir/keystores) - API imported keys
        if config.data_dir:
            keystores_dir = config.data_dir / "keystores"
            if keystores_dir.exists():
                success, failures = _load_managed_keystores(
                    keystores_dir,
                    storage,
                )
                logger.info(f"Loaded {success} keystores from managed storage")
                if failures > 0:
                    logger.warning(f"Failed to load {failures} keystores")
            else:
                logger.info(
                    f"Managed keystores directory does not exist yet: {keystores_dir}"
                )

        # Load external keystores from --keystores-path (NOT copied to managed storage)
        if config.keystores_path and config.keystores_passwords_path:
            logger.info(
                f"Loading external keystores from {config.keystores_path} "
                f"(keys stay in external location, NOT copied)"
            )
            success, failures = load_external_keystores(
                config.keystores_path,
                config.keystores_passwords_path,
                storage,
            )
            logger.info(f"Loaded {success} external keystores")
            if failures > 0:
                logger.warning(f"Failed to load {failures} external keystores")

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

    # Create the Litestar app with dependency injection
    # Use State for storing instances, but provide them via DI
    from litestar.datastructures import State

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
        dependencies={
            "storage": Provide(provide_storage, sync_to_thread=False),
            "signer": Provide(provide_signer, sync_to_thread=False),
        },
    )


async def run_server(config: Config) -> None:
    """Run the Litestar server with Granian."""
    logger.info(f"Starting py3signer on {config.host}:{config.port}")

    # Run with Granian ASGI using factory pattern for multi-worker support
    # Use env var if set (already set at import time), otherwise use config or default to 4
    workers = int(
        os.environ.get("PY3SIGNER_WORKERS", getattr(config, "workers", 4) or 4)
    )

    # Set workers env var BEFORE anything else (metrics uses this for multiproc mode)
    os.environ["PY3SIGNER_WORKERS"] = str(workers)

    # Set up multi-process metrics directory BEFORE importing asgi/metrics
    # This must happen in the main process so the metrics server can read worker data
    if workers > 1:
        from .metrics import setup_multiproc_dir

        multiproc_dir = setup_multiproc_dir()
        logger.info(
            f"Enabled Prometheus multi-process metrics mode ({workers} workers, dir={multiproc_dir})"
        )

    # Import asgi module to store config
    from . import asgi

    asgi.store_config_in_env(config)

    # Now import metrics (after setting workers env var and multiproc dir)
    from .metrics import MetricsServer, cleanup_multiproc_dir

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

    # Clean up any stale metrics files before starting
    cleanup_multiproc_dir()

    # Start metrics server in the main process (not workers)
    metrics_server = MetricsServer(host=config.metrics_host, port=config.metrics_port)
    metrics_server.start()

    try:
        server.serve()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        metrics_server.stop()
