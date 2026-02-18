"""CLI entry point for py3signer."""

import asyncio
import logging
import sys

from .server import run_server
from .config import get_config


def setup_logging(log_level: str) -> None:
    """Configure logging."""
    logging.basicConfig(
        level=getattr(logging, log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )


def main() -> None:
    """Main entry point."""
    try:
        config = get_config()
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    
    setup_logging(config.normalized_log_level)
    
    try:
        asyncio.run(run_server(config))
    except KeyboardInterrupt:
        print("\nShutting down...")
        sys.exit(0)
    except Exception:
        logging.getLogger(__name__).exception("Server error")
        sys.exit(1)


if __name__ == "__main__":
    main()
