"""Configuration management using msgspec Struct."""

import argparse
import multiprocessing
from pathlib import Path

import msgspec


class Config(msgspec.Struct, frozen=True):
    """Application configuration using msgspec Struct."""

    # HTTP server settings
    host: str = "127.0.0.1"
    port: int = 8080

    # Logging
    log_level: str = "INFO"

    # Metrics settings
    metrics_host: str = "127.0.0.1"
    metrics_port: int = 8081

    # Keystore settings
    data_dir: Path | None = None

    # Input-only keystore directories (not persisted)
    keystores_path: Path | None = None
    keystores_passwords_path: Path | None = None

    # Worker settings
    workers: int = multiprocessing.cpu_count()

    def __post_init__(self) -> None:
        """Validate configuration after initialization."""
        # msgspec handles basic type validation, but we need custom validation
        if self.port < 1 or self.port > 65535:
            raise ValueError(f"port must be between 1 and 65535, got {self.port}")

        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if self.log_level.upper() not in valid_levels:
            raise ValueError(
                f"log_level must be one of {valid_levels}, got {self.log_level}",
            )

        # Validate metrics port
        if self.metrics_port < 1 or self.metrics_port > 65535:
            raise ValueError(
                f"metrics_port must be between 1 and 65535, got {self.metrics_port}",
            )

        # Validate data_dir if provided
        if self.data_dir is not None:
            if not self.data_dir.exists():
                raise ValueError(
                    f"data_dir does not exist: {self.data_dir}",
                )
            if not self.data_dir.is_dir():
                raise ValueError(
                    f"data_dir must be a directory: {self.data_dir}",
                )

        # Validate input-only keystore paths
        if self.keystores_path is not None and self.keystores_passwords_path is None:
            raise ValueError(
                "--keystores-passwords-path must be provided when --keystores-path is set",
            )
        if self.keystores_passwords_path is not None and self.keystores_path is None:
            raise ValueError(
                "--keystores-path must be provided when --keystores-passwords-path is set",
            )

        if self.keystores_path is not None:
            if not self.keystores_path.exists():
                raise ValueError(
                    f"keystores_path does not exist: {self.keystores_path}",
                )
            if not self.keystores_path.is_dir():
                raise ValueError(
                    f"keystores_path must be a directory: {self.keystores_path}",
                )

        if self.keystores_passwords_path is not None:
            if not self.keystores_passwords_path.exists():
                raise ValueError(
                    f"keystores_passwords_path does not exist: {self.keystores_passwords_path}",
                )
            if not self.keystores_passwords_path.is_dir():
                raise ValueError(
                    f"keystores_passwords_path must be a directory: {self.keystores_passwords_path}",
                )

        # Validate workers
        if self.workers < 1:
            raise ValueError(f"workers must be at least 1, got {self.workers}")

    @property
    def normalized_log_level(self) -> str:
        """Return normalized uppercase log level."""
        return self.log_level.upper()


def get_config() -> Config:
    """Parse command line arguments and return configuration."""
    parser = argparse.ArgumentParser(
        description="py3signer - A Remote BLS Signer for Ethereum",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="HTTP server host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=8080,
        help="HTTP server port (default: 8080)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Logging level (default: INFO)",
    )
    parser.add_argument(
        "--metrics-port",
        type=int,
        default=8081,
        help="Port for metrics server (default: 8081)",
    )
    parser.add_argument(
        "--metrics-host",
        default="127.0.0.1",
        help="Host for metrics server (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help="Path to directory containing keystores (matching .json files with .txt password files)",
    )
    parser.add_argument(
        "--keystores-path",
        type=Path,
        default=None,
        help="Path to directory containing input-only keystore .json files (not persisted)",
    )
    parser.add_argument(
        "--keystores-passwords-path",
        type=Path,
        default=None,
        help="Path to directory containing input-only password .txt files (not persisted)",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=multiprocessing.cpu_count(),
        help=f"Number of worker processes (default: {multiprocessing.cpu_count()})",
    )

    args = parser.parse_args()

    # Build config dict from CLI arguments
    config_dict: dict[str, object] = {
        "host": args.host,
        "port": args.port,
        "log_level": args.log_level,
        "metrics_port": args.metrics_port,
        "metrics_host": args.metrics_host,
        "data_dir": args.data_dir,
        "keystores_path": args.keystores_path,
        "keystores_passwords_path": args.keystores_passwords_path,
        "workers": args.workers,
    }

    # Create config from dict using msgspec convert
    try:
        config = msgspec.convert(config_dict, Config)
    except msgspec.ValidationError as e:
        raise ValueError(f"Configuration validation error: {e!r}") from e

    return config
