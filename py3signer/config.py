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

    # TLS settings (optional)
    tls_cert: Path | None = None
    tls_key: Path | None = None

    # Logging
    log_level: str = "INFO"

    # Security
    auth_token: str | None = None

    # Metrics settings
    metrics_host: str = "127.0.0.1"
    metrics_port: int = 8081

    # Keystore settings
    key_store_path: Path | None = None

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

        # Validate TLS configuration
        has_cert = self.tls_cert is not None
        has_key = self.tls_key is not None
        if has_cert != has_key:
            raise ValueError(
                "Both tls_cert and tls_key must be provided together, or neither",
            )

        if self.tls_cert is not None and not self.tls_cert.exists():
            raise ValueError(f"tls_cert file not found: {self.tls_cert}")

        if self.tls_key is not None and not self.tls_key.exists():
            raise ValueError(f"tls_key file not found: {self.tls_key}")

        # Validate metrics port
        if self.metrics_port < 1 or self.metrics_port > 65535:
            raise ValueError(
                f"metrics_port must be between 1 and 65535, got {self.metrics_port}",
            )

        # Validate key_store_path if provided
        if self.key_store_path is not None:
            if not self.key_store_path.exists():
                raise ValueError(
                    f"key_store_path does not exist: {self.key_store_path}",
                )
            if not self.key_store_path.is_dir():
                raise ValueError(
                    f"key_store_path must be a directory: {self.key_store_path}",
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
        "--tls-cert",
        type=Path,
        default=None,
        help="Path to TLS certificate file",
    )
    parser.add_argument(
        "--tls-key",
        type=Path,
        default=None,
        help="Path to TLS private key file",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Logging level (default: INFO)",
    )
    parser.add_argument(
        "--auth-token",
        default=None,
        help="Bearer token for API authentication",
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
        "--key-store-path",
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
        "tls_cert": args.tls_cert,
        "tls_key": args.tls_key,
        "log_level": args.log_level,
        "auth_token": args.auth_token,
        "metrics_port": args.metrics_port,
        "metrics_host": args.metrics_host,
        "key_store_path": args.key_store_path,
        "keystores_path": args.keystores_path,
        "keystores_passwords_path": args.keystores_passwords_path,
        "workers": args.workers,
    }

    # Create config from dict using msgspec convert
    try:
        config = msgspec.convert(config_dict, Config)
    except msgspec.ValidationError as e:
        raise ValueError(f"Configuration validation error: {e}")

    return config
