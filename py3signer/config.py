"""Configuration management using msgspec Struct."""

import argparse
import os
from pathlib import Path
from typing import Self

import msgspec
import yaml


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
    metrics_enabled: bool = False
    metrics_host: str = "127.0.0.1"
    metrics_port: int = 8081
    
    def __post_init__(self) -> None:
        """Validate configuration after initialization."""
        # msgspec handles basic type validation, but we need custom validation
        if self.port < 1 or self.port > 65535:
            raise ValueError(f"port must be between 1 and 65535, got {self.port}")
        
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if self.log_level.upper() not in valid_levels:
            raise ValueError(f"log_level must be one of {valid_levels}, got {self.log_level}")
        
        # Validate TLS configuration
        has_cert = self.tls_cert is not None
        has_key = self.tls_key is not None
        if has_cert != has_key:
            raise ValueError("Both tls_cert and tls_key must be provided together, or neither")
        
        if self.tls_cert is not None and not self.tls_cert.exists():
            raise ValueError(f"tls_cert file not found: {self.tls_cert}")
        
        if self.tls_key is not None and not self.tls_key.exists():
            raise ValueError(f"tls_key file not found: {self.tls_key}")
        
        # Validate metrics port
        if self.metrics_port < 1 or self.metrics_port > 65535:
            raise ValueError(f"metrics_port must be between 1 and 65535, got {self.metrics_port}")
    
    @property
    def normalized_log_level(self) -> str:
        """Return normalized uppercase log level."""
        return self.log_level.upper()


def load_config_from_file(path: Path) -> dict:
    """Load configuration from YAML file."""
    content = path.read_text()
    data = yaml.safe_load(content) or {}
    
    # Convert string paths to Path objects
    if "tls_cert" in data and data["tls_cert"] is not None:
        data["tls_cert"] = Path(data["tls_cert"])
    if "tls_key" in data and data["tls_key"] is not None:
        data["tls_key"] = Path(data["tls_key"])
    
    return data


def load_from_env() -> dict:
    """Load configuration from environment variables."""
    env_vars = {}
    
    if "PY3SIGNER_HOST" in os.environ:
        env_vars["host"] = os.environ["PY3SIGNER_HOST"]
    
    if "PY3SIGNER_PORT" in os.environ:
        try:
            env_vars["port"] = int(os.environ["PY3SIGNER_PORT"])
        except ValueError:
            raise ValueError("PY3SIGNER_PORT must be an integer")
    
    if "PY3SIGNER_TLS_CERT" in os.environ:
        env_vars["tls_cert"] = Path(os.environ["PY3SIGNER_TLS_CERT"])
    
    if "PY3SIGNER_TLS_KEY" in os.environ:
        env_vars["tls_key"] = Path(os.environ["PY3SIGNER_TLS_KEY"])
    
    if "PY3SIGNER_LOG_LEVEL" in os.environ:
        env_vars["log_level"] = os.environ["PY3SIGNER_LOG_LEVEL"]
    
    if "PY3SIGNER_AUTH_TOKEN" in os.environ:
        env_vars["auth_token"] = os.environ["PY3SIGNER_AUTH_TOKEN"]
    
    # Metrics environment variables
    if "PY3SIGNER_METRICS_ENABLED" in os.environ:
        env_vars["metrics_enabled"] = os.environ["PY3SIGNER_METRICS_ENABLED"].lower() in ("true", "1", "yes")
    
    if "PY3SIGNER_METRICS_HOST" in os.environ:
        env_vars["metrics_host"] = os.environ["PY3SIGNER_METRICS_HOST"]
    
    if "PY3SIGNER_METRICS_PORT" in os.environ:
        try:
            env_vars["metrics_port"] = int(os.environ["PY3SIGNER_METRICS_PORT"])
        except ValueError:
            raise ValueError("PY3SIGNER_METRICS_PORT must be an integer")
    
    return env_vars


def get_config() -> Config:
    """Parse command line arguments and return configuration."""
    parser = argparse.ArgumentParser(
        description="py3signer - A Remote BLS Signer for Ethereum",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        "-c", "--config",
        type=Path,
        help="Path to configuration file (YAML)"
    )
    parser.add_argument(
        "--host",
        help="HTTP server host (default: 127.0.0.1)"
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        help="HTTP server port (default: 8080)"
    )
    parser.add_argument(
        "--tls-cert",
        type=Path,
        help="Path to TLS certificate file"
    )
    parser.add_argument(
        "--tls-key",
        type=Path,
        help="Path to TLS private key file"
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level (default: INFO)"
    )
    parser.add_argument(
        "--auth-token",
        help="Bearer token for API authentication"
    )
    parser.add_argument(
        "--metrics-enabled",
        action="store_true",
        help="Enable Prometheus metrics endpoint (default: false)"
    )
    parser.add_argument(
        "--metrics-port",
        type=int,
        help="Port for metrics server (default: 8081)"
    )
    parser.add_argument(
        "--metrics-host",
        help="Host for metrics server (default: 127.0.0.1)"
    )
    
    args = parser.parse_args()
    
    # Start with defaults (empty dict)
    config_dict: dict = {}
    
    # Load from file if specified
    if args.config:
        if not args.config.exists():
            raise FileNotFoundError(f"Config file not found: {args.config}")
        config_dict.update(load_config_from_file(args.config))
    
    # Override with environment variables
    config_dict.update(load_from_env())
    
    # Override with CLI arguments
    if args.host:
        config_dict["host"] = args.host
    if args.port:
        config_dict["port"] = args.port
    if args.tls_cert:
        config_dict["tls_cert"] = args.tls_cert
    if args.tls_key:
        config_dict["tls_key"] = args.tls_key
    if args.log_level:
        config_dict["log_level"] = args.log_level
    if args.auth_token:
        config_dict["auth_token"] = args.auth_token
    if args.metrics_enabled:
        config_dict["metrics_enabled"] = True
    if args.metrics_port:
        config_dict["metrics_port"] = args.metrics_port
    if args.metrics_host:
        config_dict["metrics_host"] = args.metrics_host
    
    # Create config from dict using msgspec convert
    try:
        config = msgspec.convert(config_dict, Config)
    except msgspec.ValidationError as e:
        raise ValueError(f"Configuration validation error: {e}")
    
    return config
