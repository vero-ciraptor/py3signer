"""Tests for configuration management."""

from pathlib import Path

import pytest

from py3signer.config import Config


class TestKeystoresPathConfig:
    """Tests for --keystores-path and --keystores-passwords-path configuration."""

    def test_both_paths_none(self) -> None:
        """Test that both paths can be None (default)."""
        config = Config()
        assert config.keystores_path is None
        assert config.keystores_passwords_path is None

    def test_both_paths_valid(self, tmp_path: Path) -> None:
        """Test that both paths can be set to valid directories."""
        keystores_dir = tmp_path / "keystores"
        passwords_dir = tmp_path / "passwords"
        keystores_dir.mkdir()
        passwords_dir.mkdir()

        config = Config(
            keystores_path=keystores_dir,
            keystores_passwords_path=passwords_dir,
        )
        assert config.keystores_path == keystores_dir
        assert config.keystores_passwords_path == passwords_dir
        assert isinstance(config.keystores_path, Path)
        assert isinstance(config.keystores_passwords_path, Path)

    def test_only_keystores_path_raises(self, tmp_path: Path) -> None:
        """Test that only keystores_path without passwords_path raises error."""
        keystores_dir = tmp_path / "keystores"
        keystores_dir.mkdir()

        with pytest.raises(
            ValueError,
            match=r".*--keystores-passwords-path must be provided.*",
        ):
            Config(keystores_path=keystores_dir, keystores_passwords_path=None)

    def test_only_passwords_path_raises(self, tmp_path: Path) -> None:
        """Test that only passwords_path without keystores_path raises error."""
        passwords_dir = tmp_path / "passwords"
        passwords_dir.mkdir()

        with pytest.raises(ValueError, match=r".*--keystores-path must be provided.*"):
            Config(keystores_path=None, keystores_passwords_path=passwords_dir)

    def test_keystores_path_not_exists(self, tmp_path: Path) -> None:
        """Test error when keystores_path does not exist."""
        keystores_dir = tmp_path / "keystores"
        passwords_dir = tmp_path / "passwords"
        passwords_dir.mkdir()

        with pytest.raises(ValueError, match=r".*keystores_path does not exist.*"):
            Config(
                keystores_path=keystores_dir,
                keystores_passwords_path=passwords_dir,
            )

    def test_passwords_path_not_exists(self, tmp_path: Path) -> None:
        """Test error when keystores_passwords_path does not exist."""
        keystores_dir = tmp_path / "keystores"
        passwords_dir = tmp_path / "passwords"
        keystores_dir.mkdir()

        with pytest.raises(
            ValueError, match=r".*keystores_passwords_path does not exist.*"
        ):
            Config(
                keystores_path=keystores_dir,
                keystores_passwords_path=passwords_dir,
            )

    def test_keystores_path_not_directory(self, tmp_path: Path) -> None:
        """Test error when keystores_path is not a directory."""
        keystores_file = tmp_path / "keystores"
        passwords_dir = tmp_path / "passwords"
        keystores_file.write_text("not a directory")
        passwords_dir.mkdir()

        with pytest.raises(ValueError, match=r".*keystores_path must be a directory.*"):
            Config(
                keystores_path=keystores_file,
                keystores_passwords_path=passwords_dir,
            )

    def test_passwords_path_not_directory(self, tmp_path: Path) -> None:
        """Test error when keystores_passwords_path is not a directory."""
        keystores_dir = tmp_path / "keystores"
        passwords_file = tmp_path / "passwords"
        keystores_dir.mkdir()
        passwords_file.write_text("not a directory")

        with pytest.raises(
            ValueError,
            match=r".*keystores_passwords_path must be a directory.*",
        ):
            Config(
                keystores_path=keystores_dir,
                keystores_passwords_path=passwords_file,
            )


class TestKeyStorePathConfig:
    """Tests for --key-store-path configuration."""

    def test_key_store_path_none(self) -> None:
        """Test that key_store_path can be None."""
        config = Config()
        assert config.key_store_path is None

    def test_key_store_path_valid(self, tmp_path: Path) -> None:
        """Test that key_store_path can be set to a valid directory."""
        keystore_dir = tmp_path / "keystores"
        keystore_dir.mkdir()

        config = Config(key_store_path=keystore_dir)
        assert config.key_store_path == keystore_dir
        assert isinstance(config.key_store_path, Path)

    def test_key_store_path_not_exists(self, tmp_path: Path) -> None:
        """Test error when key_store_path does not exist."""
        keystore_dir = tmp_path / "keystores"

        with pytest.raises(ValueError, match=r".*key_store_path does not exist.*"):
            Config(key_store_path=keystore_dir)

    def test_key_store_path_not_directory(self, tmp_path: Path) -> None:
        """Test error when key_store_path is not a directory."""
        keystore_file = tmp_path / "keystores"
        keystore_file.write_text("not a directory")

        with pytest.raises(ValueError, match=r".*key_store_path must be a directory.*"):
            Config(key_store_path=keystore_file)


class TestCombinedKeystoreConfig:
    """Tests for using both --key-store-path and --keystores-path together."""

    def test_all_three_paths_valid(self, tmp_path: Path) -> None:
        """Test that all three paths can be used together."""
        key_store_dir = tmp_path / "keystore_store"
        keystores_dir = tmp_path / "keystores"
        passwords_dir = tmp_path / "passwords"
        key_store_dir.mkdir()
        keystores_dir.mkdir()
        passwords_dir.mkdir()

        config = Config(
            key_store_path=key_store_dir,
            keystores_path=keystores_dir,
            keystores_passwords_path=passwords_dir,
        )
        assert config.key_store_path == key_store_dir
        assert config.keystores_path == keystores_dir
        assert config.keystores_passwords_path == passwords_dir


class TestHostConfig:
    """Tests for host configuration."""

    def test_default_host(self) -> None:
        """Test that default host is 127.0.0.1."""
        config = Config()
        assert config.host == "127.0.0.1"

    def test_custom_host(self) -> None:
        """Test that custom host can be set."""
        config = Config(host="0.0.0.0")
        assert config.host == "0.0.0.0"

        config2 = Config(host="192.168.1.1")
        assert config2.host == "192.168.1.1"


class TestConfigDefaults:
    """Tests for default configuration values."""

    def test_all_defaults(self) -> None:
        """Test all default configuration values."""
        config = Config()

        assert config.host == "127.0.0.1"
        assert config.port == 8080
        assert config.log_level == "INFO"
        assert config.normalized_log_level == "INFO"
        assert config.metrics_host == "127.0.0.1"
        assert config.metrics_port == 8081
        assert config.key_store_path is None
        assert config.keystores_path is None
        assert config.keystores_passwords_path is None
        assert config.workers >= 1


class TestPortConfig:
    """Tests for port configuration validation."""

    def test_valid_port(self) -> None:
        """Test that valid ports are accepted."""
        config = Config(port=8080)
        assert config.port == 8080

        # Test boundary values
        config_min = Config(port=1)
        assert config_min.port == 1

        config_max = Config(port=65535)
        assert config_max.port == 65535

    def test_port_too_low(self) -> None:
        """Test error when port is too low."""
        with pytest.raises(ValueError, match=r".*port must be between.*"):
            Config(port=0)

    def test_port_too_high(self) -> None:
        """Test error when port is too high."""
        with pytest.raises(ValueError, match=r".*port must be between.*"):
            Config(port=65536)


class TestMetricsPortConfig:
    """Tests for metrics port configuration validation."""

    def test_default_metrics_port(self) -> None:
        """Test that default metrics port is 8081."""
        config = Config()
        assert config.metrics_port == 8081
        assert config.metrics_host == "127.0.0.1"
        assert isinstance(config.metrics_port, int)

    def test_valid_metrics_port(self) -> None:
        """Test that valid metrics ports are accepted."""
        config = Config(metrics_port=9090)
        assert config.metrics_port == 9090

        # Test boundary values
        config_min = Config(metrics_port=1)
        assert config_min.metrics_port == 1

        config_max = Config(metrics_port=65535)
        assert config_max.metrics_port == 65535

    def test_metrics_port_too_low(self) -> None:
        """Test error when metrics port is too low."""
        with pytest.raises(ValueError, match=r".*metrics_port must be between.*"):
            Config(metrics_port=0)

    def test_metrics_port_too_high(self) -> None:
        """Test error when metrics port is too high."""
        with pytest.raises(ValueError, match=r".*metrics_port must be between.*"):
            Config(metrics_port=65536)

    def test_custom_metrics_host(self) -> None:
        """Test that custom metrics host can be set."""
        config = Config(metrics_host="0.0.0.0")
        assert config.metrics_host == "0.0.0.0"

        config2 = Config(metrics_host="192.168.1.1")
        assert config2.metrics_host == "192.168.1.1"


class TestLogLevelConfig:
    """Tests for log level configuration validation."""

    def test_valid_log_levels(self) -> None:
        """Test that valid log levels are accepted."""
        for level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            config = Config(log_level=level)
            assert config.normalized_log_level == level
            assert isinstance(config.normalized_log_level, str)

    def test_case_insensitive(self) -> None:
        """Test that log levels are case-insensitive."""
        config = Config(log_level="debug")
        assert config.normalized_log_level == "DEBUG"

        config2 = Config(log_level="Info")
        assert config2.normalized_log_level == "INFO"

        config3 = Config(log_level="WARNING")
        assert config3.normalized_log_level == "WARNING"

    def test_invalid_log_level(self) -> None:
        """Test error when log level is invalid."""
        with pytest.raises(ValueError, match=r".*log_level must be one of.*"):
            Config(log_level="INVALID")


class TestWorkersConfig:
    """Tests for workers configuration validation."""

    def test_default_workers(self) -> None:
        """Test that default workers is at least 1."""
        config = Config()
        assert config.workers >= 1
        assert isinstance(config.workers, int)

    def test_valid_workers(self) -> None:
        """Test that valid worker counts are accepted."""
        config = Config(workers=1)
        assert config.workers == 1

        config2 = Config(workers=4)
        assert config2.workers == 4

        config3 = Config(workers=16)
        assert config3.workers == 16

    def test_workers_too_low(self) -> None:
        """Test error when workers is less than 1."""
        with pytest.raises(ValueError, match=r".*workers must be at least 1.*"):
            Config(workers=0)

    def test_workers_negative(self) -> None:
        """Test error when workers is negative."""
        with pytest.raises(ValueError, match=r".*workers must be at least 1.*"):
            Config(workers=-1)
