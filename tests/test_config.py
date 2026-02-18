"""Tests for configuration management."""

from pathlib import Path

import pytest

from py3signer.config import Config


class TestKeystoresPathConfig:
    """Tests for --keystores-path and --keystores-passwords-path configuration."""

    def test_both_paths_none(self, tmp_path: Path) -> None:
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

        config = Config(keystores_path=keystores_dir, keystores_passwords_path=passwords_dir)
        assert config.keystores_path == keystores_dir
        assert config.keystores_passwords_path == passwords_dir

    def test_only_keystores_path_raises(self, tmp_path: Path) -> None:
        """Test that only keystores_path without passwords_path raises error."""
        keystores_dir = tmp_path / "keystores"
        keystores_dir.mkdir()

        with pytest.raises(ValueError, match="--keystores-passwords-path must be provided"):
            Config(keystores_path=keystores_dir, keystores_passwords_path=None)

    def test_only_passwords_path_raises(self, tmp_path: Path) -> None:
        """Test that only passwords_path without keystores_path raises error."""
        passwords_dir = tmp_path / "passwords"
        passwords_dir.mkdir()

        with pytest.raises(ValueError, match="--keystores-path must be provided"):
            Config(keystores_path=None, keystores_passwords_path=passwords_dir)

    def test_keystores_path_not_exists(self, tmp_path: Path) -> None:
        """Test error when keystores_path does not exist."""
        keystores_dir = tmp_path / "keystores"
        passwords_dir = tmp_path / "passwords"
        passwords_dir.mkdir()

        with pytest.raises(ValueError, match="keystores_path does not exist"):
            Config(
                keystores_path=keystores_dir,
                keystores_passwords_path=passwords_dir,
            )

    def test_passwords_path_not_exists(self, tmp_path: Path) -> None:
        """Test error when keystores_passwords_path does not exist."""
        keystores_dir = tmp_path / "keystores"
        passwords_dir = tmp_path / "passwords"
        keystores_dir.mkdir()

        with pytest.raises(ValueError, match="keystores_passwords_path does not exist"):
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

        with pytest.raises(ValueError, match="keystores_path must be a directory"):
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

        with pytest.raises(ValueError, match="keystores_passwords_path must be a directory"):
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

    def test_key_store_path_not_exists(self, tmp_path: Path) -> None:
        """Test error when key_store_path does not exist."""
        keystore_dir = tmp_path / "keystores"

        with pytest.raises(ValueError, match="key_store_path does not exist"):
            Config(key_store_path=keystore_dir)

    def test_key_store_path_not_directory(self, tmp_path: Path) -> None:
        """Test error when key_store_path is not a directory."""
        keystore_file = tmp_path / "keystores"
        keystore_file.write_text("not a directory")

        with pytest.raises(ValueError, match="key_store_path must be a directory"):
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


class TestPortConfig:
    """Tests for port configuration validation."""

    def test_valid_port(self) -> None:
        """Test that valid ports are accepted."""
        config = Config(port=8080)
        assert config.port == 8080

    def test_port_too_low(self) -> None:
        """Test error when port is too low."""
        with pytest.raises(ValueError, match="port must be between"):
            Config(port=0)

    def test_port_too_high(self) -> None:
        """Test error when port is too high."""
        with pytest.raises(ValueError, match="port must be between"):
            Config(port=65536)


class TestLogLevelConfig:
    """Tests for log level configuration validation."""

    def test_valid_log_levels(self) -> None:
        """Test that valid log levels are accepted."""
        for level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            config = Config(log_level=level)
            assert config.normalized_log_level == level

    def test_case_insensitive(self) -> None:
        """Test that log levels are case-insensitive."""
        config = Config(log_level="debug")
        assert config.normalized_log_level == "DEBUG"

    def test_invalid_log_level(self) -> None:
        """Test error when log level is invalid."""
        with pytest.raises(ValueError, match="log_level must be one of"):
            Config(log_level="INVALID")


class TestTLSConfig:
    """Tests for TLS configuration validation."""

    def test_no_tls(self) -> None:
        """Test that TLS is optional."""
        config = Config()
        assert config.tls_cert is None
        assert config.tls_key is None

    def test_both_tls_options(self, tmp_path: Path) -> None:
        """Test that both TLS options can be set."""
        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"
        cert_file.write_text("cert content")
        key_file.write_text("key content")

        config = Config(tls_cert=cert_file, tls_key=key_file)
        assert config.tls_cert == cert_file
        assert config.tls_key == key_file

    def test_only_cert_raises(self, tmp_path: Path) -> None:
        """Test error when only cert is provided."""
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text("cert content")

        with pytest.raises(ValueError, match="Both tls_cert and tls_key must be provided"):
            Config(tls_cert=cert_file, tls_key=None)

    def test_only_key_raises(self, tmp_path: Path) -> None:
        """Test error when only key is provided."""
        key_file = tmp_path / "key.pem"
        key_file.write_text("key content")

        with pytest.raises(ValueError, match="Both tls_cert and tls_key must be provided"):
            Config(tls_cert=None, tls_key=key_file)

    def test_cert_not_exists(self, tmp_path: Path) -> None:
        """Test error when cert file doesn't exist."""
        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"
        key_file.write_text("key content")

        with pytest.raises(ValueError, match="tls_cert file not found"):
            Config(tls_cert=cert_file, tls_key=key_file)

    def test_key_not_exists(self, tmp_path: Path) -> None:
        """Test error when key file doesn't exist."""
        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"
        cert_file.write_text("cert content")

        with pytest.raises(ValueError, match="tls_key file not found"):
            Config(tls_cert=cert_file, tls_key=key_file)
