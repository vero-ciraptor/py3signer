"""Tests for keystore storage persistence."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from py3signer.storage import KeyStorage


@pytest.fixture
def temp_keystore_dir(tmp_path: Path) -> Path:
    """Create a temporary directory for keystore files."""
    keystore_dir = tmp_path / "keystores"
    keystore_dir.mkdir()
    return keystore_dir


class TestStoragePersistence:
    """Test keystore persistence functionality."""

    def test_storage_without_keystore_path(self) -> None:
        """Test that storage works without a keystore path (in-memory only)."""
        storage = KeyStorage()
        assert storage.keystore_path is None

    def test_storage_with_keystore_path(self, temp_keystore_dir: Path) -> None:
        """Test that storage accepts a keystore path."""
        storage = KeyStorage(keystore_path=temp_keystore_dir)
        assert storage.keystore_path == temp_keystore_dir

    def test_add_key_with_persistence(self, temp_keystore_dir: Path) -> None:
        """Test adding a key with persistence enabled."""
        storage = KeyStorage(keystore_path=temp_keystore_dir)
        pubkey = MagicMock()
        pubkey_hex_str = "aabbccdd" * 12
        pubkey.to_bytes.return_value = bytes.fromhex(pubkey_hex_str)
        secret_key = MagicMock()
        keystore_json = '{"version": 4}'
        password = "testpass"

        result_pubkey_hex, persisted = storage.add_key(
            pubkey=pubkey,
            secret_key=secret_key,
            keystore_json=keystore_json,
            password=password,
            path="m/12381/3600/0/0/0",
        )

        assert persisted is True
        assert result_pubkey_hex == pubkey_hex_str
        assert (temp_keystore_dir / f"{pubkey_hex_str}.json").exists()
        assert (temp_keystore_dir / f"{pubkey_hex_str}.txt").exists()

        # Verify content
        with open(temp_keystore_dir / f"{pubkey_hex_str}.json") as f:
            assert f.read() == keystore_json
        with open(temp_keystore_dir / f"{pubkey_hex_str}.txt") as f:
            assert f.read() == password

    def test_add_key_without_persistence(self) -> None:
        """Test adding a key when persistence is disabled (no keystore_path)."""
        storage = KeyStorage()
        pubkey = MagicMock()
        pubkey.to_bytes.return_value = bytes.fromhex("aabbccdd" * 12)
        secret_key = MagicMock()

        _pubkey_hex, persisted = storage.add_key(
            pubkey=pubkey,
            secret_key=secret_key,
            path="m/12381/3600/0/0/0",
        )

        assert persisted is False

    def test_add_key_creates_directory(self, tmp_path: Path) -> None:
        """Test that add_key creates the directory if it doesn't exist."""
        nested_dir = tmp_path / "nested" / "keystore" / "dir"
        storage = KeyStorage(keystore_path=nested_dir)

        pubkey = MagicMock()
        pubkey.to_bytes.return_value = bytes.fromhex("aabbccdd" * 12)
        secret_key = MagicMock()

        _, persisted = storage.add_key(
            pubkey=pubkey,
            secret_key=secret_key,
            keystore_json="{}",
            password="password",
        )

        assert persisted is True
        assert nested_dir.exists()

    def test_remove_key_with_persistence(self, temp_keystore_dir: Path) -> None:
        """Test removing a key with persistence enabled."""
        storage = KeyStorage(keystore_path=temp_keystore_dir)
        pubkey_hex = "aabbccdd" * 12
        pubkey = MagicMock()
        pubkey.to_bytes.return_value = bytes.fromhex(pubkey_hex)
        secret_key = MagicMock()

        # Add key first with persistence
        storage.add_key(
            pubkey=pubkey,
            secret_key=secret_key,
            keystore_json="{}",
            password="pass",
        )

        removed, deleted = storage.remove_key(pubkey_hex)

        assert removed is True
        assert deleted is True
        assert not (temp_keystore_dir / f"{pubkey_hex}.json").exists()
        assert not (temp_keystore_dir / f"{pubkey_hex}.txt").exists()

    def test_remove_key_not_in_storage(self, temp_keystore_dir: Path) -> None:
        """Test removing a key that doesn't exist in storage."""
        storage = KeyStorage(keystore_path=temp_keystore_dir)
        pubkey_hex = "nonexistent" * 6

        removed, deleted = storage.remove_key(pubkey_hex)

        assert removed is False
        assert deleted is False

    def test_remove_key_without_persistence(self) -> None:
        """Test removing a key without persistence."""
        storage = KeyStorage()
        pubkey_hex = "aabbccdd" * 12
        pubkey = MagicMock()
        pubkey.to_bytes.return_value = bytes.fromhex(pubkey_hex)
        secret_key = MagicMock()

        # Add key without persistence
        storage.add_key(pubkey=pubkey, secret_key=secret_key)

        removed, deleted = storage.remove_key(pubkey_hex)

        assert removed is True
        assert deleted is False  # No disk deletion since no keystore_path

    def test_atomic_write(self, temp_keystore_dir: Path) -> None:
        """Test that keystore writes are atomic (temp file + rename)."""
        storage = KeyStorage(keystore_path=temp_keystore_dir)
        pubkey = MagicMock()
        pubkey.to_bytes.return_value = bytes.fromhex("aabbccdd" * 12)
        secret_key = MagicMock()
        keystore_json = '{"version": 4, "data": "test"}'
        password = "password123"

        # Save keystore via add_key
        storage.add_key(
            pubkey=pubkey,
            secret_key=secret_key,
            keystore_json=keystore_json,
            password=password,
        )

        # Check that temp files don't exist (temp files were .tmp, not starting with dot)
        temp_files = list(temp_keystore_dir.glob("*.tmp"))
        assert len(temp_files) == 0

    def test_pubkey_hex_normalization(self, temp_keystore_dir: Path) -> None:
        """Test that pubkey hex is normalized to lowercase."""
        storage = KeyStorage(keystore_path=temp_keystore_dir)
        pubkey_hex_lower = "aabbccdd0011" * 8

        pubkey = MagicMock()
        pubkey.to_bytes.return_value = bytes.fromhex(pubkey_hex_lower)
        secret_key = MagicMock()

        storage.add_key(
            pubkey=pubkey,
            secret_key=secret_key,
            keystore_json="{}",
            password="pass",
        )

        # Files should be created with lowercase name
        assert (temp_keystore_dir / f"{pubkey_hex_lower}.json").exists()

    def test_overwrite_existing_keystore(self, temp_keystore_dir: Path) -> None:
        """Test that saving over an existing keystore overwrites it."""
        storage = KeyStorage(keystore_path=temp_keystore_dir)
        pubkey_hex = "ccddeeff" * 12
        pubkey = MagicMock()
        pubkey.to_bytes.return_value = bytes.fromhex(pubkey_hex)
        secret_key = MagicMock()

        # First save
        storage.add_key(
            pubkey=pubkey,
            secret_key=secret_key,
            keystore_json='{"version": 4}',
            password="password1",
        )

        # Remove and re-add (simulating overwrite - but storage prevents duplicates)
        storage.remove_key(pubkey_hex)

        # Second save (as new key)
        storage.add_key(
            pubkey=pubkey,
            secret_key=secret_key,
            keystore_json='{"version": 5}',
            password="password2",
        )

        # Verify overwritten content
        with open(temp_keystore_dir / f"{pubkey_hex}.json") as f:
            assert '"version": 5' in f.read()
        with open(temp_keystore_dir / f"{pubkey_hex}.txt") as f:
            assert f.read() == "password2"

    def test_add_key_duplicate_raises(self) -> None:
        """Test that adding a duplicate key raises ValueError."""
        storage = KeyStorage()
        pubkey_hex = "aabbccdd" * 12
        pubkey = MagicMock()
        pubkey.to_bytes.return_value = bytes.fromhex(pubkey_hex)
        secret_key = MagicMock()

        # Add first time
        storage.add_key(pubkey=pubkey, secret_key=secret_key)

        # Add second time should raise
        with pytest.raises(ValueError, match=f"Key already exists: {pubkey_hex}"):
            storage.add_key(pubkey=pubkey, secret_key=secret_key)
