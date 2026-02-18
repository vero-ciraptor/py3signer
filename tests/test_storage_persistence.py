"""Tests for keystore storage persistence."""

import json
import os
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


@pytest.fixture
def sample_keystore_json() -> str:
    """Return a sample EIP-2335 keystore JSON string."""
    keystore = {
        "crypto": {
            "kdf": {
                "function": "scrypt",
                "params": {
                    "dklen": 32,
                    "n": 262144,
                    "p": 1,
                    "r": 8,
                    "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
                },
                "message": "",
            },
            "checksum": {
                "function": "sha256",
                "params": {},
                "message": "d221cc01c90697d905e4a2bb230d6f871f32e1e6d0aeff3b6eb9e456f47c97a6",
            },
            "cipher": {
                "function": "aes-128-ctr",
                "params": {"iv": "264daa22321ad291df5b05cc9ea32f8b"},
                "message": "8c2102046f51f9ad84a25b4d6b5ee3a71f4e4a5f5e0b1c7d3e2f8a9b0c1d2e3f",
            },
        },
        "pubkey": "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd001122",
        "path": "m/12381/3600/0/0/0",
        "uuid": "c962bf59-367b-4d55-9e63-563e89330173",
        "version": 4,
        "description": "Test keystore",
    }
    return json.dumps(keystore)


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

    def test_save_keystore_to_disk_success(self, temp_keystore_dir: Path) -> None:
        """Test successful keystore save to disk."""
        storage = KeyStorage(keystore_path=temp_keystore_dir)
        pubkey_hex = "aabbccdd00112233" * 6  # 96 hex chars
        keystore_json = '{"version": 4, "pubkey": "test"}'
        password = "testpassword123"

        result = storage.save_keystore_to_disk(pubkey_hex, keystore_json, password)

        assert result is True
        assert (temp_keystore_dir / f"{pubkey_hex}.json").exists()
        assert (temp_keystore_dir / f"{pubkey_hex}.txt").exists()

        # Verify content
        with open(temp_keystore_dir / f"{pubkey_hex}.json") as f:
            assert f.read() == keystore_json
        with open(temp_keystore_dir / f"{pubkey_hex}.txt") as f:
            assert f.read() == password

    def test_save_keystore_without_keystore_path(self) -> None:
        """Test that save returns False when no keystore path is configured."""
        storage = KeyStorage()
        result = storage.save_keystore_to_disk("test", "{}", "password")
        assert result is False

    def test_save_keystore_creates_directory(self, tmp_path: Path) -> None:
        """Test that save_keystore_to_disk creates the directory if it doesn't exist."""
        nested_dir = tmp_path / "nested" / "keystore" / "dir"
        storage = KeyStorage(keystore_path=nested_dir)

        result = storage.save_keystore_to_disk("testpubkey" * 6, "{}", "password")

        assert result is True
        assert nested_dir.exists()

    def test_delete_keystore_from_disk_success(self, temp_keystore_dir: Path) -> None:
        """Test successful keystore deletion from disk."""
        storage = KeyStorage(keystore_path=temp_keystore_dir)
        pubkey_hex = "testpubkey" * 6

        # First create files
        keystore_file = temp_keystore_dir / f"{pubkey_hex}.json"
        password_file = temp_keystore_dir / f"{pubkey_hex}.txt"
        keystore_file.write_text("{}")
        password_file.write_text("password")

        result = storage.delete_keystore_from_disk(pubkey_hex)

        assert result is True
        assert not keystore_file.exists()
        assert not password_file.exists()

    def test_delete_keystore_without_files(self, temp_keystore_dir: Path) -> None:
        """Test deleting keystore when files don't exist (should succeed)."""
        storage = KeyStorage(keystore_path=temp_keystore_dir)
        pubkey_hex = "nonexistent" * 6

        result = storage.delete_keystore_from_disk(pubkey_hex)

        assert result is True  # Should succeed even if files don't exist

    def test_delete_keystore_without_keystore_path(self) -> None:
        """Test that delete returns False when no keystore path is configured."""
        storage = KeyStorage()
        result = storage.delete_keystore_from_disk("test")
        assert result is False

    def test_add_key_with_persistence(self, temp_keystore_dir: Path) -> None:
        """Test adding a key with persistence enabled."""
        storage = KeyStorage(keystore_path=temp_keystore_dir)
        pubkey = MagicMock()
        pubkey.to_bytes.return_value = bytes.fromhex("aabbccdd" * 12)
        secret_key = MagicMock()
        keystore_json = '{"version": 4}'
        password = "testpass"

        pubkey_hex, persisted = storage.add_key_with_persistence(
            pubkey=pubkey,
            secret_key=secret_key,
            keystore_json=keystore_json,
            password=password,
            path="m/12381/3600/0/0/0",
        )

        assert persisted is True
        assert (temp_keystore_dir / f"{pubkey_hex}.json").exists()
        assert (temp_keystore_dir / f"{pubkey_hex}.txt").exists()

    def test_add_key_with_persistence_disabled(self) -> None:
        """Test adding a key when persistence is disabled (no keystore_path)."""
        storage = KeyStorage()
        pubkey = MagicMock()
        pubkey.to_bytes.return_value = bytes.fromhex("aabbccdd" * 12)
        secret_key = MagicMock()
        keystore_json = '{"version": 4}'
        password = "testpass"

        _pubkey_hex, persisted = storage.add_key_with_persistence(
            pubkey=pubkey,
            secret_key=secret_key,
            keystore_json=keystore_json,
            password=password,
            path="m/12381/3600/0/0/0",
        )

        assert persisted is False

    def test_remove_key_with_persistence(self, temp_keystore_dir: Path) -> None:
        """Test removing a key with persistence enabled."""
        storage = KeyStorage(keystore_path=temp_keystore_dir)
        pubkey_hex = "aabbccdd" * 12
        pubkey = MagicMock()
        pubkey.to_bytes.return_value = bytes.fromhex(pubkey_hex)
        secret_key = MagicMock()

        # Add key first
        storage.add_key(pubkey, secret_key)

        # Create files
        (temp_keystore_dir / f"{pubkey_hex}.json").write_text("{}")
        (temp_keystore_dir / f"{pubkey_hex}.txt").write_text("pass")

        removed_from_memory, deleted_from_disk = storage.remove_key_with_persistence(pubkey_hex)

        assert removed_from_memory is True
        assert deleted_from_disk is True
        assert not (temp_keystore_dir / f"{pubkey_hex}.json").exists()
        assert not (temp_keystore_dir / f"{pubkey_hex}.txt").exists()

    def test_remove_key_with_persistence_not_in_storage(self, temp_keystore_dir: Path) -> None:
        """Test removing a key that doesn't exist in storage."""
        storage = KeyStorage(keystore_path=temp_keystore_dir)
        pubkey_hex = "nonexistent" * 6

        removed_from_memory, deleted_from_disk = storage.remove_key_with_persistence(pubkey_hex)

        assert removed_from_memory is False
        assert deleted_from_disk is False  # No disk deletion attempted since key wasn't in memory

    def test_atomic_write(self, temp_keystore_dir: Path) -> None:
        """Test that keystore writes are atomic (temp file + rename)."""
        storage = KeyStorage(keystore_path=temp_keystore_dir)
        pubkey_hex = "testpubkey" * 6
        keystore_json = '{"version": 4, "data": "test"}'
        password = "password123"

        # Save keystore
        storage.save_keystore_to_disk(pubkey_hex, keystore_json, password)

        # Check that temp files don't exist
        temp_files = list(temp_keystore_dir.glob(".*.tmp"))
        assert len(temp_files) == 0

        # Check that final files exist
        assert (temp_keystore_dir / f"{pubkey_hex}.json").exists()
        assert (temp_keystore_dir / f"{pubkey_hex}.txt").exists()

    def test_pubkey_hex_normalization(self, temp_keystore_dir: Path) -> None:
        """Test that pubkey hex is normalized to lowercase."""
        storage = KeyStorage(keystore_path=temp_keystore_dir)
        pubkey_hex_mixed = "AABBCCDD0011" * 8
        pubkey_hex_lower = pubkey_hex_mixed.lower()

        storage.save_keystore_to_disk(pubkey_hex_mixed, "{}", "pass")

        # Files should be created with lowercase name
        assert (temp_keystore_dir / f"{pubkey_hex_lower}.json").exists()

    def test_overwrite_existing_keystore(self, temp_keystore_dir: Path) -> None:
        """Test that saving over an existing keystore overwrites it."""
        storage = KeyStorage(keystore_path=temp_keystore_dir)
        pubkey_hex = "testpubkey" * 6

        # First save
        storage.save_keystore_to_disk(pubkey_hex, '{"version": 4}', "password1")

        # Second save (overwrite)
        storage.save_keystore_to_disk(pubkey_hex, '{"version": 5}', "password2")

        # Verify overwritten content
        with open(temp_keystore_dir / f"{pubkey_hex}.json") as f:
            assert '"version": 5' in f.read()
        with open(temp_keystore_dir / f"{pubkey_hex}.txt") as f:
            assert f.read() == "password2"
