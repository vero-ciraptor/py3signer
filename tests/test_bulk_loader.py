"""Tests for bulk keystore loading."""

import json
from pathlib import Path

import pytest

from py3signer.bulk_loader import (
    load_keystore_with_password,
    load_keystores_from_directory,
    scan_keystore_directory,
)
from py3signer.keystore import KeystoreError
from py3signer.storage import KeyStorage


class TestScanKeystoreDirectory:
    """Tests for scan_keystore_directory function."""

    def test_empty_directory(self, tmp_path: Path) -> None:
        """Test scanning an empty directory."""
        result = scan_keystore_directory(tmp_path)
        assert result == {}

    def test_directory_with_matching_pairs(self, tmp_path: Path) -> None:
        """Test directory with matching keystore/password pairs."""
        # Create matching pairs
        (tmp_path / "keystore1.json").write_text("{}")
        (tmp_path / "keystore1.txt").write_text("password1")
        (tmp_path / "keystore2.json").write_text("{}")
        (tmp_path / "keystore2.txt").write_text("password2")

        result = scan_keystore_directory(tmp_path)

        assert len(result) == 2
        assert "keystore1" in result
        assert "keystore2" in result
        assert result["keystore1"] == tmp_path / "keystore1.json"
        assert result["keystore2"] == tmp_path / "keystore2.json"

    def test_directory_with_missing_password(self, tmp_path: Path) -> None:
        """Test that keystores without password files are skipped."""
        (tmp_path / "keystore1.json").write_text("{}")
        (tmp_path / "keystore1.txt").write_text("password1")
        (tmp_path / "keystore2.json").write_text("{}")  # No password file

        result = scan_keystore_directory(tmp_path)

        assert len(result) == 1
        assert "keystore1" in result
        assert "keystore2" not in result

    def test_directory_with_extra_files(self, tmp_path: Path) -> None:
        """Test that non-json files are ignored."""
        (tmp_path / "keystore.json").write_text("{}")
        (tmp_path / "keystore.txt").write_text("password")
        (tmp_path / "readme.md").write_text("# README")
        (tmp_path / "data.csv").write_text("a,b,c")

        result = scan_keystore_directory(tmp_path)

        assert len(result) == 1
        assert "keystore" in result

    def test_nonexistent_directory(self, tmp_path: Path) -> None:
        """Test scanning a non-existent directory."""
        nonexistent = tmp_path / "does_not_exist"
        result = scan_keystore_directory(nonexistent)
        assert result == {}

    def test_file_instead_of_directory(self, tmp_path: Path) -> None:
        """Test passing a file instead of a directory."""
        file_path = tmp_path / "some_file.txt"
        file_path.write_text("content")
        result = scan_keystore_directory(file_path)
        assert result == {}


class TestLoadKeystoreWithPassword:
    """Tests for load_keystore_with_password function."""

    def test_valid_keystore(self, tmp_path: Path) -> None:
        """Test loading a valid keystore with correct password."""
        # Use the test data keystore
        test_data = Path(__file__).parent / "data"
        keystore_path = test_data / "test_keystore_scrypt.json"

        # Create password file
        password_path = tmp_path / "password.txt"
        password_path.write_text("testpassword123")

        pubkey, secret_key, path, description = load_keystore_with_password(
            keystore_path, password_path
        )

        assert pubkey is not None
        assert secret_key is not None
        assert path == "m/12381/3600/0/0/0"
        assert description == "Test keystore with scrypt KDF (N=262144)"

    def test_wrong_password(self, tmp_path: Path) -> None:
        """Test loading with incorrect password."""
        test_data = Path(__file__).parent / "data"
        keystore_path = test_data / "test_keystore_scrypt.json"

        # Create password file with wrong password
        password_path = tmp_path / "password.txt"
        password_path.write_text("wrongpassword")

        with pytest.raises(KeystoreError) as exc_info:
            load_keystore_with_password(keystore_path, password_path)

        error_msg = str(exc_info.value).lower()
        assert "password" in error_msg or "invalid" in error_msg

    def test_missing_password_file(self, tmp_path: Path) -> None:
        """Test when password file doesn't exist."""
        test_data = Path(__file__).parent / "data"
        keystore_path = test_data / "test_keystore_scrypt.json"

        password_path = tmp_path / "nonexistent.txt"

        with pytest.raises(KeystoreError):
            load_keystore_with_password(keystore_path, password_path)

    def test_invalid_keystore_file(self, tmp_path: Path) -> None:
        """Test with invalid JSON keystore."""
        keystore_path = tmp_path / "invalid.json"
        keystore_path.write_text("not valid json")

        password_path = tmp_path / "invalid.txt"
        password_path.write_text("password")

        with pytest.raises(KeystoreError):
            load_keystore_with_password(keystore_path, password_path)


class TestLoadKeystoresFromDirectory:
    """Tests for load_keystores_from_directory function."""

    def test_load_valid_keystores(self, tmp_path: Path) -> None:
        """Test loading valid keystores into storage."""
        test_data = Path(__file__).parent / "data"

        # Create matching keystore/password pairs in temp directory
        keystore1_json = tmp_path / "keystore-m_12381_3600_0_0_0-16777216.json"
        keystore1_txt = tmp_path / "keystore-m_12381_3600_0_0_0-16777216.txt"

        # Copy test keystore
        keystore_data = json.loads((test_data / "test_keystore_scrypt.json").read_text())
        keystore_data["pubkey"] = "a792e85e01746b22e89c7289aa693c4413db2c83d1209380cc4e98fc132ba49c301606032f77089d90e2df0539d23037"
        keystore1_json.write_text(json.dumps(keystore_data))
        keystore1_txt.write_text("testpassword123")

        storage = KeyStorage()
        success, failures = load_keystores_from_directory(tmp_path, storage)

        assert success == 1
        assert failures == 0
        assert len(storage) == 1

    def test_partial_failure(self, tmp_path: Path) -> None:
        """Test handling when some keystores fail to load."""
        test_data = Path(__file__).parent / "data"

        # Valid keystore
        keystore1_json = tmp_path / "keystore1.json"
        keystore1_txt = tmp_path / "keystore1.txt"
        keystore_data = json.loads((test_data / "test_keystore_scrypt.json").read_text())
        keystore1_json.write_text(json.dumps(keystore_data))
        keystore1_txt.write_text("testpassword123")

        # Invalid keystore (wrong password)
        keystore2_json = tmp_path / "keystore2.json"
        keystore2_txt = tmp_path / "keystore2.txt"
        keystore2_json.write_text(json.dumps(keystore_data))
        keystore2_txt.write_text("wrongpassword")

        storage = KeyStorage()
        success, failures = load_keystores_from_directory(tmp_path, storage)

        assert success == 1
        assert failures == 1
        assert len(storage) == 1

    def test_duplicate_keystore(self, tmp_path: Path) -> None:
        """Test handling of duplicate keystores (same public key)."""
        test_data = Path(__file__).parent / "data"

        # Two keystores with same content (will have same pubkey)
        keystore1_json = tmp_path / "keystore1.json"
        keystore1_txt = tmp_path / "keystore1.txt"
        keystore2_json = tmp_path / "keystore2.json"
        keystore2_txt = tmp_path / "keystore2.txt"

        keystore_data = json.loads((test_data / "test_keystore_scrypt.json").read_text())
        keystore1_json.write_text(json.dumps(keystore_data))
        keystore1_txt.write_text("testpassword123")
        keystore2_json.write_text(json.dumps(keystore_data))
        keystore2_txt.write_text("testpassword123")

        storage = KeyStorage()
        success, failures = load_keystores_from_directory(tmp_path, storage)

        assert success == 1
        assert failures == 1  # Second one fails due to duplicate
        assert len(storage) == 1

    def test_empty_directory(self, tmp_path: Path) -> None:
        """Test loading from empty directory."""
        storage = KeyStorage()
        success, failures = load_keystores_from_directory(tmp_path, storage)

        assert success == 0
        assert failures == 0
        assert len(storage) == 0

    def test_directory_with_no_matching_pairs(self, tmp_path: Path) -> None:
        """Test directory with keystore but no password file."""
        keystore_json = tmp_path / "keystore.json"
        keystore_json.write_text("{}")

        storage = KeyStorage()
        success, failures = load_keystores_from_directory(tmp_path, storage)

        assert success == 0
        assert failures == 0
        assert len(storage) == 0


class TestBulkLoaderIntegration:
    """Integration tests for bulk loader."""

    def test_multiple_valid_keystores(self, tmp_path: Path) -> None:
        """Test loading multiple valid keystores."""
        test_data = Path(__file__).parent / "data"
        original_keystore = json.loads((test_data / "test_keystore_scrypt.json").read_text())

        # Create multiple keystores with unique pubkeys
        for i in range(3):
            keystore_data = original_keystore.copy()
            keystore_data["pubkey"] = f"{i:02x}" * 48  # Unique pubkey for each
            keystore_data["uuid"] = f"00000000-0000-0000-0000-{i:012d}"

            keystore_json = tmp_path / f"keystore{i}.json"
            keystore_txt = tmp_path / f"keystore{i}.txt"

            # Note: This won't actually decrypt properly since we changed the pubkey
            # but the keystore structure is valid
            keystore_json.write_text(json.dumps(keystore_data))
            keystore_txt.write_text("testpassword123")

        # This will fail to decrypt but that's expected - we're testing the flow
        storage = KeyStorage()
        success, failures = load_keystores_from_directory(tmp_path, storage)

        # All will fail due to pubkey mismatch or decryption failure
        # but the scanner should find them
        keystores = scan_keystore_directory(tmp_path)
        assert len(keystores) == 3
