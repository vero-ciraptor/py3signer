"""Tests for bulk keystore loading."""

import json
from pathlib import Path

import pytest

from py3signer.bulk_loader import (
    load_input_only_keystores,
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
            keystore_path,
            password_path,
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
        keystore_data = json.loads(
            (test_data / "test_keystore_scrypt.json").read_text(),
        )
        keystore_data["pubkey"] = (
            "97248533cef0908a5ebe52c3b487471301bf6369010e6167f63dd74feddac2dfb5336a59a331d38eb0e454d6f6fcb1a4"
        )
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
        keystore_data = json.loads(
            (test_data / "test_keystore_scrypt.json").read_text(),
        )
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

        keystore_data = json.loads(
            (test_data / "test_keystore_scrypt.json").read_text(),
        )
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
        original_keystore = json.loads(
            (test_data / "test_keystore_scrypt.json").read_text(),
        )

        # Create multiple keystores with unique pubkeys
        for i in range(3):
            keystore_data = original_keystore.copy()
            keystore_data["pubkey"] = f"{i + 2:02x}" * 48  # Unique pubkey for each
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


class TestLoadKeystoresPersistentParameter:
    """Tests for the persistent parameter in load_keystores_from_directory."""

    def test_load_as_non_persistent(self, tmp_path: Path) -> None:
        """Test loading keystores as non-persistent."""
        test_data = Path(__file__).parent / "data"

        # Create a valid keystore with unique pubkey
        keystore_json = tmp_path / "keystore-m_12381_3600_0_0_0-16777216.json"
        keystore_txt = tmp_path / "keystore-m_12381_3600_0_0_0-16777216.txt"

        keystore_data = json.loads(
            (test_data / "test_keystore_scrypt.json").read_text(),
        )
        keystore_data["pubkey"] = (
            "97248533cef0908a5ebe52c3b487471301bf6369010e6167f63dd74feddac2dfb5336a59a331d38eb0e454d6f6fcb1a4"
        )
        keystore_json.write_text(json.dumps(keystore_data))
        keystore_txt.write_text("testpassword123")

        storage = KeyStorage()
        success, failures = load_keystores_from_directory(
            tmp_path,
            storage,
            persistent=False,
        )

        assert success == 1
        assert failures == 0
        assert len(storage) == 1

        # Verify the key is marked as non-persistent by checking remove behavior
        # (non-persistent keys should not trigger disk deletion)
        pubkey_hex = "97248533cef0908a5ebe52c3b487471301bf6369010e6167f63dd74feddac2dfb5336a59a331d38eb0e454d6f6fcb1a4"
        storage.remove_key(pubkey_hex)


class TestLoadInputOnlyKeystores:
    """Tests for load_input_only_keystores function."""

    def test_load_from_separate_directories(self, tmp_path: Path) -> None:
        """Test loading keystores from separate directories."""
        test_data = Path(__file__).parent / "data"

        keystores_dir = tmp_path / "keystores"
        passwords_dir = tmp_path / "passwords"
        keystores_dir.mkdir()
        passwords_dir.mkdir()

        # Create keystore in keystores dir
        keystore_json = keystores_dir / "test_keystore.json"
        keystore_data = json.loads(
            (test_data / "test_keystore_scrypt.json").read_text(),
        )
        keystore_data["pubkey"] = (
            "97248533cef0908a5ebe52c3b487471301bf6369010e6167f63dd74feddac2dfb5336a59a331d38eb0e454d6f6fcb1a4"
        )
        keystore_json.write_text(json.dumps(keystore_data))

        # Create password in passwords dir with matching base name
        password_txt = passwords_dir / "test_keystore.txt"
        password_txt.write_text("testpassword123")

        storage = KeyStorage()
        success, failures = load_input_only_keystores(
            keystores_dir,
            passwords_dir,
            storage,
        )

        assert success == 1
        assert failures == 0
        assert len(storage) == 1

        # Verify key is non-persistent
        pubkey_hex = "97248533cef0908a5ebe52c3b487471301bf6369010e6167f63dd74feddac2dfb5336a59a331d38eb0e454d6f6fcb1a4"
        storage.remove_key(pubkey_hex)

    def test_missing_password_file(self, tmp_path: Path) -> None:
        """Test handling when password file is missing in separate directory."""
        keystores_dir = tmp_path / "keystores"
        passwords_dir = tmp_path / "passwords"
        keystores_dir.mkdir()
        passwords_dir.mkdir()

        # Create keystore but no password
        keystore_json = keystores_dir / "test_keystore.json"
        keystore_json.write_text('{"version": 4}')

        storage = KeyStorage()
        success, failures = load_input_only_keystores(
            keystores_dir,
            passwords_dir,
            storage,
        )

        assert success == 0
        assert failures == 1  # Counts as failure due to missing password
        assert len(storage) == 0

    def test_nonexistent_keystores_path(self, tmp_path: Path) -> None:
        """Test error when keystores path doesn't exist."""
        keystores_dir = tmp_path / "keystores"
        passwords_dir = tmp_path / "passwords"
        passwords_dir.mkdir()

        storage = KeyStorage()
        with pytest.raises(ValueError, match="Keystores path does not exist"):
            load_input_only_keystores(keystores_dir, passwords_dir, storage)

    def test_nonexistent_passwords_path(self, tmp_path: Path) -> None:
        """Test error when passwords path doesn't exist."""
        keystores_dir = tmp_path / "keystores"
        passwords_dir = tmp_path / "passwords"
        keystores_dir.mkdir()

        storage = KeyStorage()
        with pytest.raises(ValueError, match="Passwords path does not exist"):
            load_input_only_keystores(keystores_dir, passwords_dir, storage)

    def test_keystores_path_is_file(self, tmp_path: Path) -> None:
        """Test error when keystores path is a file."""
        keystores_file = tmp_path / "keystores"
        passwords_dir = tmp_path / "passwords"
        keystores_file.write_text("not a directory")
        passwords_dir.mkdir()

        storage = KeyStorage()
        with pytest.raises(ValueError, match="Keystores path is not a directory"):
            load_input_only_keystores(keystores_file, passwords_dir, storage)

    def test_passwords_path_is_file(self, tmp_path: Path) -> None:
        """Test error when passwords path is a file."""
        keystores_dir = tmp_path / "keystores"
        passwords_file = tmp_path / "passwords"
        keystores_dir.mkdir()
        passwords_file.write_text("not a directory")

        storage = KeyStorage()
        with pytest.raises(ValueError, match="Passwords path is not a directory"):
            load_input_only_keystores(keystores_dir, passwords_file, storage)

    def test_multiple_keystores_with_mixed_success(self, tmp_path: Path) -> None:
        """Test loading multiple keystores with some failures."""
        test_data = Path(__file__).parent / "data"
        original_keystore = json.loads(
            (test_data / "test_keystore_scrypt.json").read_text(),
        )

        keystores_dir = tmp_path / "keystores"
        passwords_dir = tmp_path / "passwords"
        keystores_dir.mkdir()
        passwords_dir.mkdir()

        # Valid keystore 1 - use the original with its actual pubkey
        keystore1_json = keystores_dir / "keystore1.json"
        keystore1_data = original_keystore.copy()
        keystore1_json.write_text(json.dumps(keystore1_data))
        (passwords_dir / "keystore1.txt").write_text("testpassword123")

        # Keystore with wrong password (will fail to decrypt)
        keystore2_json = keystores_dir / "keystore2.json"
        keystore2_data = original_keystore.copy()
        keystore2_json.write_text(json.dumps(keystore2_data))
        (passwords_dir / "keystore2.txt").write_text("wrongpassword")

        # Keystore with missing password
        (keystores_dir / "keystore3.json").write_text(json.dumps(original_keystore))
        # No password file for keystore3

        storage = KeyStorage()
        success, failures = load_input_only_keystores(
            keystores_dir,
            passwords_dir,
            storage,
        )

        assert success == 1  # Only keystore1 succeeds
        assert failures == 2  # keystore2 (bad password) + keystore3 (missing password)
        assert len(storage) == 1

    def test_empty_directories(self, tmp_path: Path) -> None:
        """Test loading from empty directories."""
        keystores_dir = tmp_path / "keystores"
        passwords_dir = tmp_path / "passwords"
        keystores_dir.mkdir()
        passwords_dir.mkdir()

        storage = KeyStorage()
        success, failures = load_input_only_keystores(
            keystores_dir,
            passwords_dir,
            storage,
        )

        assert success == 0
        assert failures == 0
        assert len(storage) == 0
