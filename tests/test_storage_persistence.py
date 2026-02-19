"""Tests for keystore storage persistence."""

from typing import TYPE_CHECKING
from unittest.mock import MagicMock

import pytest

from py3signer.storage import KeyNotFound, KeyStorage

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def temp_keystore_dir(tmp_path: Path) -> Path:
    """Create a temporary directory for keystore files."""
    keystore_dir = tmp_path / "keystores"
    keystore_dir.mkdir()
    return keystore_dir


@pytest.fixture
def temp_data_dir(tmp_path: Path) -> Path:
    """Create a temporary data directory."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    return data_dir


class TestStoragePersistence:
    """Test keystore persistence functionality."""

    def test_storage_without_data_dir(self) -> None:
        """Test that storage works without a data_dir (in-memory only)."""
        storage = KeyStorage()
        assert storage.data_dir is None
        assert storage.keystore_path is None

    def test_storage_with_data_dir(self, temp_data_dir: Path) -> None:
        """Test that storage accepts a data_dir and creates keystores subdirectory."""
        storage = KeyStorage(data_dir=temp_data_dir)
        assert storage.data_dir == temp_data_dir
        assert storage.keystore_path == temp_data_dir / "keystores"

    def test_storage_with_external_path(self, tmp_path: Path) -> None:
        """Test that storage accepts an external keystores path."""
        external_path = tmp_path / "external"
        external_path.mkdir()
        storage = KeyStorage(external_keystores_path=external_path)
        assert storage.external_keystores_path == external_path

    def test_storage_with_both_paths(self, tmp_path: Path) -> None:
        """Test that storage accepts both data_dir and external path."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        external_path = tmp_path / "external"
        external_path.mkdir()

        storage = KeyStorage(
            data_dir=data_dir,
            external_keystores_path=external_path,
        )
        assert storage.data_dir == data_dir
        assert storage.external_keystores_path == external_path

    def test_add_key_with_persistence(self, temp_data_dir: Path) -> None:
        """Test adding a managed key with persistence enabled."""
        storage = KeyStorage(data_dir=temp_data_dir)
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
        # Files should be in data_dir/keystores/
        keystores_dir = temp_data_dir / "keystores"
        assert (keystores_dir / f"{pubkey_hex_str}.json").exists()
        assert (keystores_dir / f"{pubkey_hex_str}.txt").exists()

        # Verify content
        with (keystores_dir / f"{pubkey_hex_str}.json").open() as f:
            assert f.read() == keystore_json
        with (keystores_dir / f"{pubkey_hex_str}.txt").open() as f:
            assert f.read() == password

    def test_add_external_key_no_persistence(self, tmp_path: Path) -> None:
        """Test adding an external key does not persist to managed storage."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        external_path = tmp_path / "external"
        external_path.mkdir()

        storage = KeyStorage(
            data_dir=data_dir,
            external_keystores_path=external_path,
        )
        pubkey = MagicMock()
        pubkey_hex_str = "aabbccdd" * 12
        pubkey.to_bytes.return_value = bytes.fromhex(pubkey_hex_str)
        secret_key = MagicMock()

        # Add as external key
        result_pubkey_hex = storage.add_external_key(
            pubkey=pubkey,
            secret_key=secret_key,
            path="m/12381/3600/0/0/0",
        )

        assert result_pubkey_hex == pubkey_hex_str
        # External keys should NOT be persisted to managed storage
        keystores_dir = data_dir / "keystores"
        assert not (keystores_dir / f"{pubkey_hex_str}.json").exists()
        assert not (keystores_dir / f"{pubkey_hex_str}.txt").exists()

        # Key should be tracked as external
        assert storage.is_external_key(pubkey_hex_str)
        assert not storage.is_managed_key(pubkey_hex_str)

    def test_add_key_without_persistence(self) -> None:
        """Test adding a key when persistence is disabled (no data_dir)."""
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
        """Test that add_key creates the keystores directory if it doesn't exist."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        storage = KeyStorage(data_dir=data_dir)

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
        assert (data_dir / "keystores").exists()

    def test_remove_managed_key_with_persistence(self, temp_data_dir: Path) -> None:
        """Test removing a managed key with persistence enabled."""
        storage = KeyStorage(data_dir=temp_data_dir)
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

        storage.remove_key(pubkey_hex)
        keystores_dir = temp_data_dir / "keystores"
        assert not (keystores_dir / f"{pubkey_hex}.json").exists()
        assert not (keystores_dir / f"{pubkey_hex}.txt").exists()

    def test_remove_external_key_deletes_password_file(self, tmp_path: Path) -> None:
        """Test removing an external key also deletes the password file."""
        external_path = tmp_path / "external"
        external_path.mkdir()
        storage = KeyStorage(external_keystores_path=external_path)

        pubkey_hex = "aabbccdd" * 12
        pubkey = MagicMock()
        pubkey.to_bytes.return_value = bytes.fromhex(pubkey_hex)
        secret_key = MagicMock()

        # Create external keystore files
        (external_path / f"{pubkey_hex}.json").write_text('{"version": 4}')
        (external_path / f"{pubkey_hex}.txt").write_text("externalpass")

        # Add as external key
        storage.add_external_key(pubkey=pubkey, secret_key=secret_key)

        # Remove the key
        storage.remove_key(pubkey_hex)

        # Both keystore and password file should be deleted from external path
        assert not (external_path / f"{pubkey_hex}.json").exists()
        assert not (external_path / f"{pubkey_hex}.txt").exists()

    def test_remove_key_not_in_storage(self, temp_data_dir: Path) -> None:
        """Test removing a key that doesn't exist in storage."""
        storage = KeyStorage(data_dir=temp_data_dir)
        pubkey_hex = "nonexistent" * 6

        with pytest.raises(KeyNotFound):
            storage.remove_key(pubkey_hex)

    def test_remove_key_without_persistence(self) -> None:
        """Test removing a key without persistence."""
        storage = KeyStorage()
        pubkey_hex = "aabbccdd" * 12
        pubkey = MagicMock()
        pubkey.to_bytes.return_value = bytes.fromhex(pubkey_hex)
        secret_key = MagicMock()

        # Add key without persistence
        storage.add_key(pubkey=pubkey, secret_key=secret_key)

        storage.remove_key(pubkey_hex)

    def test_atomic_write(self, temp_data_dir: Path) -> None:
        """Test that keystore writes are atomic (temp file + rename)."""
        storage = KeyStorage(data_dir=temp_data_dir)
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
        keystores_dir = temp_data_dir / "keystores"
        temp_files = list(keystores_dir.glob("*.tmp"))
        assert len(temp_files) == 0

    def test_pubkey_hex_normalization(self, temp_data_dir: Path) -> None:
        """Test that pubkey hex is normalized to lowercase."""
        storage = KeyStorage(data_dir=temp_data_dir)
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
        keystores_dir = temp_data_dir / "keystores"
        assert (keystores_dir / f"{pubkey_hex_lower}.json").exists()

    def test_overwrite_existing_keystore(self, temp_data_dir: Path) -> None:
        """Test that saving over an existing keystore overwrites it."""
        storage = KeyStorage(data_dir=temp_data_dir)
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

        keystores_dir = temp_data_dir / "keystores"
        # Verify overwritten content
        with (keystores_dir / f"{pubkey_hex}.json").open() as f:
            assert '"version": 5' in f.read()
        with (keystores_dir / f"{pubkey_hex}.txt").open() as f:
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

    def test_add_external_key_duplicate_raises(self) -> None:
        """Test that adding a duplicate external key raises ValueError."""
        storage = KeyStorage()
        pubkey_hex = "aabbccdd" * 12
        pubkey = MagicMock()
        pubkey.to_bytes.return_value = bytes.fromhex(pubkey_hex)
        secret_key = MagicMock()

        # Add first time as external
        storage.add_external_key(pubkey=pubkey, secret_key=secret_key)

        # Add second time should raise
        with pytest.raises(ValueError, match=f"Key already exists: {pubkey_hex}"):
            storage.add_external_key(pubkey=pubkey, secret_key=secret_key)

    def test_mixed_external_and_managed_keys(self, tmp_path: Path) -> None:
        """Test storage handles both external and managed keys."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        external_path = tmp_path / "external"
        external_path.mkdir()

        storage = KeyStorage(
            data_dir=data_dir,
            external_keystores_path=external_path,
        )

        # Add external key
        ext_pubkey = MagicMock()
        ext_pubkey_hex = "aabbccdd" * 12
        ext_pubkey.to_bytes.return_value = bytes.fromhex(ext_pubkey_hex)
        storage.add_external_key(pubkey=ext_pubkey, secret_key=MagicMock())

        # Add managed key
        mng_pubkey = MagicMock()
        mng_pubkey_hex = "11223344" * 12
        mng_pubkey.to_bytes.return_value = bytes.fromhex(mng_pubkey_hex)
        storage.add_key(
            pubkey=mng_pubkey,
            secret_key=MagicMock(),
            keystore_json="{}",
            password="pass",
        )

        # Both should be in list
        keys = storage.list_keys()
        assert len(keys) == 2

        # Check is_external flag
        key_dict = {k[0]: k[3] for k in keys}  # pubkey_hex -> is_external
        assert key_dict[ext_pubkey_hex] is True
        assert key_dict[mng_pubkey_hex] is False

        # Check type tracking
        assert storage.is_external_key(ext_pubkey_hex)
        assert not storage.is_managed_key(ext_pubkey_hex)
        assert storage.is_managed_key(mng_pubkey_hex)
        assert not storage.is_external_key(mng_pubkey_hex)


class TestKeystoreImport:
    """Test importing keystore files from external sources."""

    def test_import_keystore_files(self, tmp_path: Path) -> None:
        """Test importing keystore files from external directory (deprecated)."""
        # Create data_dir for storage
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        storage = KeyStorage(data_dir=data_dir)

        # Create source directory with keystore files
        source_dir = tmp_path / "source"
        source_dir.mkdir()
        pubkey_hex = "aabbccdd" * 12

        # Create source files
        (source_dir / f"{pubkey_hex}.json").write_text('{"version": 4}')
        (source_dir / f"{pubkey_hex}.txt").write_text("testpassword")

        # Import files (deprecated method)
        result = storage.import_keystore_files(source_dir, pubkey_hex)

        # Verify files were copied
        keystores_dir = data_dir / "keystores"
        assert result == (
            keystores_dir / f"{pubkey_hex}.json",
            keystores_dir / f"{pubkey_hex}.txt",
        )
        assert (keystores_dir / f"{pubkey_hex}.json").exists()
        assert (keystores_dir / f"{pubkey_hex}.txt").exists()
        assert (keystores_dir / f"{pubkey_hex}.json").read_text() == '{"version": 4}'
        assert (keystores_dir / f"{pubkey_hex}.txt").read_text() == "testpassword"

    def test_import_keystore_files_no_data_dir(self, tmp_path: Path) -> None:
        """Test importing when no data_dir is configured."""
        storage = KeyStorage()  # No data_dir
        source_dir = tmp_path / "source"
        source_dir.mkdir()
        pubkey_hex = "aabbccdd" * 12

        result = storage.import_keystore_files(source_dir, pubkey_hex)
        assert result == (None, None)

    def test_import_keystore_files_missing_source(self, tmp_path: Path) -> None:
        """Test importing when source files don't exist."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        storage = KeyStorage(data_dir=data_dir)

        source_dir = tmp_path / "source"
        source_dir.mkdir()
        pubkey_hex = "aabbccdd" * 12

        # Don't create any files
        result = storage.import_keystore_files(source_dir, pubkey_hex)
        assert result == (None, None)


class TestKeyDeletion:
    """Test key deletion with external and managed storage."""

    def test_delete_external_key_priority(self, tmp_path: Path) -> None:
        """Test that external key is deleted first if exists in both locations."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        external_path = tmp_path / "external"
        external_path.mkdir()

        storage = KeyStorage(
            data_dir=data_dir,
            external_keystores_path=external_path,
        )

        pubkey_hex = "aabbccdd" * 12
        pubkey = MagicMock()
        pubkey.to_bytes.return_value = bytes.fromhex(pubkey_hex)

        # Create files in both locations
        keystores_dir = data_dir / "keystores"
        keystores_dir.mkdir()
        (keystores_dir / f"{pubkey_hex}.json").write_text('{"managed": true}')
        (keystores_dir / f"{pubkey_hex}.txt").write_text("managedpass")

        (external_path / f"{pubkey_hex}.json").write_text('{"external": true}')
        (external_path / f"{pubkey_hex}.txt").write_text("externalpass")

        # Add as external key (could exist in both)
        storage.add_external_key(pubkey=pubkey, secret_key=MagicMock())

        # Remove the key
        storage.remove_key(pubkey_hex)

        # External files should be deleted
        assert not (external_path / f"{pubkey_hex}.json").exists()
        assert not (external_path / f"{pubkey_hex}.txt").exists()

        # Managed files should remain (key was tracked as external)
        # Note: current implementation deletes from managed only if is_managed is True
        assert (keystores_dir / f"{pubkey_hex}.json").exists()
        assert (keystores_dir / f"{pubkey_hex}.txt").exists()

    def test_delete_managed_key_when_not_in_external(self, tmp_path: Path) -> None:
        """Test deleting managed key when it doesn't exist in external storage."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        external_path = tmp_path / "external"
        external_path.mkdir()

        storage = KeyStorage(
            data_dir=data_dir,
            external_keystores_path=external_path,
        )

        pubkey_hex = "aabbccdd" * 12
        pubkey = MagicMock()
        pubkey.to_bytes.return_value = bytes.fromhex(pubkey_hex)

        # Add as managed key
        storage.add_key(
            pubkey=pubkey,
            secret_key=MagicMock(),
            keystore_json='{"managed": true}',
            password="managedpass",
        )

        # Remove the key
        storage.remove_key(pubkey_hex)

        # Files should be deleted from managed storage
        keystores_dir = data_dir / "keystores"
        assert not (keystores_dir / f"{pubkey_hex}.json").exists()
        assert not (keystores_dir / f"{pubkey_hex}.txt").exists()


class TestUnifiedKeyHandling:
    """Test unified key handling behavior."""

    def test_all_keys_deletable(self, tmp_path: Path) -> None:
        """Test that all keys are deletable regardless of source."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        external_path = tmp_path / "external"
        external_path.mkdir()

        storage = KeyStorage(
            data_dir=data_dir,
            external_keystores_path=external_path,
        )

        # Add external and managed keys
        for i, is_external in enumerate([True, False, True]):
            pubkey_hex = f"aabbccdd{i:02d}" * 12
            pubkey = MagicMock()
            pubkey.to_bytes.return_value = bytes.fromhex(pubkey_hex)
            secret_key = MagicMock()

            if is_external:
                storage.add_external_key(pubkey=pubkey, secret_key=secret_key)
            else:
                storage.add_key(
                    pubkey=pubkey,
                    secret_key=secret_key,
                    keystore_json='{"version": 4}',
                    password=f"pass{i}",
                )

        # All keys should be deletable
        for i in range(3):
            pubkey_hex = f"aabbccdd{i:02d}" * 12
            storage.remove_key(pubkey_hex)
            assert storage.get_key(pubkey_hex) is None

        assert len(storage) == 0

    def test_managed_keys_persisted_when_data_dir_set(self, tmp_path: Path) -> None:
        """Test that managed keys are persisted when data_dir is set."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        storage = KeyStorage(data_dir=data_dir)

        pubkey_hex = "aabbccdd" * 12
        pubkey = MagicMock()
        pubkey.to_bytes.return_value = bytes.fromhex(pubkey_hex)
        secret_key = MagicMock()

        _, persisted = storage.add_key(
            pubkey=pubkey,
            secret_key=secret_key,
            keystore_json='{"version": 4}',
            password="testpass",
        )

        assert persisted is True
        keystores_dir = data_dir / "keystores"
        assert (keystores_dir / f"{pubkey_hex}.json").exists()

    def test_external_keys_not_persisted_to_managed(self, tmp_path: Path) -> None:
        """Test that external keys are NOT persisted to managed storage."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        external_path = tmp_path / "external"
        external_path.mkdir()

        storage = KeyStorage(
            data_dir=data_dir,
            external_keystores_path=external_path,
        )

        pubkey_hex = "aabbccdd" * 12
        pubkey = MagicMock()
        pubkey.to_bytes.return_value = bytes.fromhex(pubkey_hex)

        # Create external files
        (external_path / f"{pubkey_hex}.json").write_text('{"version": 4}')
        (external_path / f"{pubkey_hex}.txt").write_text("externalpass")

        # Add as external key
        storage.add_external_key(pubkey=pubkey, secret_key=MagicMock())

        # Should not be persisted to managed storage
        keystores_dir = data_dir / "keystores"
        assert not (keystores_dir / f"{pubkey_hex}.json").exists()
        assert not (keystores_dir / f"{pubkey_hex}.txt").exists()

    def test_no_keys_persisted_without_data_dir(self) -> None:
        """Test that no keys are persisted when data_dir is not set."""
        storage = KeyStorage()  # No data_dir

        pubkey = MagicMock()
        pubkey.to_bytes.return_value = bytes.fromhex("aabbccdd" * 12)
        secret_key = MagicMock()

        _, persisted = storage.add_key(
            pubkey=pubkey,
            secret_key=secret_key,
            keystore_json='{"version": 4}',
            password="testpass",
        )

        assert persisted is False
