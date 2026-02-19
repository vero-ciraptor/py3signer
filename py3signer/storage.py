"""In-memory key storage with optional disk persistence."""

import logging
import shutil
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .metrics import KEYS_LOADED

if TYPE_CHECKING:
    from py3signer_core import PublicKey, SecretKey

logger = logging.getLogger(__name__)


@dataclass
class KeyPair:
    """A stored key pair."""

    pubkey: PublicKey
    secret_key: SecretKey
    path: str
    description: str | None = None


class KeyNotFound(Exception):
    pass


class KeyStorage:
    """In-memory storage for BLS keys with optional disk persistence.

    All keys are stored in a unified location: data_dir / "keystores"
    Keys loaded from external sources are imported (copied) to this location.
    All keys are deletable and persisted to disk when a data_dir is configured.
    """

    def __init__(self, data_dir: Path | None = None) -> None:
        self._keys: dict[str, KeyPair] = {}
        self._data_dir = data_dir
        self._keystores_dir = self._get_keystores_dir(data_dir)

    def _get_keystores_dir(self, data_dir: Path | None) -> Path | None:
        """Get the unified keystores directory path.

        Args:
            data_dir: The base data directory, or None for in-memory only.

        Returns:
            Path to keystores subdirectory, or None if data_dir is None.

        """
        if data_dir is None:
            return None
        return data_dir / "keystores"

    @property
    def data_dir(self) -> Path | None:
        """Return the data directory if configured."""
        return self._data_dir

    @property
    def keystore_path(self) -> Path | None:
        """Return the keystores directory path if configured.

        Deprecated: Use data_dir property instead. The keystores are always
        stored in data_dir / "keystores".
        """
        return self._keystores_dir

    def ensure_keystores_dir(self) -> Path | None:
        """Ensure the keystores directory exists.

        Returns:
            Path to keystores directory, or None if no data_dir configured.

        """
        if self._keystores_dir is not None:
            self._keystores_dir.mkdir(parents=True, exist_ok=True)
        return self._keystores_dir

    def import_keystore_files(
        self,
        source_dir: Path,
        pubkey_hex: str,
    ) -> tuple[Path | None, Path | None]:
        """Import keystore files from a source directory to unified storage.

        Args:
            source_dir: Directory containing the source keystore files.
            pubkey_hex: The public key hex string (base name for files).

        Returns:
            Tuple of (imported_keystore_path, imported_password_path) or (None, None)
            if import failed.

        """
        if self._keystores_dir is None:
            logger.warning("Cannot import keystore: no data_dir configured")
            return None, None

        source_keystore = source_dir / f"{pubkey_hex}.json"
        source_password = source_dir / f"{pubkey_hex}.txt"

        if not source_keystore.exists():
            logger.warning(f"Source keystore not found: {source_keystore}")
            return None, None
        if not source_password.exists():
            logger.warning(f"Source password not found: {source_password}")
            return None, None

        self.ensure_keystores_dir()
        dest_keystore = self._keystores_dir / f"{pubkey_hex}.json"
        dest_password = self._keystores_dir / f"{pubkey_hex}.txt"

        try:
            shutil.copy2(source_keystore, dest_keystore)
            shutil.copy2(source_password, dest_password)
        except Exception as e:
            logger.error(f"Failed to import keystore files: {e}")
            return None, None
        else:
            logger.info(f"Imported keystore files for {pubkey_hex[:20]}...")
            return dest_keystore, dest_password

    def _get_file_paths(self, pubkey_hex: str) -> tuple[Path, Path]:
        """Get the file paths for a keystore and its password file."""
        if self._keystores_dir is None:
            raise RuntimeError("keystores_dir not configured (no data_dir)")

        base_name = pubkey_hex.lower()
        return (
            self._keystores_dir / f"{base_name}.json",
            self._keystores_dir / f"{base_name}.txt",
        )

    def _save_to_disk(self, pubkey_hex: str, keystore_json: str, password: str) -> bool:
        """Atomically save a keystore and password to disk."""
        if self._keystores_dir is None:
            return False

        self.ensure_keystores_dir()

        keystore_file, password_file = self._get_file_paths(pubkey_hex)

        keystore_temp = password_temp = None
        try:
            # Atomic writes using temp files
            with tempfile.NamedTemporaryFile(
                mode="w",
                dir=self._keystores_dir,
                suffix=".tmp",
                delete=False,
            ) as f:
                f.write(keystore_json)
                keystore_temp = Path(f.name)

            with tempfile.NamedTemporaryFile(
                mode="w",
                dir=self._keystores_dir,
                suffix=".tmp",
                delete=False,
            ) as f:
                f.write(password)
                password_temp = Path(f.name)

            keystore_temp.rename(keystore_file)
            password_temp.rename(password_file)
        except Exception as e:
            logger.exception(f"Failed to save keystore to disk: {e!r}")
            # Cleanup temp files
            for temp in (keystore_temp, password_temp):
                if temp:
                    with suppress(OSError):
                        temp.unlink()
            return False
        else:
            logger.info(f"Saved keystore to disk: {keystore_file.name}")
            return True

    def _delete_from_disk(self, pubkey_hex: str) -> bool:
        """Delete keystore and password files from disk."""
        if self._keystores_dir is None:
            return False

        try:
            keystore_file, password_file = self._get_file_paths(pubkey_hex)

            for file_path in (keystore_file, password_file):
                if file_path.exists():
                    file_path.unlink()
                    logger.info(f"Deleted from disk: {file_path.name}")
        except Exception as e:
            logger.warning(f"Failed to delete keystore from disk: {e}")
            return False
        else:
            return True

    def add_key(
        self,
        pubkey: PublicKey,
        secret_key: SecretKey,
        path: str = "m/12381/3600/0/0/0",
        description: str | None = None,
        keystore_json: str | None = None,
        password: str | None = None,
    ) -> tuple[str, bool]:
        """Add a key to storage. Optionally persists to disk if data_dir is set.

        Args:
            pubkey: The public key
            secret_key: The secret key
            path: The derivation path
            description: Optional description
            keystore_json: Optional keystore JSON for persistence
            password: Optional password for persistence

        Returns:
            Tuple of (pubkey_hex, persisted) where persisted indicates if disk write occurred.

        """
        pubkey_hex = pubkey.to_bytes().hex()

        if pubkey_hex in self._keys:
            raise ValueError(f"Key already exists: {pubkey_hex}")

        self._keys[pubkey_hex] = KeyPair(
            pubkey=pubkey,
            secret_key=secret_key,
            path=path,
            description=description,
        )
        KEYS_LOADED.set(len(self._keys))
        logger.info(f"Added key: {pubkey_hex[:20]}...")

        persisted_to_disk = False
        if (
            self._keystores_dir is not None
            and keystore_json is not None
            and password is not None
        ):
            persisted_to_disk = self._save_to_disk(pubkey_hex, keystore_json, password)

        return pubkey_hex, persisted_to_disk

    def get_key(self, pubkey_hex: str) -> KeyPair | None:
        """Get a key pair by public key hex."""
        return self._keys.get(pubkey_hex)

    def list_keys(self) -> list[tuple[str, str, str | None]]:
        """List all stored keys as (pubkey_hex, path, description) tuples."""
        return [(h, k.path, k.description) for h, k in self._keys.items()]

    def remove_key(self, pubkey_hex: str) -> None:
        """Remove a key from storage. Also deletes from disk if data_dir is set."""
        if pubkey_hex not in self._keys:
            raise KeyNotFound

        del self._keys[pubkey_hex]
        KEYS_LOADED.set(len(self._keys))
        logger.info(f"Removed key: {pubkey_hex[:20]}...")

        # Always try to delete from disk if data_dir is configured
        if self._keystores_dir is not None:
            self._delete_from_disk(pubkey_hex)

    def get_secret_key(self, pubkey_hex: str) -> SecretKey | None:
        """Get the secret key for a given public key."""
        kp = self._keys.get(pubkey_hex)
        return kp.secret_key if kp else None

    def __len__(self) -> int:
        return len(self._keys)

    def clear(self) -> None:
        """Clear all keys (useful for testing)."""
        self._keys.clear()
        KEYS_LOADED.set(0)
