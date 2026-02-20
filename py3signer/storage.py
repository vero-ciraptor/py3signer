"""In-memory key storage with optional disk persistence."""

import logging
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .models import KeyInfo
from .path_utils import (
    get_keystore_paths,
)

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

    Supports two separate storage locations:
    - External keystores (--keystores-path): Keys stay in external directory, NOT copied
    - Managed keystores (data_dir/keystores): Keys imported via API are stored here

    Keys are tracked separately by source:
    - External keys: loaded from --keystores-path, deletable (deletes from external path)
    - Managed keys: imported via API, stored in data_dir/keystores
    """

    def __init__(
        self,
        data_dir: Path | None = None,
        external_keystores_path: Path | None = None,
    ) -> None:
        self._keys: dict[str, KeyPair] = {}
        # Track which keys are from external source vs managed
        self._external_keys: set[str] = set()
        self._managed_keys: set[str] = set()

        self._data_dir = data_dir
        self._managed_keystores_dir = self._get_managed_keystores_dir(data_dir)
        self._external_keystores_path = external_keystores_path

    def _update_keys_metric(self) -> None:
        """Update the keys_loaded metric (lazily imported to ensure proper setup order)."""
        from .metrics import KEYS_LOADED

        KEYS_LOADED.set(len(self._keys))

    def _get_managed_keystores_dir(self, data_dir: Path | None) -> Path | None:
        """Get the managed keystores directory path.

        Args:
            data_dir: The base data directory, or None for in-memory only.

        Returns:
            Path to managed keystores subdirectory, or None if data_dir is None.

        """
        if data_dir is None:
            return None
        return data_dir / "keystores"

    @property
    def data_dir(self) -> Path | None:
        """Return the data directory if configured."""
        return self._data_dir

    @property
    def managed_keystores_dir(self) -> Path | None:
        """Return the managed keystores directory path if configured."""
        return self._managed_keystores_dir

    @property
    def external_keystores_path(self) -> Path | None:
        """Return the external keystores path if configured."""
        return self._external_keystores_path

    def ensure_managed_keystores_dir(self) -> Path | None:
        """Ensure the managed keystores directory exists.

        Returns:
            Path to managed keystores directory, or None if no data_dir configured.

        """
        if self._managed_keystores_dir is not None:
            self._managed_keystores_dir.mkdir(parents=True, exist_ok=True)
        return self._managed_keystores_dir

    def _get_managed_file_paths(self, pubkey_hex: str) -> tuple[Path, Path]:
        """Get the file paths for a managed keystore and its password file."""
        if self._managed_keystores_dir is None:
            raise RuntimeError("managed_keystores_dir not configured (no data_dir)")

        return get_keystore_paths(self._managed_keystores_dir, pubkey_hex)

    def _get_external_file_paths(
        self, pubkey_hex: str
    ) -> tuple[Path | None, Path | None]:
        """Get the file paths for an external keystore and its password file.

        Returns:
            Tuple of (keystore_path, password_path) or (None, None) if external path not configured.
        """
        if self._external_keystores_path is None:
            return None, None

        keystore_path, password_path = get_keystore_paths(
            self._external_keystores_path, pubkey_hex
        )
        return keystore_path, password_path

    def _save_to_managed_storage(
        self, pubkey_hex: str, keystore_json: str, password: str
    ) -> bool:
        """Atomically save a keystore and password to managed storage."""
        if self._managed_keystores_dir is None:
            return False

        self.ensure_managed_keystores_dir()

        keystore_file, password_file = self._get_managed_file_paths(pubkey_hex)

        keystore_temp = password_temp = None
        try:
            # Atomic writes using temp files
            with tempfile.NamedTemporaryFile(
                mode="w",
                dir=self._managed_keystores_dir,
                suffix=".tmp",
                delete=False,
            ) as f:
                f.write(keystore_json)
                keystore_temp = Path(f.name)

            with tempfile.NamedTemporaryFile(
                mode="w",
                dir=self._managed_keystores_dir,
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
            logger.info(f"Saved keystore to managed storage: {keystore_file.name}")
            return True

    def _delete_from_managed_storage(self, pubkey_hex: str) -> bool:
        """Delete keystore and password files from managed storage."""
        if self._managed_keystores_dir is None:
            return False

        try:
            keystore_file, password_file = self._get_managed_file_paths(pubkey_hex)

            for file_path in (keystore_file, password_file):
                if file_path.exists():
                    file_path.unlink()
                    logger.info(f"Deleted from managed storage: {file_path.name}")
        except Exception as e:
            logger.warning(f"Failed to delete keystore from managed storage: {e}")
            return False
        else:
            return True

    def _delete_from_external_storage(self, pubkey_hex: str) -> bool:
        """Delete keystore and password files from external storage.

        Also deletes the accompanying password file.
        """
        if self._external_keystores_path is None:
            return False

        try:
            keystore_file, password_file = self._get_external_file_paths(pubkey_hex)

            if keystore_file is None or password_file is None:
                return False

            # Delete both keystore and password file
            for file_path in (keystore_file, password_file):
                if file_path.exists():
                    file_path.unlink()
                    logger.info(f"Deleted from external storage: {file_path.name}")
        except Exception as e:
            logger.warning(f"Failed to delete keystore from external storage: {e}")
            return False
        else:
            return True

    def add_external_key(
        self,
        pubkey: PublicKey,
        secret_key: SecretKey,
        path: str = "m/12381/3600/0/0/0",
        description: str | None = None,
    ) -> str:
        """Add an external key to storage (from --keystores-path).

        External keys are NOT persisted to managed storage - they stay in their
        original location. They are tracked separately for deletion purposes.

        Args:
            pubkey: The public key
            secret_key: The secret key
            path: The derivation path
            description: Optional description

        Returns:
            The pubkey_hex of the added key

        Raises:
            ValueError: If key already exists

        """
        pubkey_hex: str = pubkey.to_bytes().hex()

        if pubkey_hex in self._keys:
            raise ValueError(f"Key already exists: {pubkey_hex}")

        self._keys[pubkey_hex] = KeyPair(
            pubkey=pubkey,
            secret_key=secret_key,
            path=path,
            description=description,
        )
        self._external_keys.add(pubkey_hex)
        self._update_keys_metric()
        logger.info(f"Added external key: {pubkey_hex[:20]}...")

        return pubkey_hex

    def add_key(
        self,
        pubkey: PublicKey,
        secret_key: SecretKey,
        path: str = "m/12381/3600/0/0/0",
        description: str | None = None,
        keystore_json: str | None = None,
        password: str | None = None,
    ) -> tuple[str, bool]:
        """Add a managed key to storage (imported via API).

        Keys are persisted to managed storage (data_dir/keystores) if data_dir is set.

        Args:
            pubkey: The public key
            secret_key: The secret key
            path: The derivation path
            description: Optional description
            keystore_json: Optional keystore JSON for persistence
            password: Optional password for persistence

        Returns:
            Tuple of (pubkey_hex, persisted) where persisted indicates if disk write occurred.

        Raises:
            ValueError: If key already exists

        """
        pubkey_hex: str = pubkey.to_bytes().hex()

        if pubkey_hex in self._keys:
            raise ValueError(f"Key already exists: {pubkey_hex}")

        self._keys[pubkey_hex] = KeyPair(
            pubkey=pubkey,
            secret_key=secret_key,
            path=path,
            description=description,
        )
        self._managed_keys.add(pubkey_hex)
        self._update_keys_metric()
        logger.info(f"Added managed key: {pubkey_hex[:20]}...")

        persisted_to_disk = False
        if (
            self._managed_keystores_dir is not None
            and keystore_json is not None
            and password is not None
        ):
            persisted_to_disk = self._save_to_managed_storage(
                pubkey_hex, keystore_json, password
            )

        return pubkey_hex, persisted_to_disk

    def get_key(self, pubkey_hex: str) -> KeyPair | None:
        """Get a key pair by public key hex."""
        return self._keys.get(pubkey_hex)

    def is_external_key(self, pubkey_hex: str) -> bool:
        """Check if a key is from external storage (--keystores-path)."""
        return pubkey_hex in self._external_keys

    def is_managed_key(self, pubkey_hex: str) -> bool:
        """Check if a key is a managed key (imported via API)."""
        return pubkey_hex in self._managed_keys

    def list_keys(self) -> list[KeyInfo]:
        """List all stored keys.

        Returns:
            List of KeyInfo objects containing key metadata.
        """
        return [
            KeyInfo(
                pubkey_hex=pubkey_hex,
                path=key_pair.path,
                description=key_pair.description,
                is_external=pubkey_hex in self._external_keys,
            )
            for pubkey_hex, key_pair in self._keys.items()
        ]

    def _remove_from_tracking(self, pubkey_hex: str) -> tuple[bool, bool]:
        """Remove key from internal tracking sets.

        Args:
            pubkey_hex: The public key hex to remove

        Returns:
            Tuple of (was_external, was_managed)

        """
        is_external = pubkey_hex in self._external_keys
        is_managed = pubkey_hex in self._managed_keys

        del self._keys[pubkey_hex]
        if is_external:
            self._external_keys.discard(pubkey_hex)
        if is_managed:
            self._managed_keys.discard(pubkey_hex)

        self._update_keys_metric()
        logger.info(f"Removed key: {pubkey_hex[:20]}...")

        return is_external, is_managed

    def remove_key(self, pubkey_hex: str) -> None:
        """Remove a key from storage and delete from disk.

        Deletion logic:
        1. Check if key exists in external path first, if yes: delete from there + delete password file
        2. If not in external, check managed path, if yes: delete from there
        3. A key could exist in both (edge case), handle appropriately

        Raises:
            KeyNotFound: If key doesn't exist in storage
        """
        if pubkey_hex not in self._keys:
            raise KeyNotFound

        _is_external, is_managed = self._remove_from_tracking(pubkey_hex)

        # Deletion logic:
        # 1. Check external first (priority), delete if exists
        external_keystore, _ = self._get_external_file_paths(pubkey_hex)
        deleted_from_external = False
        if external_keystore and external_keystore.exists():
            self._delete_from_external_storage(pubkey_hex)
            deleted_from_external = True

        # 2. Also check managed storage (key could exist in both locations)
        if self._managed_keystores_dir is not None:
            managed_keystore, _ = self._get_managed_file_paths(pubkey_hex)
            # Only delete from managed if not already deleted from external
            # OR if it's a managed key (we want to clean up managed storage)
            if managed_keystore.exists() and (not deleted_from_external or is_managed):
                self._delete_from_managed_storage(pubkey_hex)

    def get_secret_key(self, pubkey_hex: str) -> SecretKey | None:
        """Get the secret key for a given public key."""
        kp = self._keys.get(pubkey_hex)
        return kp.secret_key if kp else None

    def __len__(self) -> int:
        return len(self._keys)

    def clear(self) -> None:
        """Clear all keys (useful for testing)."""
        self._keys.clear()
        self._external_keys.clear()
        self._managed_keys.clear()
        self._update_keys_metric()
