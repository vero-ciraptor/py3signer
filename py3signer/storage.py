"""In-memory key storage with optional disk persistence."""

import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from py3signer_core import PublicKey, SecretKey

from .metrics import KEYS_LOADED

logger = logging.getLogger(__name__)


@dataclass
class KeyPair:
    """A stored key pair."""

    pubkey: PublicKey
    secret_key: SecretKey
    path: str
    description: str | None = None


class KeyStorage:
    """In-memory storage for BLS keys with optional disk persistence."""

    def __init__(self, keystore_path: Path | None = None) -> None:
        self._keys: dict[str, KeyPair] = {}
        self._keystore_path = keystore_path

    @property
    def keystore_path(self) -> Path | None:
        """Return the keystore path if configured."""
        return self._keystore_path

    def _get_file_paths(self, pubkey_hex: str) -> tuple[Path, Path]:
        """Get the file paths for a keystore and its password file."""
        if self._keystore_path is None:
            raise RuntimeError("keystore_path not configured")

        base_name = pubkey_hex.lower()
        return (
            self._keystore_path / f"{base_name}.json",
            self._keystore_path / f"{base_name}.txt",
        )

    def _save_to_disk(self, pubkey_hex: str, keystore_json: str, password: str) -> bool:
        """Atomically save a keystore and password to disk."""
        if self._keystore_path is None:
            return False

        keystore_file, password_file = self._get_file_paths(pubkey_hex)
        self._keystore_path.mkdir(parents=True, exist_ok=True)

        keystore_temp = password_temp = None

        try:
            # Atomic writes using temp files
            with tempfile.NamedTemporaryFile(
                mode="w", dir=self._keystore_path, suffix=".tmp", delete=False
            ) as f:
                f.write(keystore_json)
                keystore_temp = f.name

            with tempfile.NamedTemporaryFile(
                mode="w", dir=self._keystore_path, suffix=".tmp", delete=False
            ) as f:
                f.write(password)
                password_temp = f.name

            os.rename(keystore_temp, keystore_file)
            os.rename(password_temp, password_file)

            logger.info(f"Saved keystore to disk: {keystore_file.name}")
            return True

        except Exception as e:
            logger.warning(f"Failed to save keystore to disk: {e}")
            # Cleanup temp files
            for temp in (keystore_temp, password_temp):
                if temp:
                    try:
                        os.unlink(temp)
                    except OSError:
                        pass
            return False

    def _delete_from_disk(self, pubkey_hex: str) -> bool:
        """Delete keystore and password files from disk."""
        if self._keystore_path is None:
            return False

        try:
            keystore_file, password_file = self._get_file_paths(pubkey_hex)

            for file_path in (keystore_file, password_file):
                if file_path.exists():
                    file_path.unlink()
                    logger.info(f"Deleted from disk: {file_path.name}")

            return True
        except Exception as e:
            logger.warning(f"Failed to delete keystore from disk: {e}")
            return False

    def add_key(
        self,
        pubkey: PublicKey,
        secret_key: SecretKey,
        path: str = "m/12381/3600/0/0/0",
        description: str | None = None,
        keystore_json: str | None = None,
        password: str | None = None,
    ) -> tuple[str, bool]:
        """Add a key to storage. Optionally persists to disk if keystore_path is set.

        Returns:
            Tuple of (pubkey_hex, persisted) where persisted indicates if disk write occurred.
        """
        pubkey_hex = pubkey.to_bytes().hex()

        if pubkey_hex in self._keys:
            raise ValueError(f"Key already exists: {pubkey_hex}")

        self._keys[pubkey_hex] = KeyPair(
            pubkey=pubkey, secret_key=secret_key, path=path, description=description
        )
        KEYS_LOADED.set(len(self._keys))
        logger.info(f"Added key: {pubkey_hex[:20]}...")

        persisted = False
        if self._keystore_path is not None and keystore_json is not None and password is not None:
            persisted = self._save_to_disk(pubkey_hex, keystore_json, password)

        return pubkey_hex, persisted

    def get_key(self, pubkey_hex: str) -> KeyPair | None:
        """Get a key pair by public key hex."""
        return self._keys.get(pubkey_hex)

    def list_keys(self) -> list[tuple[str, str, str | None]]:
        """List all stored keys as (pubkey_hex, path, description) tuples."""
        return [(h, k.path, k.description) for h, k in self._keys.items()]

    def remove_key(self, pubkey_hex: str) -> tuple[bool, bool]:
        """Remove a key from storage. Optionally deletes from disk if keystore_path is set.

        Returns:
            Tuple of (removed_from_memory, deleted_from_disk).
        """
        if pubkey_hex not in self._keys:
            return False, False

        del self._keys[pubkey_hex]
        KEYS_LOADED.set(len(self._keys))
        logger.info(f"Removed key: {pubkey_hex[:20]}...")

        deleted_from_disk = False
        if self._keystore_path is not None:
            deleted_from_disk = self._delete_from_disk(pubkey_hex)

        return True, deleted_from_disk

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
