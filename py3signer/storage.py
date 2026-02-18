"""In-memory key storage with optional disk persistence."""

import json
import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import cast

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
        self._keys: dict[str, KeyPair] = {}  # pubkey_hex -> KeyPair
        self._logger = logging.getLogger(__name__)
        self._keystore_path = keystore_path

    @property
    def keystore_path(self) -> Path | None:
        """Return the keystore path if configured."""
        return self._keystore_path

    def _get_keystore_file_paths(self, pubkey_hex: str) -> tuple[Path, Path]:
        """Get the file paths for a keystore and its password file.

        Args:
            pubkey_hex: The public key hex string (without 0x prefix)

        Returns:
            Tuple of (keystore_path, password_path)
        """
        if self._keystore_path is None:
            raise RuntimeError("keystore_path not configured")

        base_name = pubkey_hex.lower()
        keystore_file = self._keystore_path / f"{base_name}.json"
        password_file = self._keystore_path / f"{base_name}.txt"
        return keystore_file, password_file

    def save_keystore_to_disk(
        self, pubkey_hex: str, keystore_json: str, password: str
    ) -> bool:
        """Save a keystore and its password to disk.

        Uses atomic writes (temp file + rename) to avoid corruption.

        Args:
            pubkey_hex: The public key hex string
            keystore_json: The EIP-2335 keystore JSON string
            password: The keystore password

        Returns:
            True if saved successfully, False otherwise
        """
        if self._keystore_path is None:
            return False

        try:
            keystore_file, password_file = self._get_keystore_file_paths(pubkey_hex)

            # Ensure directory exists
            self._keystore_path.mkdir(parents=True, exist_ok=True)

            # Atomic write for keystore JSON
            with tempfile.NamedTemporaryFile(
                mode="w",
                dir=self._keystore_path,
                prefix=f".{pubkey_hex}_keystore_",
                suffix=".tmp",
                delete=False,
            ) as f:
                f.write(keystore_json)
                keystore_temp = f.name

            # Atomic write for password
            with tempfile.NamedTemporaryFile(
                mode="w",
                dir=self._keystore_path,
                prefix=f".{pubkey_hex}_password_",
                suffix=".tmp",
                delete=False,
            ) as f:
                f.write(password)
                password_temp = f.name

            # Atomic rename
            os.rename(keystore_temp, keystore_file)
            os.rename(password_temp, password_file)

            self._logger.info(f"Saved keystore to disk: {keystore_file.name}")
            return True

        except Exception as e:
            self._logger.warning(f"Failed to save keystore to disk: {e}")
            # Cleanup temp files if they exist
            try:
                if "keystore_temp" in locals() and os.path.exists(keystore_temp):
                    os.unlink(keystore_temp)
            except Exception:
                pass
            try:
                if "password_temp" in locals() and os.path.exists(password_temp):
                    os.unlink(password_temp)
            except Exception:
                pass
            return False

    def delete_keystore_from_disk(self, pubkey_hex: str) -> bool:
        """Delete a keystore and its password file from disk.

        Args:
            pubkey_hex: The public key hex string

        Returns:
            True if both files were deleted or didn't exist, False on error
        """
        if self._keystore_path is None:
            return False

        try:
            keystore_file, password_file = self._get_keystore_file_paths(pubkey_hex)

            # Delete keystore file if it exists
            if keystore_file.exists():
                keystore_file.unlink()
                self._logger.info(f"Deleted keystore from disk: {keystore_file.name}")

            # Delete password file if it exists
            if password_file.exists():
                password_file.unlink()
                self._logger.info(f"Deleted password from disk: {password_file.name}")

            return True

        except Exception as e:
            self._logger.warning(f"Failed to delete keystore from disk: {e}")
            return False

    def add_key(
        self,
        pubkey: PublicKey,
        secret_key: SecretKey,
        path: str = "m/12381/3600/0/0/0",
        description: str | None = None,
    ) -> str:
        """Add a key to storage. Returns the public key hex."""
        pubkey_bytes = pubkey.to_bytes()
        pubkey_hex = cast(str, pubkey_bytes.hex())

        if pubkey_hex in self._keys:
            raise ValueError(f"Key already exists: {pubkey_hex}")

        self._keys[pubkey_hex] = KeyPair(
            pubkey=pubkey, secret_key=secret_key, path=path, description=description
        )

        # Update metrics
        KEYS_LOADED.set(len(self._keys))

        self._logger.info(f"Added key: {pubkey_hex[:20]}...")
        return pubkey_hex

    def add_key_with_persistence(
        self,
        pubkey: PublicKey,
        secret_key: SecretKey,
        keystore_json: str,
        password: str,
        path: str = "m/12381/3600/0/0/0",
        description: str | None = None,
    ) -> tuple[str, bool]:
        """Add a key to storage and persist to disk if keystore_path is configured.

        Args:
            pubkey: The public key
            secret_key: The secret key
            keystore_json: The EIP-2335 keystore JSON string for persistence
            password: The keystore password for persistence
            path: The derivation path
            description: Optional description

        Returns:
            Tuple of (pubkey_hex, persisted) where persisted indicates if disk write occurred
        """
        pubkey_hex = self.add_key(pubkey, secret_key, path, description)

        persisted = False
        if self._keystore_path is not None:
            persisted = self.save_keystore_to_disk(pubkey_hex, keystore_json, password)

        return pubkey_hex, persisted

    def get_key(self, pubkey_hex: str) -> KeyPair | None:
        """Get a key pair by public key hex."""
        return self._keys.get(pubkey_hex)

    def list_keys(self) -> list[tuple[str, str, str | None]]:
        """List all stored keys. Returns list of (pubkey_hex, path, description)."""
        return [(pubkey_hex, kp.path, kp.description) for pubkey_hex, kp in self._keys.items()]

    def remove_key(self, pubkey_hex: str) -> bool:
        """Remove a key from storage. Returns True if key was found and removed."""
        if pubkey_hex in self._keys:
            del self._keys[pubkey_hex]
            # Update metrics
            KEYS_LOADED.set(len(self._keys))
            self._logger.info(f"Removed key: {pubkey_hex[:20]}...")
            return True
        return False

    def remove_key_with_persistence(self, pubkey_hex: str) -> tuple[bool, bool]:
        """Remove a key from storage and delete from disk if keystore_path is configured.

        Args:
            pubkey_hex: The public key hex string

        Returns:
            Tuple of (removed_from_memory, deleted_from_disk)
        """
        removed_from_memory = self.remove_key(pubkey_hex)

        deleted_from_disk = False
        if removed_from_memory and self._keystore_path is not None:
            deleted_from_disk = self.delete_keystore_from_disk(pubkey_hex)

        return removed_from_memory, deleted_from_disk

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
