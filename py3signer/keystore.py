"""EIP-2335 keystore handling."""

import json
import logging
from pathlib import Path
from typing import Any

from py3signer_core import SecretKey, decrypt_keystore

logger = logging.getLogger(__name__)


class KeystoreError(Exception):
    """Error decrypting or parsing keystore."""

    pass


class Keystore:
    """EIP-2335 keystore representation."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        self._validate()

    @classmethod
    def from_file(cls, path: Path) -> "Keystore":
        """Load keystore from JSON file."""
        try:
            with open(path) as f:
                data = json.load(f)
            return cls(data)
        except json.JSONDecodeError as e:
            raise KeystoreError(f"Invalid JSON: {e}")
        except FileNotFoundError:
            raise KeystoreError(f"Keystore file not found: {path}")

    @classmethod
    def from_json(cls, json_str: str) -> "Keystore":
        """Load keystore from JSON string."""
        try:
            data = json.loads(json_str)
            return cls(data)
        except json.JSONDecodeError as e:
            raise KeystoreError(f"Invalid JSON: {e}")

    def _validate(self) -> None:
        """Validate keystore structure."""
        required = ["crypto", "pubkey", "path", "uuid", "version"]
        for field in required:
            if field not in self.data:
                raise KeystoreError(f"Missing required field: {field}")

        if self.data.get("version") != 4:
            logger.warning(f"Unexpected keystore version: {self.data.get('version')}")

        crypto = self.data.get("crypto", {})
        if "kdf" not in crypto or "checksum" not in crypto or "cipher" not in crypto:
            raise KeystoreError("Invalid crypto structure")

    @property
    def pubkey(self) -> str:
        """Get the public key hex string."""
        return self.data["pubkey"]

    @property
    def uuid(self) -> str:
        """Get the keystore UUID."""
        return self.data["uuid"]

    @property
    def path(self) -> str:
        """Get the derivation path."""
        return self.data["path"]

    @property
    def description(self) -> str | None:
        """Get the optional description."""
        return self.data.get("description")

    def decrypt(self, password: str) -> SecretKey:
        """Decrypt the keystore and return the secret key."""
        try:
            json_str = json.dumps(self.data)
            secret_bytes = decrypt_keystore(json_str, password)

            # Convert list to bytes if necessary (Rust returns Vec<u8> as list)
            if isinstance(secret_bytes, list):
                secret_bytes = bytes(secret_bytes)

            if len(secret_bytes) != 32:
                raise KeystoreError(f"Invalid secret key length: {len(secret_bytes)}")

            return SecretKey.from_bytes(secret_bytes)
        except Exception as e:
            error_msg = str(e).lower()
            if "checksum" in error_msg or "password" in error_msg or "invalid" in error_msg:
                raise KeystoreError("Invalid password")
            raise KeystoreError(f"Decryption failed: {e}")
