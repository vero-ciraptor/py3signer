"""EIP-2335 keystore handling."""

import json
import logging
import unicodedata
from pathlib import Path
from typing import Any

import msgspec
from py3signer_core import SecretKey, decrypt_keystore

logger = logging.getLogger(__name__)


def normalize_password(password: str) -> str:
    """Normalize password according to EIP-2335 specification.

    The password is first converted to its NFKD representation, then the control
    codes are stripped (C0: 0x00-0x1F, C1: 0x80-0x9F, DEL: 0x7F), and finally
    it is UTF-8 encoded.

    Args:
        password: Raw password string

    Returns:
        Normalized password string

    """
    # NFKD normalization
    normalized = unicodedata.normalize("NFKD", password)

    # Strip control codes: C0 (0x00-0x1F), C1 (0x80-0x9F), DEL (0x7F)
    result = []
    for char in normalized:
        code = ord(char)
        # Skip C0 control codes (0x00-0x1F), C1 control codes (0x80-0x9F), and DEL (0x7F)
        if code <= 0x1F or (0x7F <= code <= 0x9F):
            continue
        result.append(char)

    return "".join(result)


class KeystoreError(Exception):
    """Error decrypting or parsing keystore."""


class Keystore(msgspec.Struct):
    """EIP-2335 keystore representation."""

    crypto: dict[str, Any]
    pubkey: str
    path: str
    uuid: str
    version: int
    description: str | None = None

    def __post_init__(self) -> None:
        """Validate keystore structure after initialization."""
        self._validate()

    def _validate(self) -> None:
        """Validate keystore structure."""
        # crypto, pubkey, path, uuid, version are already validated by msgspec
        # as they are required fields with types
        if self.version != 4:
            raise KeystoreError(
                f"Keystore version {self.version} is not supported, "
                "only version 4 (EIP-2335) is supported",
            )

        if (
            "kdf" not in self.crypto
            or "checksum" not in self.crypto
            or "cipher" not in self.crypto
        ):
            raise KeystoreError("Invalid crypto structure")

    @classmethod
    def from_file(cls, path: Path) -> Keystore:
        """Load keystore from JSON file."""
        try:
            with open(path) as f:
                data = json.load(f)
            return cls(**data)
        except json.JSONDecodeError as e:
            raise KeystoreError(f"Invalid JSON: {e}")
        except FileNotFoundError:
            raise KeystoreError(f"Keystore file not found: {path}")
        except msgspec.ValidationError as e:
            raise KeystoreError(f"Invalid keystore structure: {e}")

    @classmethod
    def from_json(cls, json_str: str) -> Keystore:
        """Load keystore from JSON string."""
        try:
            data = json.loads(json_str)
            return cls(**data)
        except json.JSONDecodeError as e:
            raise KeystoreError(f"Invalid JSON: {e}")
        except msgspec.ValidationError as e:
            raise KeystoreError(f"Invalid keystore structure: {e}")

    def decrypt(self, password: str) -> SecretKey:
        """Decrypt the keystore and return the secret key."""
        try:
            # Apply EIP-2335 password normalization
            normalized_password = normalize_password(password)

            # Convert struct to dict for the decrypt_keystore function
            data = msgspec.to_builtins(self)
            json_str = json.dumps(data)
            secret_bytes = decrypt_keystore(json_str, normalized_password)

            # Convert list to bytes if necessary (Rust returns Vec<u8> as list)
            if isinstance(secret_bytes, list):
                secret_bytes = bytes(secret_bytes)

            if len(secret_bytes) != 32:
                raise KeystoreError(f"Invalid secret key length: {len(secret_bytes)}")

            return SecretKey.from_bytes(secret_bytes)
        except Exception as e:
            error_msg = str(e).lower()
            if (
                "checksum" in error_msg
                or "password" in error_msg
                or "invalid" in error_msg
            ):
                raise KeystoreError("Invalid password") from e
            raise KeystoreError(f"Decryption failed: {e}") from e
