"""EIP-2335 keystore handling."""

import logging
import unicodedata
from pathlib import Path
from typing import Any, Self

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
    def from_file(cls, path: Path) -> Self:
        """Load keystore from JSON file."""
        return msgspec.json.decode(path.read_bytes(), type=cls)

    @classmethod
    def from_json(cls, json_str: str) -> Self:
        """Load keystore from JSON string."""
        return msgspec.json.decode(json_str, type=cls)

    def decrypt(self, password: str) -> SecretKey:
        """Decrypt the keystore and return the secret key."""
        try:
            # Apply EIP-2335 password normalization
            normalized_password = normalize_password(password)

            # Convert struct to JSON for the decrypt_keystore function
            json_str = msgspec.json.encode(self).decode()
            secret_bytes = decrypt_keystore(json_str, normalized_password)
        except Exception as e:
            error_msg = str(e).lower()
            if (
                "checksum" in error_msg
                or "password" in error_msg
                or "invalid" in error_msg
            ):
                raise KeystoreError("Invalid password") from e
            raise KeystoreError(f"Decryption failed: {e}") from e
        else:
            if len(secret_bytes) != 32:
                raise KeystoreError(f"Invalid secret key length: {len(secret_bytes)}")

            return SecretKey.from_bytes(secret_bytes)
