"""Data classes for py3signer.

This module contains dataclasses and structured types used across the codebase.
"""

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from py3signer_core import PublicKey, SecretKey


@dataclass(slots=True)
class KeystoreLoadResult:
    """Result of loading a keystore with its password.

    Attributes:
        pubkey: The public key
        secret_key: The secret key
        path: The derivation path
        description: Optional description from the keystore
        password: The password used to decrypt the keystore (read-only property)

    """

    pubkey: PublicKey
    secret_key: SecretKey
    path: str
    description: str | None
    _password: bytearray = field(repr=False)

    @property
    def password(self) -> str:
        """Return the password as a string for immediate use.

        Returns:
            The password string decoded from the internal bytearray.
        """
        return self._password.decode("utf-8")

    def clear_password(self) -> None:
        """Clear the password from memory by zeroing out the bytearray.

        This should be called after the password is no longer needed to
        minimize the time the password exists in memory.
        """
        for i in range(len(self._password)):
            self._password[i] = 0


@dataclass(frozen=True, slots=True)
class KeyInfo:
    """Information about a stored key.

    Attributes:
        pubkey_hex: The public key in hex format (without 0x prefix)
        path: The derivation path
        description: Optional description
        is_external: Whether this key is from external storage

    """

    pubkey_hex: str
    path: str
    description: str | None
    is_external: bool
