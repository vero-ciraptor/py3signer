"""Data classes for py3signer.

This module contains dataclasses and structured types used across the codebase.
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from py3signer_core import PublicKey, SecretKey


@dataclass(frozen=True, slots=True)
class KeystoreLoadResult:
    """Result of loading a keystore with its password.

    Attributes:
        pubkey: The public key
        secret_key: The secret key
        path: The derivation path
        description: Optional description from the keystore
        password: The password used to decrypt the keystore

    """

    pubkey: PublicKey
    secret_key: SecretKey
    path: str
    description: str | None
    password: str


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
