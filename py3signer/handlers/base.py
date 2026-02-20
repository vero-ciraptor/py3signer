"""Base types, structs and validation helpers for handlers."""

import logging
from enum import Enum
from typing import Any

import msgspec
from litestar.exceptions import ValidationException

logger = logging.getLogger(__name__)


# Request/Response structs


class KeystoreImportRequest(msgspec.Struct):
    """Request struct for importing keystores."""

    keystores: list[str]
    passwords: list[str]
    slashing_protection: str | None = (
        None  # EIP-3076 slashing protection data (optional)
    )

    def __post_init__(self) -> None:
        if len(self.keystores) != len(self.passwords):
            raise ValueError("keystores and passwords must have the same length")
        if len(self.keystores) == 0:
            raise ValueError("keystores must not be empty")


class KeystoreDeleteRequest(msgspec.Struct):
    """Request struct for deleting keystores."""

    pubkeys: list[str]

    def __post_init__(self) -> None:
        if len(self.pubkeys) == 0:
            raise ValueError("pubkeys must not be empty")


class KeystoreImportResult(msgspec.Struct):
    """Result of importing a keystore."""

    status: str
    message: str


class KeystoreDeleteStatus(Enum):
    """Status of a keystore deletion operation."""

    # key was active and removed
    DELETED = "deleted"
    # slashing protection data returned but key was not active
    NOT_ACTIVE = "not_active"
    # key was not found to be removed, and no slashing data can be returned
    NOT_FOUND = "not_found"
    # unexpected condition meant the key could not be removed
    # (the key was actually found, but we couldn't stop using it)
    # - this would be a sign that making it active elsewhere would
    # almost certainly cause you headaches / slashing conditions etc.
    ERROR = "error"


class KeystoreDeleteResult(msgspec.Struct):
    """Result of deleting a keystore."""

    status: KeystoreDeleteStatus
    message: str = ""


class SlashingProtectionData(msgspec.Struct):
    """Slashing protection data in EIP-3076 format.

    This is a minimal placeholder implementation. Full slashing protection
    tracking would require maintaining attestation and block signing history.
    """

    metadata: dict[str, str]
    data: list[dict[str, Any]]

    @classmethod
    def empty(cls) -> SlashingProtectionData:
        """Return empty slashing protection data."""
        return cls(
            metadata={
                "interchange_format_version": "5",
                "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            },
            data=[],
        )


class KeystoreInfo(msgspec.Struct):
    """Keystore information response."""

    validating_pubkey: str
    derivation_path: str
    # readonly=True for external keys that shouldn't be modified via API
    readonly: bool = False


class HealthResponse(msgspec.Struct):
    """Health check response."""

    status: str
    keys_loaded: int


class Web3SignerHealthResponse(msgspec.Struct):
    """Web3Signer-compatible healthcheck response."""

    status: str
    outcome: str


# Response wrapper structs to streamline serialization pipeline


class ListKeystoresResponse(msgspec.Struct):
    """Response for listing keystores.

    Directly serializable by msgspec, eliminating manual to_builtins conversion.
    """

    data: list[KeystoreInfo]


class ImportKeystoresResponse(msgspec.Struct):
    """Response for importing keystores.

    Directly serializable by msgspec, eliminating manual to_builtins conversion.
    """

    data: list[KeystoreImportResult]


class DeleteKeystoresResponse(msgspec.Struct):
    """Response for deleting keystores.

    Directly serializable by msgspec, eliminating manual to_builtins conversion.
    """

    data: list[KeystoreDeleteResult]
    slashing_protection: dict[str, Any]


class SignResponse(msgspec.Struct):
    """Response for signing operations.

    Directly serializable by msgspec.
    """

    signature: str


# Validation helpers


def validate_import_request(data: dict[str, Any]) -> KeystoreImportRequest:
    """Validate and parse keystore import request.

    Args:
        data: Raw request data

    Returns:
        Parsed KeystoreImportRequest

    Raises:
        ValidationException: If validation fails

    """
    try:
        return msgspec.convert(data, KeystoreImportRequest)
    except (msgspec.ValidationError, msgspec.DecodeError) as e:
        raise ValidationException(detail=f"Validation error: {e}") from e
    except ValueError as e:
        raise ValidationException(detail=str(e)) from e


def validate_delete_request(data: dict[str, Any]) -> KeystoreDeleteRequest:
    """Validate and parse keystore delete request.

    Args:
        data: Raw request data

    Returns:
        Parsed KeystoreDeleteRequest

    Raises:
        ValidationException: If validation fails

    """
    try:
        return msgspec.convert(data, KeystoreDeleteRequest)
    except (msgspec.ValidationError, msgspec.DecodeError) as e:
        raise ValidationException(detail=f"Validation error: {e}") from e
    except ValueError as e:
        raise ValidationException(detail=str(e)) from e


def clean_pubkey_hex(pubkey_hex: str) -> str:
    """Clean a public key hex string (remove 0x prefix and lowercase).

    Args:
        pubkey_hex: The public key hex string

    Returns:
        Cleaned hex string

    """
    # Use removeprefix() instead of replace() - stops at first match vs scans entire string
    return pubkey_hex.removeprefix("0x").lower()
