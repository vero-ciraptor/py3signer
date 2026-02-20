"""HTTP route handlers for Keymanager API with Litestar."""

import logging
from enum import Enum
from typing import Any

import msgspec
from litestar import Controller, Request, Response, Router, delete, get, post
from litestar.exceptions import HTTPException, NotFoundException, ValidationException
from litestar.status_codes import HTTP_200_OK, HTTP_500_INTERNAL_SERVER_ERROR

from .keystore import Keystore, KeystoreError
from .signer import Signer, SignerError
from .signing_types import (
    SignRequest,
    get_domain_for_request,
    sign_request_decoder,
    validate_signing_root,
)
from .storage import KeyNotFound, KeyStorage

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


def _validate_import_request(data: dict[str, Any]) -> KeystoreImportRequest:
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


def _validate_delete_request(data: dict[str, Any]) -> KeystoreDeleteRequest:
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


def _clean_pubkey_hex(pubkey_hex: str) -> str:
    """Clean a public key hex string (remove 0x prefix and lowercase).

    Args:
        pubkey_hex: The public key hex string

    Returns:
        Cleaned hex string

    """
    return pubkey_hex.lower().replace("0x", "")


# Import helper


def _import_single_keystore(
    keystore_json: str,
    password: str,
    existing_keys: set[str],
    storage: KeyStorage,
    persistence_enabled: bool,
) -> KeystoreImportResult:
    """Import a single keystore.

    Args:
        keystore_json: The keystore JSON string
        password: The password for the keystore
        existing_keys: Set of existing public key hex strings
        storage: The KeyStorage instance
        persistence_enabled: Whether persistence is enabled

    Returns:
        KeystoreImportResult with status and message

    """
    try:
        keystore = Keystore.from_json(keystore_json)
        secret_key = keystore.decrypt(password)
        pubkey = secret_key.public_key()
        pubkey_hex = pubkey.to_bytes().hex()

        if pubkey_hex in existing_keys:
            return KeystoreImportResult(
                status="duplicate",
                message=f"Keystore already exists for pubkey {keystore.pubkey}",
            )

        # Add key with optional persistence
        _, persisted = storage.add_key(
            pubkey=pubkey,
            secret_key=secret_key,
            path=keystore.path,
            description=keystore.description,
            keystore_json=keystore_json if persistence_enabled else None,
            password=password if persistence_enabled else None,
        )

        if persistence_enabled and not persisted:
            logger.warning(
                f"Failed to persist keystore to disk: {pubkey_hex[:20]}...",
            )

        existing_keys.add(pubkey_hex)
        return KeystoreImportResult(
            status="imported",
            message=f"Successfully imported keystore with pubkey {keystore.pubkey}",
        )

    except KeystoreError as e:
        return KeystoreImportResult(status="error", message=str(e))
    except Exception as e:
        logger.exception("Unexpected error importing keystore")
        return KeystoreImportResult(
            status="error",
            message=f"Internal error: {e}",
        )


# Delete helper


def _delete_single_key(
    pubkey_hex: str,
    storage: KeyStorage,
) -> tuple[KeystoreDeleteResult, dict[str, Any] | None]:
    """Delete a single key and return result with optional slashing data.

    Args:
        pubkey_hex: The public key hex string (with or without 0x prefix)
        storage: The KeyStorage instance

    Returns:
        Tuple of (delete result, slashing data entry or None)

    """
    cleaned_pubkey = _clean_pubkey_hex(pubkey_hex)

    try:
        storage.remove_key(cleaned_pubkey)
    except KeyNotFound:
        return KeystoreDeleteResult(status=KeystoreDeleteStatus.NOT_FOUND), None
    except Exception as e:
        return (
            KeystoreDeleteResult(status=KeystoreDeleteStatus.ERROR, message=str(e)),
            None,
        )

    # Build slashing protection entry for deleted key
    slashing_entry = {
        "pubkey": f"0x{cleaned_pubkey}",
        "signed_blocks": [],
        "signed_attestations": [],
    }
    return KeystoreDeleteResult(status=KeystoreDeleteStatus.DELETED), slashing_entry


# Signing helpers


async def _parse_sign_request(request: Request) -> SignRequest:
    """Parse and validate a sign request from the request body.

    Args:
        request: The HTTP request

    Returns:
        Parsed SignRequest

    Raises:
        ValidationException: If parsing fails

    """
    from typing import cast

    try:
        body_bytes = await request.body()
        return cast("SignRequest", sign_request_decoder.decode(body_bytes))
    except (msgspec.ValidationError, msgspec.DecodeError) as e:
        raise ValidationException(detail=f"Validation error: {e}") from e
    except ValueError as e:
        raise ValidationException(detail=str(e)) from e


def _build_slashing_protection_response(
    entries: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build slashing protection response per EIP-3076.

    Args:
        entries: List of slashing data entries

    Returns:
        EIP-3076 formatted slashing protection data

    """
    return {
        "metadata": {
            "interchange_format_version": "5",
            "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
        },
        "data": entries,
    }


# Controllers


class HealthController(Controller):  # type: ignore[misc]
    """Health check endpoints."""

    path = "/"

    @get("/health")  # type: ignore[untyped-decorator]
    async def health(self, storage: KeyStorage) -> HealthResponse:
        """Health check endpoint."""
        return HealthResponse(status="healthy", keys_loaded=len(storage))

    @get("/healthcheck")  # type: ignore[untyped-decorator]
    async def healthcheck(self) -> Web3SignerHealthResponse:
        """Health check endpoint for compatibility with Vero validator client.

        Returns Web3Signer-compatible healthcheck response.
        """
        return Web3SignerHealthResponse(status="UP", outcome="UP")


class LocalKeyManagerController(Controller):  # type: ignore[misc]
    """Keymanager API - Local Key Manager endpoints."""

    path = "/eth/v1/keystores"

    @get()  # type: ignore[untyped-decorator]
    async def list_keystores(self, storage: KeyStorage) -> ListKeystoresResponse:
        """GET /eth/v1/keystores - List all imported keys."""
        keys = storage.list_keys()
        keystores = [
            KeystoreInfo(
                validating_pubkey=key_info.pubkey_hex,
                derivation_path=key_info.path,
                readonly=key_info.is_external,  # External keys are readonly
            )
            for key_info in keys
        ]
        return ListKeystoresResponse(data=keystores)

    @post(status_code=HTTP_200_OK)  # type: ignore[untyped-decorator]
    async def import_keystores(
        self,
        data: dict[str, Any],
        storage: KeyStorage,
    ) -> ImportKeystoresResponse:
        """POST /eth/v1/keystores - Import keystores.

        Accepts EIP-3076 slashing_protection data (stored but not processed).
        """
        import_request = _validate_import_request(data)

        # Log if slashing protection data was provided (we accept but don't process it)
        if import_request.slashing_protection:
            logger.warning(
                "Slashing protection data provided during import (accepted but not processed)",
            )

        existing_keys = {key.pubkey_hex for key in storage.list_keys()}
        persistence_enabled = storage.managed_keystores_dir is not None

        results = [
            _import_single_keystore(
                keystore_json=keystore_json,
                password=password,
                existing_keys=existing_keys,
                storage=storage,
                persistence_enabled=persistence_enabled,
            )
            for keystore_json, password in zip(
                import_request.keystores,
                import_request.passwords,
                strict=True,
            )
        ]

        return ImportKeystoresResponse(data=results)

    @delete(status_code=HTTP_200_OK)  # type: ignore[untyped-decorator]
    async def delete_keystores(
        self,
        data: dict[str, Any],
        storage: KeyStorage,
    ) -> DeleteKeystoresResponse:
        """DELETE /eth/v1/keystores - Delete keystores.

        Returns slashing protection data for keys that were active or had data.
        Per the spec, slashing protection data must be retained even after deletion.
        """
        delete_request = _validate_delete_request(data)

        results: list[KeystoreDeleteResult] = []
        slashing_entries: list[dict[str, Any]] = []

        for pubkey_hex in delete_request.pubkeys:
            result, slashing_entry = _delete_single_key(pubkey_hex, storage)
            results.append(result)
            if slashing_entry:
                slashing_entries.append(slashing_entry)

        slashing_protection = _build_slashing_protection_response(slashing_entries)

        return DeleteKeystoresResponse(
            data=results,
            slashing_protection=slashing_protection,
        )


class SigningController(Controller):  # type: ignore[misc]
    """Remote Signing API endpoints."""

    path = "/api/v1/eth2"

    @get("/publicKeys")  # type: ignore[untyped-decorator]
    async def list_public_keys(self, storage: KeyStorage) -> list[str]:
        """GET /api/v1/eth2/publicKeys - List available BLS public keys."""
        keys = storage.list_keys()
        return [f"0x{key_info.pubkey_hex}" for key_info in keys]

    @post("/sign/{identifier:str}", status_code=HTTP_200_OK)  # type: ignore[untyped-decorator]
    async def sign(
        self,
        request: Request,
        identifier: str,
        signer: Signer,
    ) -> Response | SignResponse:
        """POST /api/v1/eth2/sign/:identifier - Sign data."""
        pubkey_hex = _clean_pubkey_hex(identifier)
        if not pubkey_hex:
            raise ValidationException(detail="Missing identifier")

        # Parse request body
        sign_request = await _parse_sign_request(request)

        # Validate signing root
        try:
            message = validate_signing_root(sign_request.signing_root)
        except ValueError as e:
            raise ValidationException(detail=str(e)) from e

        if message is None:
            raise ValidationException(
                detail="signing_root is required - SSZ signing root computation from request data "
                "is not yet implemented. Please provide signing_root in the request.",
            )

        # Get domain for signing
        try:
            domain = get_domain_for_request(sign_request)
        except ValueError as e:
            raise HTTPException(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(e),
            ) from e

        # Perform signing
        try:
            signature = signer.sign_data(
                pubkey_hex=pubkey_hex,
                data=message,
                domain=domain,
            )
        except SignerError as e:
            raise NotFoundException(detail=str(e)) from e
        except Exception as e:
            logger.exception("Signing error")
            raise HTTPException(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Signing failed: {e}",
            ) from e

        # Build response
        signature_hex = signature.to_bytes().hex()
        full_signature = f"0x{signature_hex}"

        accept_header = request.headers.get("Accept", "")
        if accept_header == "text/plain":
            return Response(
                content=full_signature,
                status_code=HTTP_200_OK,
                media_type="text/plain",
            )

        return SignResponse(signature=full_signature)


# Router configuration


def get_routers() -> list[Router]:
    """Get all routers for the application."""
    return [
        Router(path="/", route_handlers=[HealthController]),
        Router(path="/", route_handlers=[LocalKeyManagerController]),
        Router(path="/", route_handlers=[SigningController]),
    ]
