"""HTTP route handlers for Keymanager API with Litestar."""

import logging
from enum import Enum
from typing import Any

import msgspec
from litestar import Controller, Request, Response, Router, delete, get, post
from litestar.exceptions import HTTPException, NotFoundException, ValidationException
from litestar.status_codes import (
    HTTP_200_OK,
    HTTP_500_INTERNAL_SERVER_ERROR,
)

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
    readonly: bool = False


class HealthResponse(msgspec.Struct):
    """Health check response."""

    status: str
    keys_loaded: int


class Web3SignerHealthResponse(msgspec.Struct):
    """Web3Signer-compatible healthcheck response."""

    status: str
    outcome: str


# Helper functions to get state from request


def _get_storage(request: Request) -> KeyStorage:
    """Get KeyStorage from app state."""
    result: KeyStorage = request.app.state["storage"]
    return result


def _get_signer(request: Request) -> Signer:
    """Get Signer from app state."""
    result: Signer = request.app.state["signer"]
    return result


# Controllers


class HealthController(Controller):  # type: ignore[misc]
    """Health check endpoints."""

    path = "/"

    @get("/health")  # type: ignore[untyped-decorator]
    async def health(self, request: Request) -> HealthResponse:
        """Health check endpoint."""
        storage = _get_storage(request)
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
    async def list_keystores(self, request: Request) -> Response[dict[str, Any]]:
        """GET /eth/v1/keystores - List all imported keys."""
        storage = _get_storage(request)

        keys = storage.list_keys()
        keystores = [
            KeystoreInfo(validating_pubkey=pubkey, derivation_path=path, readonly=False)
            for pubkey, path, _ in keys
        ]
        return Response(
            content={"data": [msgspec.to_builtins(k) for k in keystores]},
            status_code=HTTP_200_OK,
        )

    @post()  # type: ignore[untyped-decorator]
    async def import_keystores(
        self,
        request: Request,
        data: dict[str, Any],
    ) -> Response[dict[str, Any]]:
        """POST /eth/v1/keystores - Import keystores.

        Accepts EIP-3076 slashing_protection data (stored but not processed).
        """
        storage = _get_storage(request)

        # Validate request manually since msgspec doesn't integrate directly
        try:
            import_req = msgspec.convert(data, KeystoreImportRequest)
        except (msgspec.ValidationError, msgspec.DecodeError) as e:
            raise ValidationException(detail=f"Validation error: {e}") from e
        except ValueError as e:
            raise ValidationException(detail=str(e)) from e

        # Log if slashing protection data was provided (we accept but don't process it)
        if import_req.slashing_protection:
            logger.warning(
                "Slashing protection data provided during import (accepted but not processed)"
            )

        results = []
        existing_keys = {k[0] for k in storage.list_keys()}
        persistence_enabled = storage.keystore_path is not None

        for keystore_json, password in zip(
            import_req.keystores, import_req.passwords, strict=True
        ):
            try:
                keystore = Keystore.from_json(keystore_json)
                secret_key = keystore.decrypt(password)
                pubkey = secret_key.public_key()
                pubkey_hex = pubkey.to_bytes().hex()

                if pubkey_hex in existing_keys:
                    results.append(
                        KeystoreImportResult(
                            status="duplicate",
                            message=f"Keystore already exists for pubkey {keystore.pubkey}",
                        ),
                    )
                    continue

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
                results.append(
                    KeystoreImportResult(
                        status="imported",
                        message=f"Successfully imported keystore with pubkey {keystore.pubkey}",
                    ),
                )

            except KeystoreError as e:
                results.append(KeystoreImportResult(status="error", message=str(e)))
            except Exception as e:
                logger.exception("Unexpected error importing keystore")
                results.append(
                    KeystoreImportResult(
                        status="error",
                        message=f"Internal error: {e}",
                    ),
                )

        return Response(
            content={"data": [msgspec.to_builtins(r) for r in results]},
            status_code=HTTP_200_OK,
        )

    @delete(status_code=HTTP_200_OK)  # type: ignore[untyped-decorator]
    async def delete_keystores(
        self,
        request: Request,
        data: dict[str, Any],
    ) -> Response[dict[str, Any]]:
        """DELETE /eth/v1/keystores - Delete keystores.

        Returns slashing protection data for keys that were active or had data.
        Per the spec, slashing protection data must be retained even after deletion.
        """
        storage = _get_storage(request)

        try:
            delete_req = msgspec.convert(data, KeystoreDeleteRequest)
        except (msgspec.ValidationError, msgspec.DecodeError) as e:
            raise ValidationException(detail=f"Validation error: {e}") from e
        except ValueError as e:
            raise ValidationException(detail=str(e)) from e

        results = []
        # Track pubkeys that had slashing data (active or not_active status)
        # For now, we return empty slashing protection for all deleted keys
        # A full implementation would track attestation/block signing history
        slashing_data_entries: list[dict[str, Any]] = []

        for pubkey_hex in delete_req.pubkeys:
            pubkey_hex_clean = pubkey_hex.lower().replace("0x", "")
            try:
                storage.remove_key(pubkey_hex_clean)
            except KeyNotFound:
                results.append(
                    KeystoreDeleteResult(status=KeystoreDeleteStatus.NOT_FOUND)
                )
            except Exception as e:
                error = str(e)
                results.append(
                    KeystoreDeleteResult(
                        status=KeystoreDeleteStatus.ERROR, message=error
                    )
                )
            else:
                results.append(
                    KeystoreDeleteResult(status=KeystoreDeleteStatus.DELETED)
                )
                # Add empty entry for this pubkey to slashing protection data
                slashing_data_entries.append(
                    {
                        "pubkey": f"0x{pubkey_hex_clean}",
                        "signed_blocks": [],
                        "signed_attestations": [],
                    }
                )

        # Build slashing protection response per EIP-3076
        slashing_protection = {
            "metadata": {
                "interchange_format_version": "5",
                "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            },
            "data": slashing_data_entries,
        }

        return Response(
            content={
                "data": [msgspec.to_builtins(r) for r in results],
                "slashing_protection": slashing_protection,
            },
            status_code=HTTP_200_OK,
        )


class SigningController(Controller):  # type: ignore[misc]
    """Remote Signing API endpoints."""

    path = "/api/v1/eth2"

    @get("/publicKeys")  # type: ignore[untyped-decorator]
    async def list_public_keys(self, request: Request) -> Response[list[str]]:
        """GET /api/v1/eth2/publicKeys - List available BLS public keys."""
        storage = _get_storage(request)
        keys = storage.list_keys()
        public_keys = [f"0x{pubkey}" for pubkey, _, _ in keys]
        return Response(content=public_keys, status_code=HTTP_200_OK)

    @post("/sign/{identifier:str}")  # type: ignore[untyped-decorator]
    async def sign(self, request: Request, identifier: str) -> Response:
        """POST /api/v1/eth2/sign/:identifier - Sign data."""
        signer = _get_signer(request)

        pubkey_hex = identifier.lower().replace("0x", "")
        if not pubkey_hex:
            raise ValidationException(detail="Missing identifier")

        # Read and parse request body
        try:
            body_bytes = await request.body()
            sign_req: SignRequest = sign_request_decoder.decode(body_bytes)
        except (msgspec.ValidationError, msgspec.DecodeError) as e:
            raise ValidationException(detail=f"Validation error: {e}") from e
        except ValueError as e:
            raise ValidationException(detail=str(e)) from e

        try:
            message = validate_signing_root(sign_req.signing_root)
        except ValueError as e:
            raise ValidationException(detail=str(e)) from e

        if message is None:
            raise ValidationException(
                detail="signing_root is required - SSZ signing root computation from request data "
                "is not yet implemented. Please provide signing_root in the request.",
            )

        try:
            domain = get_domain_for_request(sign_req)
        except ValueError as e:
            raise HTTPException(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(e),
            ) from e

        try:
            signature = signer.sign_data(
                pubkey_hex=pubkey_hex,
                data=message,
                domain=domain,
            )
            signature_hex = signature.to_bytes().hex()
            full_signature = f"0x{signature_hex}"

            # Check Accept header to determine response format
            accept_header = request.headers.get("Accept", "")

            if accept_header == "text/plain":
                # Return plain text signature
                return Response(
                    content=full_signature,
                    status_code=HTTP_200_OK,
                    media_type="text/plain",
                )
            # Default: return JSON (for application/json, */*, or missing header)
            return Response(
                content={"signature": full_signature},
                status_code=HTTP_200_OK,
                media_type="application/json",
            )
        except SignerError as e:
            raise NotFoundException(detail=str(e)) from e
        except Exception as e:
            logger.exception("Signing error")
            raise HTTPException(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Signing failed: {e}",
            ) from e


# Router configuration


def get_routers() -> list[Router]:
    """Get all routers for the application."""
    return [
        Router(path="/", route_handlers=[HealthController]),
        Router(path="/", route_handlers=[LocalKeyManagerController]),
        Router(path="/", route_handlers=[SigningController]),
    ]
