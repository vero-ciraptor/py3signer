"""HTTP route handlers for Keymanager API with Litestar."""

import logging
from enum import Enum
from typing import Any

import msgspec
from litestar import Controller, Request, Response, Router, delete, get, post
from litestar.exceptions import HTTPException, NotFoundException, ValidationException
from litestar.status_codes import (
    HTTP_200_OK,
    HTTP_401_UNAUTHORIZED,
    HTTP_500_INTERNAL_SERVER_ERROR,
    HTTP_501_NOT_IMPLEMENTED,
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


def _get_auth_token(request: Request) -> str | None:
    """Get auth token from app state."""
    result: str | None = request.app.state["auth_token"]
    return result


def _check_auth(request: Request) -> None:
    """Check if request is authenticated."""
    auth_token = _get_auth_token(request)
    if auth_token is None:
        return

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
        )
    if auth_header[7:] != auth_token:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
        )


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


class KeystoreController(Controller):  # type: ignore[misc]
    """Keymanager API keystore endpoints."""

    path = "/eth/v1/keystores"

    @get()  # type: ignore[untyped-decorator]
    async def list_keystores(self, request: Request) -> Response[dict[str, Any]]:
        """GET /eth/v1/keystores - List all imported keys."""
        _check_auth(request)
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
        """POST /eth/v1/keystores - Import keystores."""
        _check_auth(request)
        storage = _get_storage(request)

        # Validate request manually since msgspec doesn't integrate directly
        try:
            import_req = msgspec.convert(data, KeystoreImportRequest)
        except (msgspec.ValidationError, msgspec.DecodeError) as e:
            raise ValidationException(detail=f"Validation error: {e}") from e
        except ValueError as e:
            raise ValidationException(detail=str(e)) from e

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
        """DELETE /eth/v1/keystores - Delete keystores."""
        _check_auth(request)
        storage = _get_storage(request)

        try:
            delete_req = msgspec.convert(data, KeystoreDeleteRequest)
        except (msgspec.ValidationError, msgspec.DecodeError) as e:
            raise ValidationException(detail=f"Validation error: {e}") from e
        except ValueError as e:
            raise ValidationException(detail=str(e)) from e

        results = []

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

        return Response(
            content={"data": [msgspec.to_builtins(r) for r in results]},
            status_code=HTTP_200_OK,
        )


class RemoteKeysController(Controller):  # type: ignore[misc]
    """Remote keys endpoints (stub)."""

    path = "/eth/v1/remotekeys"

    @get()  # type: ignore[untyped-decorator]
    async def list_remote_keys(self, request: Request) -> Response[dict[str, Any]]:
        """GET /eth/v1/remotekeys - List remote keys (stub)."""
        _check_auth(request)
        return Response(content={"data": []}, status_code=HTTP_200_OK)

    @post()  # type: ignore[untyped-decorator]
    async def add_remote_keys(self, request: Request) -> Response[dict[str, Any]]:
        """POST /eth/v1/remotekeys - Add remote keys (stub)."""
        _check_auth(request)
        return Response(
            content={"data": [], "message": "Remote keys not supported"},
            status_code=HTTP_501_NOT_IMPLEMENTED,
        )

    @delete(status_code=HTTP_501_NOT_IMPLEMENTED)  # type: ignore[untyped-decorator]
    async def delete_remote_keys(self, request: Request) -> Response[dict[str, Any]]:
        """DELETE /eth/v1/remotekeys - Delete remote keys (stub)."""
        _check_auth(request)
        return Response(
            content={"data": [], "message": "Remote keys not supported"},
            status_code=HTTP_501_NOT_IMPLEMENTED,
        )


class SigningController(Controller):  # type: ignore[misc]
    """Remote Signing API endpoints."""

    path = "/api/v1/eth2"

    @get("/publicKeys")  # type: ignore[untyped-decorator]
    async def list_public_keys(self, request: Request) -> Response[list[str]]:
        """GET /api/v1/eth2/publicKeys - List available BLS public keys."""
        _check_auth(request)
        storage = _get_storage(request)
        keys = storage.list_keys()
        public_keys = [f"0x{pubkey}" for pubkey, _, _ in keys]
        return Response(content=public_keys, status_code=HTTP_200_OK)

    @post("/sign/{identifier:str}")  # type: ignore[untyped-decorator]
    async def sign(self, request: Request, identifier: str) -> Response:
        """POST /api/v1/eth2/sign/:identifier - Sign data."""
        _check_auth(request)
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
            # Return just the raw hex string (not JSON) per Web3Signer API spec
            return Response(
                content=f"0x{signature_hex}",
                status_code=HTTP_200_OK,
                media_type="text/plain",
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
        Router(path="/", route_handlers=[KeystoreController]),
        Router(path="/", route_handlers=[RemoteKeysController]),
        Router(path="/", route_handlers=[SigningController]),
    ]
