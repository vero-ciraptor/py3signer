"""HTTP route handlers for Keymanager API with msgspec validation."""

import json
import logging
from typing import cast

import msgspec
from aiohttp import web

from .keystore import Keystore, KeystoreError
from .signer import Signer, SignerError
from .signing_types import (
    SignRequest,
    get_domain_for_request,
    sign_request_decoder,
    validate_signing_root,
)
from .storage import KeyStorage

logger = logging.getLogger(__name__)


# msgspec Structs for request validation
class KeystoreImportRequest(msgspec.Struct):
    """Request struct for importing keystores."""

    keystores: list[str]
    passwords: list[str]

    def __post_init__(self) -> None:
        """Validate that keystores and passwords have matching lengths."""
        if len(self.keystores) != len(self.passwords):
            raise ValueError("keystores and passwords must have the same length")
        if len(self.keystores) == 0:
            raise ValueError("keystores must not be empty")


class KeystoreDeleteRequest(msgspec.Struct):
    """Request struct for deleting keystores."""

    pubkeys: list[str]

    def __post_init__(self) -> None:
        """Validate that pubkeys list is not empty."""
        if len(self.pubkeys) == 0:
            raise ValueError("pubkeys must not be empty")


# JSON decoders for request structs
keystore_import_decoder = msgspec.json.Decoder(KeystoreImportRequest)
keystore_delete_decoder = msgspec.json.Decoder(KeystoreDeleteRequest)


class APIHandler:
    """HTTP request handlers for the Keymanager API."""

    def __init__(self, storage: KeyStorage, signer: Signer, auth_token: str | None = None):
        self._storage = storage
        self._signer = signer
        self._auth_token = auth_token
        # Check if persistence is enabled
        self._persistence_enabled = storage.keystore_path is not None
        if self._persistence_enabled:
            logger.info(f"Keystore persistence enabled: {storage.keystore_path}")

    async def _check_auth(self, request: web.Request) -> bool:
        """Check if request is authenticated."""
        if self._auth_token is None:
            return True

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return False

        token = auth_header[7:]  # Remove "Bearer "
        return token == self._auth_token

    async def _require_auth(self, request: web.Request) -> None:
        """Raise 401 if not authenticated."""
        if not await self._check_auth(request):
            raise web.HTTPUnauthorized(
                text=json.dumps({"error": "Unauthorized"}), content_type="application/json"
            )

    async def health(self, request: web.Request) -> web.Response:
        """Health check endpoint."""
        return web.json_response({"status": "healthy", "keys_loaded": len(self._storage)})

    async def list_keystores(self, request: web.Request) -> web.Response:
        """GET /eth/v1/keystores - List all imported keys."""
        await self._require_auth(request)

        keys = self._storage.list_keys()
        keystores = [
            {"validating_pubkey": pubkey, "derivation_path": path, "readonly": False}
            for pubkey, path, _ in keys
        ]

        return web.json_response({"data": keystores})

    async def import_keystores(self, request: web.Request) -> web.Response:
        """POST /eth/v1/keystores - Import keystores."""
        await self._require_auth(request)

        try:
            body_bytes = await request.read()
        except Exception:
            raise web.HTTPBadRequest(
                text=json.dumps({"error": "Failed to read request body"}),
                content_type="application/json",
            )

        # Validate request with msgspec
        try:
            import_req = keystore_import_decoder.decode(body_bytes)
        except (msgspec.ValidationError, msgspec.DecodeError) as e:
            raise web.HTTPBadRequest(
                text=json.dumps({"error": f"Validation error: {e}"}),
                content_type="application/json",
            )
        except ValueError as e:
            raise web.HTTPBadRequest(
                text=json.dumps({"error": str(e)}), content_type="application/json"
            )

        results = []

        for keystore_json, password in zip(import_req.keystores, import_req.passwords):
            try:
                keystore = Keystore.from_json(keystore_json)
                secret_key = keystore.decrypt(password)
                pubkey = secret_key.public_key()
                pubkey_bytes = pubkey.to_bytes()
                pubkey_hex = cast(str, pubkey_bytes.hex())

                # Check if key already exists
                if pubkey_hex in [k[0] for k in self._storage.list_keys()]:
                    results.append(
                        {
                            "status": "duplicate",
                            "message": f"Keystore already exists for pubkey {keystore.pubkey}",
                        }
                    )
                    continue

                # Add key with persistence if enabled
                if self._persistence_enabled:
                    _, persisted = self._storage.add_key_with_persistence(
                        pubkey=pubkey,
                        secret_key=secret_key,
                        keystore_json=keystore_json,
                        password=password,
                        path=keystore.path,
                        description=keystore.description,
                    )
                    if not persisted:
                        logger.warning(f"Failed to persist keystore to disk: {pubkey_hex[:20]}...")
                else:
                    self._storage.add_key(
                        pubkey=pubkey,
                        secret_key=secret_key,
                        path=keystore.path,
                        description=keystore.description,
                    )

                results.append(
                    {
                        "status": "imported",
                        "message": f"Successfully imported keystore with pubkey {keystore.pubkey}",
                    }
                )

            except KeystoreError as e:
                results.append({"status": "error", "message": str(e)})
            except Exception as e:
                logger.exception("Unexpected error importing keystore")
                results.append({"status": "error", "message": f"Internal error: {str(e)}"})

        return web.json_response({"data": results}, status=200)

    async def delete_keystores(self, request: web.Request) -> web.Response:
        """DELETE /eth/v1/keystores - Delete keystores."""
        await self._require_auth(request)

        try:
            body_bytes = await request.read()
        except Exception:
            raise web.HTTPBadRequest(
                text=json.dumps({"error": "Failed to read request body"}),
                content_type="application/json",
            )

        # Validate request with msgspec
        try:
            delete_req = keystore_delete_decoder.decode(body_bytes)
        except (msgspec.ValidationError, msgspec.DecodeError) as e:
            raise web.HTTPBadRequest(
                text=json.dumps({"error": f"Validation error: {e}"}),
                content_type="application/json",
            )
        except ValueError as e:
            raise web.HTTPBadRequest(
                text=json.dumps({"error": str(e)}), content_type="application/json"
            )

        results = []

        for pubkey_hex in delete_req.pubkeys:
            # Normalize pubkey
            pubkey_hex = pubkey_hex.lower().replace("0x", "")

            # Remove with persistence if enabled
            if self._persistence_enabled:
                removed_from_memory, deleted_from_disk = self._storage.remove_key_with_persistence(
                    pubkey_hex
                )
                if removed_from_memory and not deleted_from_disk:
                    logger.warning(
                        f"Failed to delete keystore files from disk: {pubkey_hex[:20]}..."
                    )
            else:
                removed_from_memory = self._storage.remove_key(pubkey_hex)

            if removed_from_memory:
                results.append(
                    {
                        "status": "deleted",
                        "message": f"Successfully deleted keystore with pubkey {pubkey_hex}",
                    }
                )
            else:
                results.append(
                    {
                        "status": "not_found",
                        "message": f"Keystore not found for pubkey {pubkey_hex}",
                    }
                )

        return web.json_response({"data": results})

    async def list_remote_keys(self, request: web.Request) -> web.Response:
        """GET /eth/v1/remotekeys - List remote keys (stub)."""
        await self._require_auth(request)

        return web.json_response(
            {
                "data": []  # Stub - no remote keys support
            }
        )

    async def add_remote_keys(self, request: web.Request) -> web.Response:
        """POST /eth/v1/remotekeys - Add remote keys (stub)."""
        await self._require_auth(request)

        return web.json_response({"data": [], "message": "Remote keys not supported"}, status=501)

    async def delete_remote_keys(self, request: web.Request) -> web.Response:
        """DELETE /eth/v1/remotekeys - Delete remote keys (stub)."""
        await self._require_auth(request)

        return web.json_response({"data": [], "message": "Remote keys not supported"}, status=501)

    async def list_public_keys(self, request: web.Request) -> web.Response:
        """GET /api/v1/eth2/publicKeys - List available BLS public keys.

        Returns a JSON array of hex-encoded BLS public keys, as specified
        by the Ethereum Remote Signing API.
        """
        await self._require_auth(request)

        keys = self._storage.list_keys()
        public_keys = [f"0x{pubkey}" for pubkey, _, _ in keys]

        return web.json_response(public_keys)

    async def sign(self, request: web.Request) -> web.Response:
        """POST /api/v1/eth2/sign/:identifier - Sign data.

        This endpoint implements the Ethereum Remote Signing API specification,
        using typed discriminated signing requests. The 'type' field determines
        the signing operation, and the appropriate domain is computed based on
        the type and fork_info.

        Note: SSZ signing root computation is not yet implemented. Callers must
        provide the signingRoot field. In the future, signingRoot may be computed
        from the type-specific data when not provided.
        """
        await self._require_auth(request)

        # Get identifier from path
        pubkey_hex = request.match_info.get("identifier", "").lower().replace("0x", "")

        if not pubkey_hex:
            raise web.HTTPBadRequest(
                text=json.dumps({"error": "Missing identifier"}), content_type="application/json"
            )

        try:
            body_bytes = await request.read()
        except Exception:
            raise web.HTTPBadRequest(
                text=json.dumps({"error": "Failed to read request body"}),
                content_type="application/json",
            )

        # Parse and validate the discriminated sign request
        try:
            sign_req: SignRequest = sign_request_decoder.decode(body_bytes)
        except (msgspec.ValidationError, msgspec.DecodeError) as e:
            raise web.HTTPBadRequest(
                text=json.dumps({"error": f"Validation error: {e}"}),
                content_type="application/json",
            )
        except ValueError as e:
            raise web.HTTPBadRequest(
                text=json.dumps({"error": str(e)}), content_type="application/json"
            )

        # Validate signingRoot - required since we don't compute SSZ roots
        try:
            message = validate_signing_root(sign_req.signing_root)
        except ValueError as e:
            raise web.HTTPBadRequest(
                text=json.dumps({"error": str(e)}), content_type="application/json"
            )

        if message is None:
            # In the future, we could compute the signing root from type-specific data
            # For now, signingRoot is required
            raise web.HTTPBadRequest(
                text=json.dumps(
                    {
                        "error": "signingRoot is required (SSZ signing root computation not yet implemented)"
                    }
                ),
                content_type="application/json",
            )

        # Get domain based on signing type
        try:
            domain = get_domain_for_request(sign_req)
        except ValueError as e:
            raise web.HTTPInternalServerError(
                text=json.dumps({"error": str(e)}), content_type="application/json"
            )

        try:
            signature = self._signer.sign_data(
                pubkey_hex=pubkey_hex,
                data=message,
                domain=domain,
            )

            signature_hex = signature.to_bytes().hex()

            return web.json_response({"signature": f"0x{signature_hex}"})

        except SignerError as e:
            raise web.HTTPNotFound(
                text=json.dumps({"error": str(e)}), content_type="application/json"
            )
        except Exception as e:
            logger.exception("Signing error")
            raise web.HTTPInternalServerError(
                text=json.dumps({"error": f"Signing failed: {str(e)}"}),
                content_type="application/json",
            )


def setup_routes(app: web.Application, handler: APIHandler) -> None:
    """Set up all routes for the application."""

    # Health check
    app.router.add_get("/health", handler.health)

    # Keymanager API - keystores
    app.router.add_get("/eth/v1/keystores", handler.list_keystores)
    app.router.add_post("/eth/v1/keystores", handler.import_keystores)
    app.router.add_delete("/eth/v1/keystores", handler.delete_keystores)

    # Keymanager API - remote keys (stubs)
    app.router.add_get("/eth/v1/remotekeys", handler.list_remote_keys)
    app.router.add_post("/eth/v1/remotekeys", handler.add_remote_keys)
    app.router.add_delete("/eth/v1/remotekeys", handler.delete_remote_keys)

    # Remote Signing API
    app.router.add_get("/api/v1/eth2/publicKeys", handler.list_public_keys)
    app.router.add_post("/api/v1/eth2/sign/{identifier}", handler.sign)
