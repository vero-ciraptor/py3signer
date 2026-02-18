"""Instrumented HTTP route handlers for profiling."""

import json
import logging
import time

import msgspec
from aiohttp import web

from .keystore import Keystore, KeystoreError
from .signer import Signer
from .signing_types import (
    SignRequest,
    get_domain_for_request,
    sign_request_decoder,
    validate_signing_root,
)
from .storage import KeyStorage

logger = logging.getLogger(__name__)


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


keystore_import_decoder = msgspec.json.Decoder(KeystoreImportRequest)
keystore_delete_decoder = msgspec.json.Decoder(KeystoreDeleteRequest)


def _bad_request(message: str) -> web.HTTPBadRequest:
    """Create a bad request response."""
    return web.HTTPBadRequest(text=json.dumps({"error": message}), content_type="application/json")


def _validation_error(e: Exception) -> web.HTTPBadRequest:
    """Create a validation error response."""
    return _bad_request(f"Validation error: {e}")


class ProfilingAPIHandler:
    """HTTP request handlers with detailed profiling."""

    def __init__(self, storage: KeyStorage, signer: Signer, auth_token: str | None = None):
        self._storage = storage
        self._signer = signer
        self._auth_token = auth_token
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
        return auth_header[7:] == self._auth_token

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
            import_req = keystore_import_decoder.decode(body_bytes)
        except (msgspec.ValidationError, msgspec.DecodeError) as e:
            raise _validation_error(e)
        except ValueError as e:
            raise _bad_request(str(e))

        results = []
        existing_keys = {k[0] for k in self._storage.list_keys()}

        for keystore_json, password in zip(import_req.keystores, import_req.passwords):
            try:
                keystore = Keystore.from_json(keystore_json)
                secret_key = keystore.decrypt(password)
                pubkey = secret_key.public_key()
                pubkey_hex = pubkey.to_bytes().hex()

                if pubkey_hex in existing_keys:
                    results.append(
                        {
                            "status": "duplicate",
                            "message": f"Keystore already exists for pubkey {keystore.pubkey}",
                        }
                    )
                    continue

                # Add key with optional persistence
                _, persisted = self._storage.add_key(
                    pubkey=pubkey,
                    secret_key=secret_key,
                    path=keystore.path,
                    description=keystore.description,
                    keystore_json=keystore_json if self._persistence_enabled else None,
                    password=password if self._persistence_enabled else None,
                )

                if self._persistence_enabled and not persisted:
                    logger.warning(f"Failed to persist keystore to disk: {pubkey_hex[:20]}...")

                existing_keys.add(pubkey_hex)
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
                results.append({"status": "error", "message": f"Internal error: {e}"})

        return web.json_response({"data": results})

    async def delete_keystores(self, request: web.Request) -> web.Response:
        """DELETE /eth/v1/keystores - Delete keystores."""
        await self._require_auth(request)

        try:
            body_bytes = await request.read()
            delete_req = keystore_delete_decoder.decode(body_bytes)
        except (msgspec.ValidationError, msgspec.DecodeError) as e:
            raise _validation_error(e)
        except ValueError as e:
            raise _bad_request(str(e))

        results = []

        for pubkey_hex in delete_req.pubkeys:
            pubkey_hex = pubkey_hex.lower().replace("0x", "")
            removed, deleted = self._storage.remove_key(pubkey_hex)

            if removed and self._persistence_enabled and not deleted:
                logger.warning(f"Failed to delete keystore files from disk: {pubkey_hex[:20]}...")

            if removed:
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
        return web.json_response({"data": []})

    async def add_remote_keys(self, request: web.Request) -> web.Response:
        """POST /eth/v1/remotekeys - Add remote keys (stub)."""
        await self._require_auth(request)
        return web.json_response({"data": [], "message": "Remote keys not supported"}, status=501)

    async def delete_remote_keys(self, request: web.Request) -> web.Response:
        """DELETE /eth/v1/remotekeys - Delete remote keys (stub)."""
        await self._require_auth(request)
        return web.json_response({"data": [], "message": "Remote keys not supported"}, status=501)

    async def list_public_keys(self, request: web.Request) -> web.Response:
        """GET /api/v1/eth2/publicKeys - List available BLS public keys."""
        await self._require_auth(request)
        keys = self._storage.list_keys()
        public_keys = [f"0x{pubkey}" for pubkey, _, _ in keys]
        return web.json_response(public_keys)

    async def sign(self, request: web.Request) -> web.Response:
        """POST /api/v1/eth2/sign/:identifier - Sign data with detailed profiling."""
        profile_times = {}
        total_start = time.perf_counter()

        # Phase 1: HTTP parsing / initial request handling
        phase_start = time.perf_counter()
        await self._require_auth(request)
        profile_times["auth_check"] = (time.perf_counter() - phase_start) * 1_000_000

        phase_start = time.perf_counter()
        pubkey_hex = request.match_info.get("identifier", "").lower().replace("0x", "")
        if not pubkey_hex:
            raise _bad_request("Missing identifier")
        # Include header parsing in http_parsing
        body_bytes = await request.read()
        profile_times["http_parsing"] = (time.perf_counter() - phase_start) * 1_000_000

        # Phase 2: JSON parsing (msgspec)
        phase_start = time.perf_counter()
        try:
            sign_req: SignRequest = sign_request_decoder.decode(body_bytes)
        except (msgspec.ValidationError, msgspec.DecodeError) as e:
            raise _validation_error(e)
        except ValueError as e:
            raise _bad_request(str(e))
        profile_times["json_parsing"] = (time.perf_counter() - phase_start) * 1_000_000

        # Phase 3: Validate signing root
        phase_start = time.perf_counter()
        try:
            message = validate_signing_root(sign_req.signing_root)
        except ValueError as e:
            raise _bad_request(str(e))

        if message is None:
            raise _bad_request(
                "signing_root is required (SSZ signing root computation not yet implemented)"
            )
        # Include validation in domain_computation for now
        profile_times["domain_computation"] = (time.perf_counter() - phase_start) * 1_000_000

        # Phase 4: Domain computation
        phase_start = time.perf_counter()
        try:
            domain = get_domain_for_request(sign_req)
        except ValueError as e:
            raise web.HTTPInternalServerError(
                text=json.dumps({"error": str(e)}), content_type="application/json"
            )
        # Add to domain_computation time (already started above)
        profile_times["domain_computation"] += (time.perf_counter() - phase_start) * 1_000_000

        # Phase 5: Key lookup
        phase_start = time.perf_counter()
        secret_key = self._storage.get_secret_key(pubkey_hex)
        if secret_key is None:
            raise web.HTTPNotFound(
                text=json.dumps({"error": f"Key not found: {pubkey_hex}"}),
                content_type="application/json",
            )
        profile_times["key_lookup"] = (time.perf_counter() - phase_start) * 1_000_000

        # Phase 6: BLS signing (Rust)
        phase_start = time.perf_counter()
        try:
            # Import the Rust signing function directly
            from py3signer_core import sign

            signature = sign(secret_key, message, domain)
            signature_hex = signature.to_bytes().hex()
        except Exception as e:
            logger.exception("Signing error")
            raise web.HTTPInternalServerError(
                text=json.dumps({"error": f"Signing failed: {e}"}), content_type="application/json"
            )
        profile_times["bls_signing"] = (time.perf_counter() - phase_start) * 1_000_000

        # Phase 7: Response encoding
        phase_start = time.perf_counter()
        response_data = {"signature": f"0x{signature_hex}", "_profile": profile_times}
        profile_times["response_encoding"] = (time.perf_counter() - phase_start) * 1_000_000

        # Update total time
        profile_times["total"] = (time.perf_counter() - total_start) * 1_000_000

        return web.json_response(response_data)


def setup_routes(app: web.Application, handler: ProfilingAPIHandler) -> None:
    """Set up all routes for the application."""
    app.router.add_get("/health", handler.health)
    app.router.add_get("/eth/v1/keystores", handler.list_keystores)
    app.router.add_post("/eth/v1/keystores", handler.import_keystores)
    app.router.add_delete("/eth/v1/keystores", handler.delete_keystores)
    app.router.add_get("/eth/v1/remotekeys", handler.list_remote_keys)
    app.router.add_post("/eth/v1/remotekeys", handler.add_remote_keys)
    app.router.add_delete("/eth/v1/remotekeys", handler.delete_remote_keys)
    app.router.add_get("/api/v1/eth2/publicKeys", handler.list_public_keys)
    app.router.add_post("/api/v1/eth2/sign/{identifier}", handler.sign)
