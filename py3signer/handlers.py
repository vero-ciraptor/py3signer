"""HTTP route handlers for Keymanager API with msgspec validation."""

import json
import logging
from typing import Any

from aiohttp import web
import msgspec

from .storage import KeyStorage
from .signer import Signer, SignerError
from .keystore import Keystore, KeystoreError

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


class SignRequest(msgspec.Struct):
    """Request struct for signing data."""
    signing_root: str | None = msgspec.field(name="signingRoot", default=None)
    domain: str | None = None
    domain_name: str | None = msgspec.field(name="domainName", default=None)

    def __post_init__(self) -> None:
        """Validate signing request."""
        # Validate signing_root if provided (must be 32 bytes = 64 hex chars)
        if self.signing_root is not None:
            signing_root_clean = self.signing_root.replace("0x", "")
            if len(signing_root_clean) != 64:
                raise ValueError("signingRoot must be 32 bytes (64 hex characters)")
            try:
                bytes.fromhex(signing_root_clean)
            except ValueError:
                raise ValueError("signingRoot must be valid hexadecimal")
        
        # Validate domain if provided (must be 4 bytes = 8 hex chars)
        if self.domain is not None:
            domain_clean = self.domain.replace("0x", "")
            if len(domain_clean) != 8:
                raise ValueError("domain must be 4 bytes (8 hex characters)")
            try:
                bytes.fromhex(domain_clean)
            except ValueError:
                raise ValueError("domain must be valid hexadecimal")
        
        # Must have either domain or domain_name
        if self.domain is None and self.domain_name is None:
            raise ValueError("Either domain or domainName must be provided")


# JSON decoders for request structs
keystore_import_decoder = msgspec.json.Decoder(KeystoreImportRequest)
keystore_delete_decoder = msgspec.json.Decoder(KeystoreDeleteRequest)
sign_request_decoder = msgspec.json.Decoder(SignRequest)


class APIHandler:
    """HTTP request handlers for the Keymanager API."""
    
    def __init__(self, storage: KeyStorage, signer: Signer, auth_token: str | None = None):
        self._storage = storage
        self._signer = signer
        self._auth_token = auth_token
    
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
                text=json.dumps({"error": "Unauthorized"}),
                content_type="application/json"
            )
    
    async def health(self, request: web.Request) -> web.Response:
        """Health check endpoint."""
        return web.json_response({
            "status": "healthy",
            "keys_loaded": len(self._storage)
        })
    
    async def list_keystores(self, request: web.Request) -> web.Response:
        """GET /eth/v1/keystores - List all imported keys."""
        await self._require_auth(request)
        
        keys = self._storage.list_keys()
        keystores = [
            {
                "validating_pubkey": pubkey,
                "derivation_path": path,
                "readonly": False
            }
            for pubkey, path, _ in keys
        ]
        
        return web.json_response({
            "data": keystores
        })
    
    async def import_keystores(self, request: web.Request) -> web.Response:
        """POST /eth/v1/keystores - Import keystores."""
        await self._require_auth(request)
        
        try:
            body_bytes = await request.read()
        except Exception:
            raise web.HTTPBadRequest(
                text=json.dumps({"error": "Failed to read request body"}),
                content_type="application/json"
            )
        
        # Validate request with msgspec
        try:
            import_req = keystore_import_decoder.decode(body_bytes)
        except (msgspec.ValidationError, msgspec.DecodeError) as e:
            raise web.HTTPBadRequest(
                text=json.dumps({"error": f"Validation error: {e}"}),
                content_type="application/json"
            )
        except ValueError as e:
            raise web.HTTPBadRequest(
                text=json.dumps({"error": str(e)}),
                content_type="application/json"
            )
        
        results = []
        
        for keystore_json, password in zip(import_req.keystores, import_req.passwords):
            try:
                keystore = Keystore.from_json(keystore_json)
                secret_key = keystore.decrypt(password)
                pubkey = secret_key.public_key()
                
                pubkey_hex = self._storage.add_key(
                    pubkey=pubkey,
                    secret_key=secret_key,
                    path=keystore.path,
                    description=keystore.description
                )
                
                results.append({
                    "status": "imported",
                    "message": f"Successfully imported keystore with pubkey {keystore.pubkey}"
                })
                
            except KeystoreError as e:
                results.append({
                    "status": "error",
                    "message": str(e)
                })
            except ValueError as e:
                results.append({
                    "status": "duplicate",
                    "message": str(e)
                })
            except Exception as e:
                logger.exception("Unexpected error importing keystore")
                results.append({
                    "status": "error",
                    "message": f"Internal error: {str(e)}"
                })
        
        return web.json_response({
            "data": results
        }, status=200)
    
    async def delete_keystores(self, request: web.Request) -> web.Response:
        """DELETE /eth/v1/keystores - Delete keystores."""
        await self._require_auth(request)
        
        try:
            body_bytes = await request.read()
        except Exception:
            raise web.HTTPBadRequest(
                text=json.dumps({"error": "Failed to read request body"}),
                content_type="application/json"
            )
        
        # Validate request with msgspec
        try:
            delete_req = keystore_delete_decoder.decode(body_bytes)
        except (msgspec.ValidationError, msgspec.DecodeError) as e:
            raise web.HTTPBadRequest(
                text=json.dumps({"error": f"Validation error: {e}"}),
                content_type="application/json"
            )
        except ValueError as e:
            raise web.HTTPBadRequest(
                text=json.dumps({"error": str(e)}),
                content_type="application/json"
            )
        
        results = []
        
        for pubkey_hex in delete_req.pubkeys:
            # Normalize pubkey
            pubkey_hex = pubkey_hex.lower().replace("0x", "")
            
            if self._storage.remove_key(pubkey_hex):
                results.append({
                    "status": "deleted",
                    "message": f"Successfully deleted keystore with pubkey {pubkey_hex}"
                })
            else:
                results.append({
                    "status": "not_found",
                    "message": f"Keystore not found for pubkey {pubkey_hex}"
                })
        
        return web.json_response({
            "data": results
        })
    
    async def list_remote_keys(self, request: web.Request) -> web.Response:
        """GET /eth/v1/remotekeys - List remote keys (stub)."""
        await self._require_auth(request)
        
        return web.json_response({
            "data": []  # Stub - no remote keys support
        })
    
    async def add_remote_keys(self, request: web.Request) -> web.Response:
        """POST /eth/v1/remotekeys - Add remote keys (stub)."""
        await self._require_auth(request)
        
        return web.json_response({
            "data": [],
            "message": "Remote keys not supported"
        }, status=501)
    
    async def delete_remote_keys(self, request: web.Request) -> web.Response:
        """DELETE /eth/v1/remotekeys - Delete remote keys (stub)."""
        await self._require_auth(request)
        
        return web.json_response({
            "data": [],
            "message": "Remote keys not supported"
        }, status=501)
    
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

        Note: This endpoint uses a simplified request format compared to the
        full Ethereum Remote Signing API spec. The spec supports typed signing
        requests with discriminators (e.g., {"type": "ATTESTATION", ...}),
        but py3signer currently only supports the simplified format with
        signingRoot and domain/domainName.
        """
        await self._require_auth(request)
        
        # Get identifier from path
        pubkey_hex = request.match_info.get("identifier", "").lower().replace("0x", "")
        
        if not pubkey_hex:
            raise web.HTTPBadRequest(
                text=json.dumps({"error": "Missing identifier"}),
                content_type="application/json"
            )
        
        try:
            body_bytes = await request.read()
        except Exception:
            raise web.HTTPBadRequest(
                text=json.dumps({"error": "Failed to read request body"}),
                content_type="application/json"
            )
        
        # Validate request with msgspec
        try:
            sign_req = sign_request_decoder.decode(body_bytes)
        except (msgspec.ValidationError, msgspec.DecodeError) as e:
            raise web.HTTPBadRequest(
                text=json.dumps({"error": f"Validation error: {e}"}),
                content_type="application/json"
            )
        except ValueError as e:
            raise web.HTTPBadRequest(
                text=json.dumps({"error": str(e)}),
                content_type="application/json"
            )
        
        # Convert hex to bytes
        if sign_req.signing_root is None:
            raise web.HTTPBadRequest(
                text=json.dumps({"error": "signingRoot is required (py3signer does not compute signing roots from SSZ data)"}),
                content_type="application/json"
            )
        message = bytes.fromhex(sign_req.signing_root.replace("0x", ""))
        
        # Determine domain
        domain: bytes | None = None
        if sign_req.domain:
            domain = bytes.fromhex(sign_req.domain.replace("0x", ""))
        
        try:
            signature = self._signer.sign_data(
                pubkey_hex=pubkey_hex,
                data=message,
                domain=domain,
                domain_name=sign_req.domain_name
            )
            
            signature_hex = signature.to_bytes().hex()
            
            return web.json_response({
                "signature": f"0x{signature_hex}"
            })
            
        except SignerError as e:
            raise web.HTTPNotFound(
                text=json.dumps({"error": str(e)}),
                content_type="application/json"
            )
        except Exception as e:
            logger.exception("Signing error")
            raise web.HTTPInternalServerError(
                text=json.dumps({"error": f"Signing failed: {str(e)}"}),
                content_type="application/json"
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
