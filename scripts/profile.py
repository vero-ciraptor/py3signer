#!/usr/bin/env python3
"""Profiling script for py3signer HTTP request handling.

This script profiles each phase of the /api/v1/eth2/sign/{identifier} endpoint
to identify where overhead is coming from (1.4k HTTP req/s vs 5k+ raw Rust signing).

Phases profiled:
1. HTTP layer: Request parsing, routing
2. JSON parsing: msgspec decoding of request body
3. Domain computation: Fork info → domain calculation
4. Key lookup: Finding the secret key in storage
5. BLS signing: The actual Rust signing operation
6. Response encoding: Building the JSON response
"""

import argparse
import asyncio
import json
import statistics
import sys
import time
from dataclasses import dataclass, field
from typing import Any

import aiohttp


@dataclass
class PhaseTiming:
    """Timing data for a single request phase."""
    name: str
    elapsed_us: float


@dataclass
class RequestProfile:
    """Complete timing profile for a single signing request."""
    total_time_us: float = 0.0
    phases: list[PhaseTiming] = field(default_factory=list)
    
    def add_phase(self, name: str, elapsed_us: float) -> None:
        self.phases.append(PhaseTiming(name, elapsed_us))
    
    def get_phase_time(self, name: str) -> float:
        for phase in self.phases:
            if phase.name == name:
                return phase.elapsed_us
        return 0.0


@dataclass
class ProfileResults:
    """Aggregated profiling results across all requests."""
    total_requests: int = 0
    profiles: list[RequestProfile] = field(default_factory=list)
    
    def add_profile(self, profile: RequestProfile) -> None:
        self.profiles.append(profile)
        self.total_requests += 1
    
    def get_phase_stats(self, phase_name: str) -> dict[str, float]:
        """Get statistics for a specific phase across all requests."""
        times = [p.get_phase_time(phase_name) for p in self.profiles]
        if not times:
            return {"mean": 0, "min": 0, "max": 0, "p50": 0, "p95": 0, "p99": 0}
        
        sorted_times = sorted(times)
        return {
            "mean": statistics.mean(times),
            "min": min(times),
            "max": max(times),
            "p50": sorted_times[len(sorted_times) // 2],
            "p95": sorted_times[int(len(sorted_times) * 0.95)],
            "p99": sorted_times[int(len(sorted_times) * 0.99)],
        }
    
    def get_total_time_stats(self) -> dict[str, float]:
        """Get statistics for total request time."""
        times = [p.total_time_us for p in self.profiles]
        if not times:
            return {"mean": 0, "min": 0, "max": 0, "p50": 0, "p95": 0, "p99": 0}
        
        sorted_times = sorted(times)
        return {
            "mean": statistics.mean(times),
            "min": min(times),
            "max": max(times),
            "p50": sorted_times[len(sorted_times) // 2],
            "p95": sorted_times[int(len(sorted_times) * 0.95)],
            "p99": sorted_times[int(len(sorted_times) * 0.99)],
        }
    
    def print_report(self) -> None:
        """Print a formatted profiling report."""
        phase_names = [
            "http_parsing",
            "json_parsing",
            "auth_check",
            "domain_computation",
            "key_lookup",
            "bls_signing",
            "response_encoding",
        ]
        
        # Get phase stats
        phase_stats = {name: self.get_phase_stats(name) for name in phase_names}
        total_stats = self.get_total_time_stats()
        
        # Calculate throughput
        total_time_sum = sum(p.total_time_us for p in self.profiles)
        avg_time_per_req = total_time_sum / self.total_requests if self.total_requests > 0 else 0
        theoretical_max_rps = 1_000_000 / avg_time_per_req if avg_time_per_req > 0 else 0
        
        print("\n" + "=" * 80)
        print("PY3SIGNER PROFILING REPORT")
        print("=" * 80)
        print(f"Total Requests Profiled: {self.total_requests}")
        print(f"Avg Request Time: {total_stats['mean']:.1f} µs")
        print(f"P50 Request Time: {total_stats['p50']:.1f} µs")
        print(f"P95 Request Time: {total_stats['p95']:.1f} µs")
        print(f"P99 Request Time: {total_stats['p99']:.1f} µs")
        print(f"Min Request Time: {total_stats['min']:.1f} µs")
        print(f"Max Request Time: {total_stats['max']:.1f} µs")
        print(f"Theoretical Max RPS (single-threaded): {theoretical_max_rps:.0f}")
        print()
        
        # Calculate mean percentages
        print("Phase Breakdown (mean times):")
        print("-" * 80)
        print(f"{'Phase':<30} {'Time (µs)':<12} {'% of total':<12} {'P95 (µs)':<12}")
        print("-" * 80)
        
        total_measured = 0.0
        for name in phase_names:
            stats = phase_stats[name]
            pct = (stats["mean"] / total_stats["mean"] * 100) if total_stats["mean"] > 0 else 0
            total_measured += stats["mean"]
            print(f"{name:<30} {stats['mean']:<12.1f} {pct:<12.1f} {stats['p95']:<12.1f}")
        
        print("-" * 80)
        # Calculate overhead (time not accounted for by measured phases)
        overhead = total_stats["mean"] - total_measured
        overhead_pct = (overhead / total_stats["mean"] * 100) if total_stats["mean"] > 0 else 0
        print(f"{'(overhead/unmeasured)':<30} {overhead:<12.1f} {overhead_pct:<12.1f}")
        print(f"{'TOTAL':<30} {total_stats['mean']:<12.1f} {100.0:<12.1f}")
        print("=" * 80)
        
        # Identify bottlenecks
        print("\nBOTTLENECK ANALYSIS:")
        print("-" * 80)
        
        sorted_phases = sorted(
            [(name, stats["mean"], stats["mean"] / total_stats["mean"] * 100) 
             for name, stats in phase_stats.items()],
            key=lambda x: x[1],
            reverse=True
        )
        
        for i, (name, time_us, pct) in enumerate(sorted_phases[:3], 1):
            print(f"  {i}. {name}: {time_us:.1f} µs ({pct:.1f}% of total)")
        
        # Compare to theoretical max
        raw_signing_time = phase_stats["bls_signing"]["mean"]
        http_overhead = total_stats["mean"] - raw_signing_time
        overhead_ratio = http_overhead / raw_signing_time if raw_signing_time > 0 else 0
        
        print(f"\nRAW vs HTTP COMPARISON:")
        print(f"  Raw BLS signing: {raw_signing_time:.1f} µs")
        print(f"  HTTP stack overhead: {http_overhead:.1f} µs ({overhead_ratio:.1f}x raw signing)")
        print(f"  Expected raw RPS: {1_000_000 / raw_signing_time:.0f}")
        print(f"  Actual HTTP RPS: {theoretical_max_rps:.0f}")
        print(f"  Efficiency: {(raw_signing_time / total_stats['mean'] * 100):.1f}%")
        print("=" * 80)


# Sample keystore for testing
SAMPLE_KEYSTORE = {
    "crypto": {
        "kdf": {
            "function": "scrypt",
            "params": {
                "dklen": 32,
                "n": 262144,
                "p": 1,
                "r": 8,
                "salt": "6be0cacaea53966620ff7f9dd382fafa6f440742decb8767b596561eb99e8166",
            },
            "message": "",
        },
        "checksum": {
            "function": "sha256",
            "params": {},
            "message": "18479069bd8aa2f30e0fb5e15213976cca24e9f807792a3b3ce9be64b8a536b5",
        },
        "cipher": {
            "function": "aes-256-ctr",
            "params": {"iv": "b0ab452c5f261d39f5be6ff1a8dd87df"},
            "message": "d8a426a250cf2092990556a9b6670bc179d765708b04fef4f46bc507c929078c",
        },
    },
    "description": "Test keystore with scrypt KDF (N=262144)",
    "pubkey": "a792e85e01746b22e89c7289aa693c4413db2c83d1209380cc4e98fc132ba49c301606032f77089d90e2df0539d23037",
    "path": "m/12381/3600/0/0/0",
    "uuid": "f1b49410-fd1d-41fd-a222-340f74867fa9",
    "version": 4,
}

SAMPLE_KEYSTORE_PASSWORD = "testpassword123"

FORK_INFO = {
    "fork": {
        "previous_version": "0x00000000",
        "current_version": "0x00000000",
        "epoch": "0",
    },
    "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
}


def create_signing_request() -> dict[str, Any]:
    """Create an ATTESTATION signing request."""
    return {
        "type": "ATTESTATION",
        "fork_info": FORK_INFO,
        "signingRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "attestation": {
            "slot": "123",
            "index": "0",
            "beacon_block_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "source": {
                "epoch": "0",
                "root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            },
            "target": {
                "epoch": "1",
                "root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            },
        },
    }


async def import_test_keystore(
    session: aiohttp.ClientSession, base_url: str, auth_token: str | None
) -> str | None:
    """Import the test keystore and return the public key."""
    headers = {"Content-Type": "application/json"}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    payload = {
        "keystores": [json.dumps(SAMPLE_KEYSTORE)],
        "passwords": [SAMPLE_KEYSTORE_PASSWORD],
    }

    try:
        async with session.post(
            f"{base_url}/eth/v1/keystores",
            json=payload,
            headers=headers,
        ) as response:
            if response.status == 200:
                data = await response.json()
                if data.get("data") and len(data["data"]) > 0:
                    status = data["data"][0].get("status")
                    if status in ("imported", "duplicate"):
                        return str(SAMPLE_KEYSTORE["pubkey"])
                    print(f"Keystore import failed: {data['data'][0].get('message', status)}")
                    return None
            else:
                text = await response.text()
                print(f"Keystore import failed: HTTP {response.status} - {text}")
                return None
    except Exception as e:
        print(f"Keystore import error: {e}")
        return None

    return None


async def check_server_health(
    session: aiohttp.ClientSession, base_url: str, auth_token: str | None
) -> bool:
    """Check if the server is healthy."""
    headers = {}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    try:
        async with session.get(
            f"{base_url}/health",
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=5),
        ) as response:
            if response.status == 200:
                data = await response.json()
                print(f"Server is healthy. Keys loaded: {data.get('keys_loaded', 'unknown')}")
                return True
            else:
                print(f"Server health check failed: HTTP {response.status}")
                return False
    except Exception as e:
        print(f"Server health check error: {e}")
        return False


async def profile_single_request(
    session: aiohttp.ClientSession,
    base_url: str,
    pubkey: str,
    auth_token: str | None,
) -> RequestProfile:
    """Profile a single signing request with detailed timing.
    
    Note: Since we can't instrument the server directly from the client,
    we measure round-trip timing and use server-side profiling if available.
    For comprehensive profiling, we need to instrument the server code.
    """
    profile = RequestProfile()
    
    headers = {"Content-Type": "application/json"}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    payload = create_signing_request()
    payload_json = json.dumps(payload)
    
    # Measure total client-side time (includes network latency)
    start_total = time.perf_counter()
    
    try:
        # Use raw bytes to avoid extra serialization timing
        async with session.post(
            f"{base_url}/api/v1/eth2/sign/{pubkey}",
            data=payload_json,
            headers=headers,
        ) as response:
            await response.read()  # Read full response
            end_total = time.perf_counter()
            
            profile.total_time_us = (end_total - start_total) * 1_000_000
            
            # If server returns profiling data, parse it
            if response.status == 200:
                try:
                    data = await response.json()
                    if "_profile" in data:
                        # Server-side profiling data available
                        server_profile = data["_profile"]
                        for phase_name, phase_time_us in server_profile.items():
                            profile.add_phase(phase_name, phase_time_us)
                except:
                    pass
            
    except Exception as e:
        end_total = time.perf_counter()
        profile.total_time_us = (end_total - start_total) * 1_000_000
        print(f"Request failed: {e}")
    
    return profile


async def run_client_side_profile(
    base_url: str,
    pubkey: str,
    auth_token: str | None,
    num_requests: int,
) -> ProfileResults:
    """Run client-side profiling of signing requests."""
    results = ProfileResults()
    
    timeout = aiohttp.ClientTimeout(total=30)
    connector = aiohttp.TCPConnector(limit=10, limit_per_host=10)
    
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        for i in range(num_requests):
            profile = await profile_single_request(session, base_url, pubkey, auth_token)
            results.add_profile(profile)
            
            if (i + 1) % 100 == 0:
                print(f"  Completed {i + 1}/{num_requests} requests...")
    
    return results


def create_instrumented_handler_module() -> str:
    """Create the instrumented handler module code."""
    return '''
"""Instrumented HTTP route handlers for profiling."""

import json
import logging
import time

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
                "signingRoot is required (SSZ signing root computation not yet implemented)"
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
                text=json.dumps({"error": f"Key not found: {pubkey_hex}"}), content_type="application/json"
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
'''


def create_instrumented_server_module() -> str:
    """Create the instrumented server module code."""
    return '''
"""aiohttp server setup with profiling support."""

import asyncio
import logging
import ssl

from aiohttp import web

from py3signer.bulk_loader import load_keystores_from_directory
from py3signer.config import Config
from py3signer.handlers_profiled import ProfilingAPIHandler, setup_routes
from py3signer.metrics import MetricsServer, setup_metrics_middleware
from py3signer.signer import Signer
from py3signer.storage import KeyStorage

logger = logging.getLogger(__name__)

# Typed app keys to avoid NotAppKeyWarning
APP_KEY_STORAGE: web.AppKey[KeyStorage] = web.AppKey("storage", KeyStorage)
APP_KEY_SIGNER: web.AppKey[Signer] = web.AppKey("signer", Signer)


def create_app(config: Config) -> web.Application:
    """Create and configure the aiohttp application with profiling."""
    # Create components
    storage = KeyStorage(keystore_path=config.key_store_path)
    signer = Signer(storage)
    handler = ProfilingAPIHandler(storage, signer, auth_token=config.auth_token)

    # Load keystores from directory if configured
    if config.key_store_path:
        success, failures = load_keystores_from_directory(config.key_store_path, storage)
        logger.info(f"Loaded {success} keystores from {config.key_store_path}")
        if failures > 0:
            logger.warning(f"Failed to load {failures} keystores")

    # Create app
    app = web.Application()

    # Store components in app for access using typed AppKey
    app[APP_KEY_STORAGE] = storage
    app[APP_KEY_SIGNER] = signer

    # Setup routes
    setup_routes(app, handler)

    # Setup metrics middleware (after routes are registered)
    setup_metrics_middleware(app)

    return app


async def run_server(config: Config) -> None:
    """Run the aiohttp server with profiling enabled."""
    logger.info(f"Starting py3signer (with profiling) on {config.host}:{config.port}")

    # Create app
    app = create_app(config)

    # Setup SSL if configured
    ssl_context: ssl.SSLContext | None = None
    if config.tls_cert and config.tls_key:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(str(config.tls_cert), str(config.tls_key))
        logger.info("TLS enabled")

    # Run server
    runner = web.AppRunner(app)
    await runner.setup()

    site = web.TCPSite(runner, host=config.host, port=config.port, ssl_context=ssl_context)

    await site.start()

    protocol = "https" if ssl_context else "http"
    logger.info(f"Server running at {protocol}://{config.host}:{config.port}")
    logger.info("PROFILING MODE: Sign endpoint returns timing data in _profile field")

    # Start metrics server if enabled
    metrics_server: MetricsServer | None = None
    metrics_server = MetricsServer(host=config.metrics_host, port=config.metrics_port)
    await metrics_server.start()

    logger.info("Press Ctrl+C to stop")

    # Keep running
    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        pass
    finally:
        await metrics_server.stop()
        await runner.cleanup()


if __name__ == "__main__":
    from py3signer.config import Config
    import argparse
    
    parser = argparse.ArgumentParser(description="Run py3signer with profiling")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind to")
    parser.add_argument("--keystore-path", help="Path to keystores")
    
    args = parser.parse_args()
    
    config = Config(
        host=args.host,
        port=args.port,
        key_store_path=args.keystore_path,
    )
    
    try:
        asyncio.run(run_server(config))
    except KeyboardInterrupt:
        logger.info("Server stopped")
'''


def write_instrumented_handlers() -> None:
    """Write the instrumented handler module to disk."""
    handlers_path = "/home/admin/.openclaw/workspace/py3signer/py3signer/handlers_profiled.py"
    with open(handlers_path, "w") as f:
        f.write(create_instrumented_handler_module())
    print(f"Created {handlers_path}")
    
    server_path = "/home/admin/.openclaw/workspace/py3signer/scripts/profile_server.py"
    with open(server_path, "w") as f:
        f.write(create_instrumented_server_module())
    print(f"Created {server_path}")


async def run_profile_with_server(
    base_url: str,
    num_requests: int,
    auth_token: str | None,
) -> ProfileResults:
    """Run profiling against a running server."""
    results = ProfileResults()
    
    headers = {"Content-Type": "application/json"}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    # First, import a test keystore
    timeout = aiohttp.ClientTimeout(total=30)
    
    async with aiohttp.ClientSession(timeout=timeout) as session:
        # Check health and get pubkey
        pubkey = None
        try:
            async with session.get(f"{base_url}/health", headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"Server healthy. Keys loaded: {data.get('keys_loaded', 'unknown')}")
        except Exception as e:
            print(f"Server health check failed: {e}")
            return results

        # Try to get existing pubkey
        try:
            async with session.get(f"{base_url}/api/v1/eth2/publicKeys", headers=headers) as response:
                if response.status == 200:
                    keys = await response.json()
                    if keys:
                        pubkey = keys[0].replace("0x", "")
                        print(f"Using existing key: {pubkey[:20]}...")
        except Exception:
            pass

        # Import test keystore if needed
        if pubkey is None:
            print("Importing test keystore...")
            payload = {
                "keystores": [json.dumps(SAMPLE_KEYSTORE)],
                "passwords": [SAMPLE_KEYSTORE_PASSWORD],
            }
            try:
                async with session.post(
                    f"{base_url}/eth/v1/keystores",
                    json=payload,
                    headers=headers,
                ) as response:
                    if response.status == 200:
                        pubkey = str(SAMPLE_KEYSTORE["pubkey"])
                        print(f"Imported key: {pubkey[:20]}...")
            except Exception as e:
                print(f"Failed to import keystore: {e}")
                return results

        if not pubkey:
            print("No public key available for signing")
            return results

        # Run profiling requests
        print(f"\nRunning {num_requests} profiled requests...")
        payload = create_signing_request()
        
        for i in range(num_requests):
            try:
                start = time.perf_counter()
                async with session.post(
                    f"{base_url}/api/v1/eth2/sign/{pubkey}",
                    json=payload,
                    headers=headers,
                ) as response:
                    data = await response.json()
                    end = time.perf_counter()
                    
                    profile = RequestProfile()
                    profile.total_time_us = (end - start) * 1_000_000
                    
                    # Extract server profiling data if available
                    if "_profile" in data:
                        server_profile = data["_profile"]
                        for phase_name, phase_time in server_profile.items():
                            if phase_name != "total":
                                profile.add_phase(phase_name, phase_time)
                    
                    results.add_profile(profile)
                    
                    if (i + 1) % 100 == 0:
                        print(f"  Completed {i + 1}/{num_requests} requests...")
                        
            except Exception as e:
                print(f"Request {i} failed: {e}")
    
    return results


async def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Profile py3signer HTTP request handling",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Profile a running server
  python scripts/profile.py --url http://localhost:8080 --requests 1000

  # Auto-start server with profiling instrumentation
  python scripts/profile.py --start-server --requests 1000

  # Custom port
  python scripts/profile.py --start-server --port 9000 --requests 500
        """,
    )

    parser.add_argument(
        "--url",
        type=str,
        default="http://localhost:8080",
        help="Server URL (default: http://localhost:8080)",
    )
    parser.add_argument(
        "--requests",
        type=int,
        default=1000,
        help="Number of requests to profile (default: 1000)",
    )
    parser.add_argument(
        "--auth-token",
        type=str,
        default=None,
        help="Auth token if server requires authentication",
    )
    parser.add_argument(
        "--start-server",
        action="store_true",
        help="Start a profiled server automatically",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port for auto-started server (default: 8080)",
    )
    parser.add_argument(
        "--setup-only",
        action="store_true",
        help="Only write the instrumented handler files, don't run",
    )

    args = parser.parse_args()

    print("=" * 80)
    print("PY3SIGNER PROFILING TOOL")
    print("=" * 80)
    print()

    # Write the instrumented handlers
    write_instrumented_handlers()
    
    if args.setup_only:
        print("\nSetup complete. Instrumented handlers written.")
        print("To use: Modify py3signer to use handlers_profiled.ProfilingAPIHandler")
        return 0

    # Check if we need to start the server
    server_process = None
    if args.start_server:
        import subprocess
        import os
        
        print("Starting profiled server...")
        env = os.environ.copy()
        env["PYTHONPATH"] = "/home/admin/.openclaw/workspace/py3signer"
        
        server_process = subprocess.Popen(
            [
                sys.executable,
                "-m", "py3signer",
                "--host", "127.0.0.1",
                "--port", str(args.port),
            ],
            cwd="/home/admin/.openclaw/workspace/py3signer",
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        
        # Wait for server to start
        print("Waiting for server to start...")
        await asyncio.sleep(2)
        args.url = f"http://127.0.0.1:{args.port}"

    try:
        # Run the profiling
        results = await run_profile_with_server(
            base_url=args.url,
            num_requests=args.requests,
            auth_token=args.auth_token,
        )
        
        # Print the report
        results.print_report()
        
    finally:
        if server_process:
            print("\nStopping server...")
            server_process.terminate()
            try:
                server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_process.kill()

    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("\nProfiling interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
