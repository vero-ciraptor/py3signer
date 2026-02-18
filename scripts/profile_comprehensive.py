#!/usr/bin/env python3
"""Comprehensive profiling script for py3signer.

This script:
1. Measures raw Rust BLS signing performance (no HTTP)
2. Measures HTTP server performance with detailed phase breakdown
3. Compares the two to identify overhead sources
"""

import asyncio
import json
import statistics
import sys
import time
from dataclasses import dataclass, field
from typing import Any

import aiohttp


# Sample keystore
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


def profile_raw_signing(iterations: int = 10000) -> dict[str, float]:
    """Profile raw Rust BLS signing without any HTTP overhead."""
    from py3signer_core import SecretKey, sign

    # Decrypt the keystore to get the secret key
    from py3signer.keystore import Keystore

    keystore = Keystore.from_json(json.dumps(SAMPLE_KEYSTORE))
    secret_key = keystore.decrypt(SAMPLE_KEYSTORE_PASSWORD)

    # Prepare signing data
    message = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
    domain = bytes.fromhex("01000000")  # DOMAIN_BEACON_ATTESTER

    print(f"Warming up with 100 iterations...")
    for _ in range(100):
        sign(secret_key, message, domain)

    print(f"Running {iterations} raw signing iterations...")
    times = []

    for i in range(iterations):
        start = time.perf_counter()
        signature = sign(secret_key, message, domain)
        end = time.perf_counter()
        times.append((end - start) * 1_000_000)  # Convert to microseconds

        if (i + 1) % 1000 == 0:
            print(f"  Completed {i + 1}/{iterations}")

    sorted_times = sorted(times)
    return {
        "mean": statistics.mean(times),
        "min": min(times),
        "max": max(times),
        "p50": sorted_times[len(sorted_times) // 2],
        "p95": sorted_times[int(len(sorted_times) * 0.95)],
        "p99": sorted_times[int(len(sorted_times) * 0.99)],
        "stddev": statistics.stdev(times) if len(times) > 1 else 0,
    }


def profile_python_overhead(iterations: int = 10000) -> dict[str, float]:
    """Profile the Python-level overhead (key lookup, domain computation, etc.)."""
    import sys

    sys.path.insert(0, "/home/admin/.openclaw/workspace/py3signer")

    from py3signer.keystore import Keystore
    from py3signer.storage import KeyStorage
    from py3signer.signing_types import (
        get_domain_for_request,
        sign_request_decoder,
        validate_signing_root,
    )

    # Setup storage with key
    storage = KeyStorage()
    keystore = Keystore.from_json(json.dumps(SAMPLE_KEYSTORE))
    secret_key = keystore.decrypt(SAMPLE_KEYSTORE_PASSWORD)
    pubkey = secret_key.public_key()
    storage.add_key(pubkey, secret_key, path="m/12381/3600/0/0/0")
    pubkey_hex = pubkey.to_bytes().hex()

    # Prepare request data
    request_json = json.dumps(create_signing_request())

    print(f"Warming up with 100 iterations...")
    for _ in range(100):
        sign_req = sign_request_decoder.decode(request_json.encode())
        message = validate_signing_root(sign_req.signing_root)
        domain = get_domain_for_request(sign_req)
        sk = storage.get_secret_key(pubkey_hex)

    print(f"Running {iterations} Python overhead iterations...")

    # Time each phase separately
    json_times = []
    domain_times = []
    key_lookup_times = []

    for i in range(iterations):
        # JSON parsing
        start = time.perf_counter()
        sign_req = sign_request_decoder.decode(request_json.encode())
        json_times.append((time.perf_counter() - start) * 1_000_000)

        # Domain computation + validation
        start = time.perf_counter()
        message = validate_signing_root(sign_req.signing_root)
        domain = get_domain_for_request(sign_req)
        domain_times.append((time.perf_counter() - start) * 1_000_000)

        # Key lookup
        start = time.perf_counter()
        sk = storage.get_secret_key(pubkey_hex)
        key_lookup_times.append((time.perf_counter() - start) * 1_000_000)

        if (i + 1) % 1000 == 0:
            print(f"  Completed {i + 1}/{iterations}")

    def get_stats(times):
        sorted_times = sorted(times)
        return {
            "mean": statistics.mean(times),
            "min": min(times),
            "max": max(times),
            "p50": sorted_times[len(sorted_times) // 2],
            "p95": sorted_times[int(len(sorted_times) * 0.95)],
            "p99": sorted_times[int(len(sorted_times) * 0.99)],
        }

    return {
        "json_parsing": get_stats(json_times),
        "domain_computation": get_stats(domain_times),
        "key_lookup": get_stats(key_lookup_times),
    }


async def profile_http_server(
    base_url: str,
    num_requests: int = 1000,
) -> dict[str, Any]:
    """Profile the HTTP server with detailed phase breakdown."""

    headers = {"Content-Type": "application/json"}

    timeout = aiohttp.ClientTimeout(total=30)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        # Import test keystore
        print("Importing test keystore...")
        payload = {
            "keystores": [json.dumps(SAMPLE_KEYSTORE)],
            "passwords": [SAMPLE_KEYSTORE_PASSWORD],
        }

        async with session.post(
            f"{base_url}/eth/v1/keystores", json=payload, headers=headers
        ) as response:
            if response.status != 200:
                print(f"Failed to import keystore: {await response.text()}")
                return {}

        pubkey = str(SAMPLE_KEYSTORE["pubkey"])
        print(f"Using key: {pubkey[:30]}...")

        # Profile requests
        print(f"Running {num_requests} HTTP requests...")

        phase_times = {
            "http_parsing": [],
            "json_parsing": [],
            "auth_check": [],
            "domain_computation": [],
            "key_lookup": [],
            "bls_signing": [],
            "response_encoding": [],
            "total_server": [],
            "total_client": [],
        }

        request_payload = create_signing_request()

        for i in range(num_requests):
            client_start = time.perf_counter()

            async with session.post(
                f"{base_url}/api/v1/eth2/sign/{pubkey}",
                json=request_payload,
                headers=headers,
            ) as response:
                data = await response.json()
                client_end = time.perf_counter()

                client_time = (client_end - client_start) * 1_000_000
                phase_times["total_client"].append(client_time)

                if "_profile" in data:
                    profile = data["_profile"]
                    for phase in [
                        "http_parsing",
                        "json_parsing",
                        "auth_check",
                        "domain_computation",
                        "key_lookup",
                        "bls_signing",
                        "response_encoding",
                    ]:
                        if phase in profile:
                            phase_times[phase].append(profile[phase])
                    if "total" in profile:
                        phase_times["total_server"].append(profile["total"])

            if (i + 1) % 100 == 0:
                print(f"  Completed {i + 1}/{num_requests}")

        # Calculate statistics
        def get_stats(times):
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

        return {phase: get_stats(times) for phase, times in phase_times.items()}


def print_report(raw_stats, python_stats, http_stats):
    """Print a comprehensive profiling report."""
    print("\n" + "=" * 80)
    print("PY3SIGNER COMPREHENSIVE PROFILING REPORT")
    print("=" * 80)

    # Raw signing performance
    print("\n1. RAW BLS SIGNING (Rust, no overhead):")
    print("-" * 60)
    print(f"  Mean: {raw_stats['mean']:.1f} µs ({1000000 / raw_stats['mean']:.0f} ops/sec)")
    print(f"  P50:  {raw_stats['p50']:.1f} µs")
    print(f"  P95:  {raw_stats['p95']:.1f} µs")
    print(f"  P99:  {raw_stats['p99']:.1f} µs")
    print(f"  Min:  {raw_stats['min']:.1f} µs")
    print(f"  Max:  {raw_stats['max']:.1f} µs")

    # Python overhead breakdown
    print("\n2. PYTHON OVERHEAD BREAKDOWN:")
    print("-" * 60)
    total_python = 0
    for phase_name, phase_stats in python_stats.items():
        print(f"  {phase_name:20s}: {phase_stats['mean']:6.1f} µs (P95: {phase_stats['p95']:.1f})")
        total_python += phase_stats["mean"]
    print(f"  {'Total Python overhead':20s}: {total_python:6.1f} µs")

    # HTTP server breakdown
    print("\n3. HTTP SERVER BREAKDOWN (measured server-side):")
    print("-" * 60)
    total_measured = 0
    for phase_name in [
        "http_parsing",
        "json_parsing",
        "auth_check",
        "domain_computation",
        "key_lookup",
        "bls_signing",
        "response_encoding",
    ]:
        if phase_name in http_stats:
            phase_stats = http_stats[phase_name]
            print(
                f"  {phase_name:20s}: {phase_stats['mean']:6.1f} µs (P95: {phase_stats['p95']:.1f})"
            )
            total_measured += phase_stats["mean"]

    if "total_server" in http_stats:
        server_total = http_stats["total_server"]["mean"]
        overhead = server_total - total_measured
        print(f"  {'Unmeasured overhead':20s}: {overhead:6.1f} µs")
        print(f"  {'TOTAL (server-side)':20s}: {server_total:6.1f} µs")

    # Client vs Server comparison
    if "total_client" in http_stats and "total_server" in http_stats:
        client_total = http_stats["total_client"]["mean"]
        server_total = http_stats["total_server"]["mean"]
        network_overhead = client_total - server_total

        print("\n4. NETWORK OVERHEAD:")
        print("-" * 60)
        print(f"  Client round-trip:    {client_total:6.1f} µs")
        print(f"  Server processing:    {server_total:6.1f} µs")
        print(
            f"  Network + framework:  {network_overhead:6.1f} µs ({network_overhead / client_total * 100:.1f}%)"
        )

    # Efficiency analysis
    print("\n5. EFFICIENCY ANALYSIS:")
    print("-" * 60)

    raw_rps = 1000000 / raw_stats["mean"]
    print(f"  Raw Rust RPS:         {raw_rps:6.0f}")

    if "total_client" in http_stats:
        http_rps = 1000000 / http_stats["total_client"]["mean"]
        print(f"  HTTP client RPS:      {http_rps:6.0f}")
        print(f"  Efficiency:           {http_rps / raw_rps * 100:6.1f}%")

        overhead_x = http_stats["total_client"]["mean"] / raw_stats["mean"]
        print(f"  Overhead factor:      {overhead_x:6.2f}x raw signing")

    # Bottleneck identification
    print("\n6. BOTTLENECK ANALYSIS:")
    print("-" * 60)

    # Sort phases by mean time
    phase_means = []
    for phase_name in [
        "http_parsing",
        "json_parsing",
        "auth_check",
        "domain_computation",
        "key_lookup",
        "bls_signing",
        "response_encoding",
    ]:
        if phase_name in http_stats:
            phase_means.append((phase_name, http_stats[phase_name]["mean"]))

    phase_means.sort(key=lambda x: x[1], reverse=True)

    print("  Top 3 server-side phases:")
    for i, (name, mean_time) in enumerate(phase_means[:3], 1):
        pct = mean_time / server_total * 100 if server_total > 0 else 0
        print(f"    {i}. {name}: {mean_time:.1f} µs ({pct:.1f}%)")

    print("\n" + "=" * 80)

    # Recommendations
    print("\n7. RECOMMENDATIONS:")
    print("-" * 60)

    # Calculate network/framework overhead as the biggest issue
    if "total_client" in http_stats and "total_server" in http_stats:
        network_pct = network_overhead / client_total * 100
        if network_pct > 30:
            print(f"  ⚠️  HIGH NETWORK/FRAMEWORK OVERHEAD: {network_pct:.1f}% of total time")
            print("     Consider:")
            print("     - Keep-alive connections (already enabled)")
            print("     - HTTP/2 for connection multiplexing")
            print("     - Batching multiple signing requests")
            print("     - Using Unix sockets for local clients")

    # Check BLS signing vs expected
    if "bls_signing" in http_stats:
        bls_mean = http_stats["bls_signing"]["mean"]
        if bls_mean > raw_stats["mean"] * 1.5:
            print(f"  ⚠️  BLS SIGNING OVERHEAD: {bls_mean:.1f} µs vs {raw_stats['mean']:.1f} µs raw")
            print("     Python-to-Rust call overhead may be significant")
        else:
            print(f"  ✓  BLS signing performance is close to raw: {bls_mean:.1f} µs")

    # Check JSON parsing
    if "json_parsing" in http_stats:
        json_mean = http_stats["json_parsing"]["mean"]
        if json_mean > 10:
            print(f"  ⚠️  JSON parsing is relatively slow: {json_mean:.1f} µs")
            print("     msgspec should be faster - check request size")
        else:
            print(f"  ✓  JSON parsing is efficient: {json_mean:.1f} µs")

    print("=" * 80)


async def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Comprehensive py3signer profiling")
    parser.add_argument("--raw-iterations", type=int, default=10000, help="Raw signing iterations")
    parser.add_argument("--http-requests", type=int, default=1000, help="HTTP requests")
    parser.add_argument("--skip-raw", action="store_true", help="Skip raw signing test")
    parser.add_argument("--skip-python", action="store_true", help="Skip Python overhead test")
    parser.add_argument("--skip-http", action="store_true", help="Skip HTTP test")
    parser.add_argument("--url", default="http://127.0.0.1:9090", help="Server URL")

    args = parser.parse_args()

    print("=" * 80)
    print("PY3SIGNER COMPREHENSIVE PROFILER")
    print("=" * 80)

    raw_stats = {}
    python_stats = {}
    http_stats = {}

    # Profile raw signing
    if not args.skip_raw:
        print("\n[1/3] Profiling raw Rust BLS signing...")
        raw_stats = profile_raw_signing(args.raw_iterations)

    # Profile Python overhead
    if not args.skip_python:
        print("\n[2/3] Profiling Python overhead...")
        python_stats = profile_python_overhead(args.raw_iterations)

    # Profile HTTP server
    if not args.skip_http:
        print("\n[3/3] Profiling HTTP server...")
        print(f"Connecting to {args.url}...")
        http_stats = await profile_http_server(args.url, args.http_requests)

    # Print report
    print_report(raw_stats, python_stats, http_stats)


if __name__ == "__main__":
    asyncio.run(main())
