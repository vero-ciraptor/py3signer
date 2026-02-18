#!/usr/bin/env python3
"""Benchmark script for py3signer signature throughput.

This script measures how many signatures per second py3signer can provide
on the /api/v1/eth2/sign/{identifier} endpoint.
"""

import argparse
import asyncio
import json
import os
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import aiohttp


@dataclass
class BenchmarkResult:
    """Results from a benchmark run."""

    total_time: float
    total_requests: int
    successful_requests: int
    failed_requests: int
    latencies: list[float]
    _url: str = ""
    _concurrency: int = 0

    @property
    def signatures_per_second(self) -> float:
        """Calculate signatures per second."""
        if self.total_time == 0:
            return 0.0
        return self.successful_requests / self.total_time

    @property
    def requests_per_second(self) -> float:
        """Calculate total requests per second."""
        if self.total_time == 0:
            return 0.0
        return self.total_requests / self.total_time

    @property
    def error_rate(self) -> float:
        """Calculate error rate as percentage."""
        if self.total_requests == 0:
            return 0.0
        return (self.failed_requests / self.total_requests) * 100

    @property
    def avg_latency(self) -> float:
        """Calculate average latency in milliseconds."""
        if not self.latencies:
            return 0.0
        return statistics.mean(self.latencies) * 1000

    @property
    def min_latency(self) -> float:
        """Calculate minimum latency in milliseconds."""
        if not self.latencies:
            return 0.0
        return min(self.latencies) * 1000

    @property
    def max_latency(self) -> float:
        """Calculate maximum latency in milliseconds."""
        if not self.latencies:
            return 0.0
        return max(self.latencies) * 1000

    @property
    def p50_latency(self) -> float:
        """Calculate 50th percentile latency in milliseconds."""
        if not self.latencies:
            return 0.0
        return statistics.median(self.latencies) * 1000

    @property
    def p95_latency(self) -> float:
        """Calculate 95th percentile latency in milliseconds."""
        if not self.latencies:
            return 0.0
        sorted_latencies = sorted(self.latencies)
        index = int(len(sorted_latencies) * 0.95)
        return sorted_latencies[min(index, len(sorted_latencies) - 1)] * 1000

    @property
    def p99_latency(self) -> float:
        """Calculate 99th percentile latency in milliseconds."""
        if not self.latencies:
            return 0.0
        sorted_latencies = sorted(self.latencies)
        index = int(len(sorted_latencies) * 0.99)
        return sorted_latencies[min(index, len(sorted_latencies) - 1)] * 1000

    def __str__(self) -> str:
        """Format results as a string."""
        return f"""py3signer Benchmark
===================
URL: {self._url or "N/A"}
Concurrency: {self._concurrency or "N/A"}
Total Requests: {self.total_requests}

Results:
  Total Time: {self.total_time:.2f}s
  Signatures/sec: {self.signatures_per_second:.1f}
  Avg Latency: {self.avg_latency:.1f}ms
  P50: {self.p50_latency:.0f}ms
  P95: {self.p95_latency:.0f}ms
  P99: {self.p99_latency:.0f}ms
  Errors: {self.failed_requests} ({self.error_rate:.1f}%)
"""


# Sample EIP-2335 keystore for testing (from tests/data/test_keystore_scrypt.json)
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

# Fork info for signing requests
FORK_INFO = {
    "fork": {
        "previous_version": "0x00000000",
        "current_version": "0x00000000",
        "epoch": "0",
    },
    "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
}


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Benchmark py3signer signature throughput",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic benchmark with defaults
  python scripts/benchmark.py

  # Custom URL and concurrency
  python scripts/benchmark.py --url http://localhost:9000 --concurrency 20

  # With authentication
  python scripts/benchmark.py --auth-token mysecrettoken

  # Custom request count
  python scripts/benchmark.py --requests 5000 --concurrency 50

  # Auto-import keystores from path
  python scripts/benchmark.py --key-store-path ./keystores
        """,
    )

    parser.add_argument(
        "--url",
        type=str,
        default="http://localhost:8080",
        help="Server URL (default: http://localhost:8080)",
    )

    parser.add_argument(
        "--concurrency",
        type=int,
        default=10,
        help="Number of concurrent requests (default: 10)",
    )

    parser.add_argument(
        "--requests",
        type=int,
        default=1000,
        help="Total number of requests to send (default: 1000)",
    )

    parser.add_argument(
        "--key-store-path",
        type=str,
        default=None,
        help="Path to keystores for auto-loading (optional)",
    )

    parser.add_argument(
        "--auth-token",
        type=str,
        default=None,
        help="Auth token if server requires authentication",
    )

    parser.add_argument(
        "--pubkey",
        type=str,
        default=None,
        help="Public key to use for signing (default: use test keystore)",
    )

    return parser.parse_args()


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
                        return cast(str, SAMPLE_KEYSTORE["pubkey"])
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


async def load_keystores_from_path(
    session: aiohttp.ClientSession, base_url: str, key_store_path: str, auth_token: str | None
) -> list[str]:
    """Load keystores from a directory path."""
    headers = {"Content-Type": "application/json"}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    pubkeys: list[str] = []
    keystore_path = Path(key_store_path)

    if not keystore_path.exists():
        print(f"Keystore path does not exist: {key_store_path}")
        return pubkeys

    # Find all keystore JSON files
    keystore_files = list(keystore_path.glob("**/keystore-*.json"))
    keystore_files.extend(keystore_path.glob("**/*keystore*.json"))

    if not keystore_files:
        print(f"No keystore files found in: {key_store_path}")
        return pubkeys

    print(f"Found {len(keystore_files)} keystore files")

    # Look for password files
    password_files = list(keystore_path.glob("**/*.txt"))
    password_files.extend(keystore_path.glob("**/password*"))
    password_map = {}

    for pf in password_files:
        try:
            password = pf.read_text().strip()
            password_map[pf.stem] = password
        except Exception:
            pass

    for ks_file in keystore_files:
        try:
            keystore_data = json.loads(ks_file.read_text())

            # Try to find password
            ks_password: str | None = None
            ks_name = ks_file.stem

            # Check for password file with same name
            if ks_name in password_map:
                ks_password = password_map[ks_name]
            elif "password" in password_map:
                ks_password = password_map["password"]
            else:
                # Try common passwords
                ks_password = SAMPLE_KEYSTORE_PASSWORD

            payload = {
                "keystores": [json.dumps(keystore_data)],
                "passwords": [ks_password],
            }

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
                            pubkey = keystore_data.get("pubkey")
                            if pubkey:
                                pubkeys.append(pubkey)
                                print(f"  Loaded keystore: {pubkey[:20]}...")

        except Exception as e:
            print(f"  Failed to load {ks_file}: {e}")

    return pubkeys


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


def create_signing_request() -> dict[str, Any]:
    """Create an ATTESTATION signing request."""
    return {
        "type": "ATTESTATION",
        "fork_info": FORK_INFO,
        "signing_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
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


async def send_sign_request(
    session: aiohttp.ClientSession,
    base_url: str,
    pubkey: str,
    auth_token: str | None,
) -> tuple[bool, float]:
    """Send a single signing request and return (success, latency_seconds)."""
    headers = {"Content-Type": "application/json"}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    payload = create_signing_request()

    start_time = time.perf_counter()
    try:
        async with session.post(
            f"{base_url}/api/v1/eth2/sign/{pubkey}",
            json=payload,
            headers=headers,
        ) as response:
            end_time = time.perf_counter()
            latency = end_time - start_time

            if response.status == 200:
                return True, latency
            else:
                return False, latency
    except Exception:
        end_time = time.perf_counter()
        latency = end_time - start_time
        return False, latency


async def worker(
    session: aiohttp.ClientSession,
    base_url: str,
    pubkey: str,
    auth_token: str | None,
    request_queue: asyncio.Queue[int],
    result_queue: asyncio.Queue[tuple[bool, float]],
) -> None:
    """Worker that processes signing requests from the queue."""
    while True:
        try:
            # Get a request ID from the queue (timeout to allow checking for termination)
            _ = await asyncio.wait_for(request_queue.get(), timeout=0.1)
        except asyncio.TimeoutError:
            # Check if queue is empty and we should exit
            if request_queue.empty():
                break
            continue

        success, latency = await send_sign_request(session, base_url, pubkey, auth_token)
        await result_queue.put((success, latency))
        request_queue.task_done()


async def run_benchmark(
    base_url: str,
    pubkey: str,
    auth_token: str | None,
    concurrency: int,
    total_requests: int,
) -> BenchmarkResult:
    """Run the benchmark with specified concurrency."""
    latencies: list[float] = []
    successful = 0
    failed = 0

    # Create request and result queues
    request_queue: asyncio.Queue[int] = asyncio.Queue()
    result_queue: asyncio.Queue[tuple[bool, float]] = asyncio.Queue()

    # Fill the request queue
    for i in range(total_requests):
        await request_queue.put(i)

    # Create aiohttp session with connection pooling
    timeout = aiohttp.ClientTimeout(total=30)
    connector = aiohttp.TCPConnector(limit=concurrency * 2, limit_per_host=concurrency * 2)

    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        # Start workers
        workers = [
            asyncio.create_task(
                worker(session, base_url, pubkey, auth_token, request_queue, result_queue)
            )
            for _ in range(concurrency)
        ]

        # Start timing
        start_time = time.perf_counter()

        # Collect results
        for _ in range(total_requests):
            success, latency = await result_queue.get()
            latencies.append(latency)
            if success:
                successful += 1
            else:
                failed += 1

        # Wait for all workers to complete
        await request_queue.join()
        for w in workers:
            w.cancel()

        end_time = time.perf_counter()

    return BenchmarkResult(
        total_time=end_time - start_time,
        total_requests=total_requests,
        successful_requests=successful,
        failed_requests=failed,
        latencies=latencies,
    )


async def main() -> int:
    """Main entry point."""
    args = parse_args()

    print("=" * 50)
    print("py3signer Benchmark Tool")
    print("=" * 50)
    print()

    # Validate arguments
    if args.concurrency <= 0:
        print("Error: concurrency must be positive")
        return 1

    if args.requests <= 0:
        print("Error: requests must be positive")
        return 1

    print(f"Configuration:")
    print(f"  URL: {args.url}")
    print(f"  Concurrency: {args.concurrency}")
    print(f"  Total Requests: {args.requests}")
    print(f"  Auth Token: {'Yes' if args.auth_token else 'No'}")
    print(f"  Keystore Path: {args.key_store_path or 'None (use test keystore)'}")
    print()

    # Create a session for setup
    timeout = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        # Check server health
        print("Checking server health...")
        if not await check_server_health(session, args.url, args.auth_token):
            print("Error: Server is not healthy or not reachable")
            return 1
        print()

        # Determine which pubkey to use
        pubkey: str | None = args.pubkey

        if pubkey is None:
            # Check if server already has keys loaded
            headers = {}
            if args.auth_token:
                headers["Authorization"] = f"Bearer {args.auth_token}"

            try:
                async with session.get(
                    f"{args.url}/api/v1/eth2/publicKeys",
                    headers=headers,
                ) as response:
                    if response.status == 200:
                        keys = await response.json()
                        if keys:
                            pubkey = keys[0].replace("0x", "")
                            print(f"Using existing key: {pubkey[:20]}...")
            except Exception:
                pass

        # If no key found, try to import one
        if pubkey is None:
            if args.key_store_path:
                print("Loading keystores from path...")
                pubkeys = await load_keystores_from_path(
                    session, args.url, args.key_store_path, args.auth_token
                )
                if pubkeys:
                    pubkey = pubkeys[0]
                else:
                    print("Warning: No keystores loaded from path, using test keystore")

            if pubkey is None:
                print("Importing test keystore...")
                pubkey = await import_test_keystore(session, args.url, args.auth_token)

        if pubkey is None:
            print("Error: Failed to get a valid public key for signing")
            return 1

        print(f"Using pubkey: {pubkey[:30]}...")
        print()

    # Run the benchmark
    print("Running benchmark...")
    print()

    result = await run_benchmark(
        base_url=args.url,
        pubkey=pubkey,
        auth_token=args.auth_token,
        concurrency=args.concurrency,
        total_requests=args.requests,
    )

    # Store metadata for display
    result._url = args.url
    result._concurrency = args.concurrency

    # Print results
    print(result)

    return 0 if result.failed_requests == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("\nBenchmark interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
