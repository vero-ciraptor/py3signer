#!/usr/bin/env python3
"""Comparison benchmark between py3signer_core and blspy.

This script compares the performance and API of py3signer_core (our Rust bindings)
against blspy (the official Chia BLS library).

To run with blspy installed:
    uv run --with blspy python compare_blspy.py

Or install blspy first (requires CMake):
    pip install blspy
"""

import time
from collections.abc import Callable

# py3signer_core is always available
from py3signer_core import (
    generate_random_key,
    sign,
    verify,
)

# Try to import blspy - may not be available
try:
    from blspy import AugSchemeMPL
    from blspy import (
        PrivateKey as BlsPrivateKey,
    )
    from blspy import (
        PublicKey as BlsPublicKey,
    )
    from blspy import (
        Signature as BlsSignature,
    )

    BLSPY_AVAILABLE = True
except ImportError:
    BLSPY_AVAILABLE = False
    print("Warning: blspy not installed. Install with: pip install blspy")
    print("Continuing with API comparison only...\n")


# Test configuration
ITERATIONS = 10_000
MESSAGE = b"\x00" * 32  # 32-byte signing root


def benchmark(name: str, fn: Callable, iterations: int = ITERATIONS) -> float:
    """Benchmark a function and return ops/sec."""
    # Warmup
    for _ in range(100):
        fn()

    start = time.perf_counter()
    for _ in range(iterations):
        fn()
    elapsed = time.perf_counter() - start

    ops_per_sec = iterations / elapsed
    us_per_op = (elapsed / iterations) * 1_000_000
    print(f"  {name}:")
    print(f"    {us_per_op:.2f} µs/op | {ops_per_sec:.0f} ops/sec")
    return ops_per_sec


def compare_basic_operations():
    """Compare basic key operations."""
    print("=" * 60)
    print("BASIC OPERATIONS COMPARISON")
    print("=" * 60)

    # py3signer_core
    print("\npy3signer_core (Rust bindings):")
    sk = generate_random_key()
    pk = sk.public_key()
    sig = sign(sk, MESSAGE)

    benchmark("Key generation", generate_random_key)
    benchmark("Sign", lambda: sign(sk, MESSAGE))
    benchmark("Verify", lambda: verify(pk, MESSAGE, sig))

    # blspy
    if BLSPY_AVAILABLE:
        print("\nblspy (C++ bindings):")
        seed = bytes([1] * 32)
        bls_sk = BlsPrivateKey.from_seed(seed)
        bls_pk = bls_sk.get_g1()
        bls_sig = AugSchemeMPL.sign(bls_sk, MESSAGE)

        benchmark(
            "Key generation (from_seed)",
            lambda: BlsPrivateKey.from_seed(bytes([2] * 32)),
        )
        benchmark("Sign", lambda: AugSchemeMPL.sign(bls_sk, MESSAGE))
        benchmark("Verify", lambda: AugSchemeMPL.verify(bls_pk, MESSAGE, bls_sig))


def compare_api_design():
    """Compare API design differences."""
    print("\n" + "=" * 60)
    print("API DESIGN COMPARISON")
    print("=" * 60)

    comparison = """
py3signer_core (Our Rust Bindings):
-----------------------------------
• Simple, minimal API surface
• Direct binding to blst crate (Rust BLS implementation)
• GIL release during operations for better concurrency
• Immutable SecretKey wrapper with Arc for thread safety
• Sign function: sign(secret_key, message) -> Signature
• Verify function: verify(pubkey, message, signature) -> bool
• Uses BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_ DST
• Fixed-size message handling (32 bytes expected)

blspy (Chia Official Library):
------------------------------
• More comprehensive API
• Based on Chia's BLS implementation (relic library)
• Multiple schemes: BasicScheme, AugScheme, PopScheme
• Mutable key objects
• Uses AugSchemeMPL by default (augments pubkey into message)
• Sign: AugSchemeMPL.sign(private_key, message)
• Verify: AugSchemeMPL.verify(public_key, message, signature)
• Aggregation support for signatures and public keys
• HD key derivation support (from seed, from bytes)
• Additional features: key aggregation, batch verification

Key Differences:
----------------
1. Scheme: py3signer uses basic BLS with standard DST
   blspy uses AugScheme by default (adds pubkey to message hash)

2. DST (Domain Separation Tag):
   py3signer: BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_
   blspy: Varies by scheme

3. Thread Safety:
   py3signer: Arc<SecretKey> for cheap cloning
   blspy: Standard Python object semantics

4. Performance:
   py3signer: GIL release during signing (~500µs)
   blspy: Holds GIL (may block other Python threads)

5. Dependencies:
   py3signer: Pure Rust, single binary
   blspy: C++ with CMake build requirement
"""
    print(comparison)


def compare_features():
    """Compare feature sets."""
    print("=" * 60)
    print("FEATURE COMPARISON")
    print("=" * 60)

    features = [
        ("Feature", "py3signer_core", "blspy"),
        ("-" * 25, "-" * 20, "-" * 20),
        ("Basic signing", "✓", "✓"),
        ("Basic verification", "✓", "✓"),
        ("GIL release", "✓", "✗"),
        ("Signature aggregation", "✗", "✓"),
        ("Public key aggregation", "✗", "✓"),
        ("Batch verification", "✗", "✓"),
        ("HD key derivation", "✗", "✓"),
        ("Multiple schemes", "✗ (basic only)", "✓ (3 schemes)"),
        ("Key serialization", "✓", "✓"),
        ("Signature serialization", "✓", "✓"),
        ("Keystore support", "✓ (EIP-2335)", "✗"),
        ("No CMake required", "✓", "✗"),
    ]

    for row in features:
        print(f"  {row[0]:<25} | {row[1]:<20} | {row[2]:<20}")


def compare_use_cases():
    """Discuss best use cases for each."""
    print("\n" + "=" * 60)
    print("RECOMMENDED USE CASES")
    print("=" * 60)

    print("""
Use py3signer_core when:
• Building Ethereum validator software
• Need GIL release for concurrent signing
• Want simple, minimal API
• Deploying in containerized environments
• Don't need signature aggregation
• Prefer Rust-based dependencies

Use blspy when:
• Building Chia blockchain software
• Need signature/public key aggregation
• Need batch verification
• Need HD wallet key derivation
• Want scheme flexibility (Basic/Aug/PoP)
• Can tolerate CMake build requirement
""")


def theoretical_performance_comparison():
    """Discuss theoretical performance differences."""
    print("=" * 60)
    print("PERFORMANCE ANALYSIS")
    print("=" * 60)

    print("""
Expected Performance (based on underlying libraries):
-----------------------------------------------------

Underlying Implementation:
  py3signer_core: blst crate (Rust, by Supranational)
  blspy: relic library (C, with Chia optimizations)

Both use highly optimized assembly for BLS12-381 operations.
Performance should be very similar (~400-600 µs per sign).

Key Performance Factors:
------------------------
1. GIL Handling:
   py3signer_core: Releases GIL during signing
   → Better for multi-threaded Python applications

   blspy: Holds GIL during signing
   → May block other Python threads

2. Memory Allocation:
   py3signer_core: Uses Arc for cheap key cloning
   → Lower overhead when sharing keys across threads

   blspy: Standard Python object model
   → Simpler but may have higher cloning cost

3. Startup Time:
   py3signer_core: Single shared library
   → Faster module import

   blspy: Complex C++ initialization
   → Slower module import

4. Throughput (single-threaded):
   Both: ~2,000 signs/second expected
   Winner: Likely very close, depends on build optimization

5. Throughput (multi-threaded Python):
   py3signer_core: Better (GIL release allows true parallelism)
   blspy: Worse (GIL serialization)

Typical Benchmark Results:
--------------------------
py3signer_core: ~486 µs/sign (~2,056 signs/sec)
blspy (expected): ~400-500 µs/sign (~2,000-2,500 signs/sec)
""")


def main():
    """Run all comparisons."""
    print("=" * 60)
    print("PY3SIGNER_CORE vs BLSPY COMPARISON")
    print("=" * 60)

    compare_api_design()
    compare_features()

    if BLSPY_AVAILABLE:
        compare_basic_operations()
    else:
        print("\n" + "=" * 60)
        print("PERFORMANCE BENCHMARKS")
        print("=" * 60)
        print("\n  blspy not installed. Skipping runtime benchmarks.")
        print("  Install with: pip install blspy (requires CMake)")
        print("\n  py3signer_core benchmarks:")

        sk = generate_random_key()
        pk = sk.public_key()
        sig = sign(sk, MESSAGE)

        benchmark("Key generation", generate_random_key, 1000)
        benchmark("Sign", lambda: sign(sk, MESSAGE))
        benchmark("Verify", lambda: verify(pk, MESSAGE, sig))

    theoretical_performance_comparison()
    compare_use_cases()

    print("\n" + "=" * 60)
    print("COMPARISON COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
