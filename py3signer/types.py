"""Type definitions for py3signer.

This module contains type aliases and NewType definitions for domain-specific
types to improve type safety and code readability.
"""

from typing import NewType

# Domain-specific type aliases for type safety
PubkeyHex = NewType("PubkeyHex", str)
"""Hex-encoded public key (64 characters, without 0x prefix)."""

SignatureHex = NewType("SignatureHex", str)
"""Hex-encoded BLS signature (192 characters, without 0x prefix)."""

SigningRootHex = NewType("SigningRootHex", str)
"""Hex-encoded signing root (64 characters, without 0x prefix)."""

DomainHex = NewType("DomainHex", str)
"""Hex-encoded 4-byte domain (8 characters)."""
