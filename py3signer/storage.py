"""In-memory key storage."""

import logging
from dataclasses import dataclass
from typing import Dict, List, Tuple

from py3signer_core import SecretKey, PublicKey

from .metrics import KEYS_LOADED

logger = logging.getLogger(__name__)


@dataclass
class KeyPair:
    """A stored key pair."""
    pubkey: PublicKey
    secret_key: SecretKey
    path: str
    description: str | None = None


class KeyStorage:
    """In-memory storage for BLS keys."""
    
    def __init__(self) -> None:
        self._keys: dict[str, KeyPair] = {}  # pubkey_hex -> KeyPair
        self._logger = logging.getLogger(__name__)
    
    def add_key(
        self,
        pubkey: PublicKey,
        secret_key: SecretKey,
        path: str = "m/12381/3600/0/0/0",
        description: str | None = None
    ) -> str:
        """Add a key to storage. Returns the public key hex."""
        pubkey_bytes = pubkey.to_bytes()
        pubkey_hex = pubkey_bytes.hex()
        
        if pubkey_hex in self._keys:
            raise ValueError(f"Key already exists: {pubkey_hex}")
        
        self._keys[pubkey_hex] = KeyPair(
            pubkey=pubkey,
            secret_key=secret_key,
            path=path,
            description=description
        )
        
        # Update metrics
        KEYS_LOADED.set(len(self._keys))
        
        self._logger.info(f"Added key: {pubkey_hex[:20]}...")
        return pubkey_hex
    
    def get_key(self, pubkey_hex: str) -> KeyPair | None:
        """Get a key pair by public key hex."""
        return self._keys.get(pubkey_hex)
    
    def list_keys(self) -> list[tuple[str, str, str | None]]:
        """List all stored keys. Returns list of (pubkey_hex, path, description)."""
        return [
            (pubkey_hex, kp.path, kp.description)
            for pubkey_hex, kp in self._keys.items()
        ]
    
    def remove_key(self, pubkey_hex: str) -> bool:
        """Remove a key from storage. Returns True if key was found and removed."""
        if pubkey_hex in self._keys:
            del self._keys[pubkey_hex]
            # Update metrics
            KEYS_LOADED.set(len(self._keys))
            self._logger.info(f"Removed key: {pubkey_hex[:20]}...")
            return True
        return False
    
    def get_secret_key(self, pubkey_hex: str) -> SecretKey | None:
        """Get the secret key for a given public key."""
        kp = self._keys.get(pubkey_hex)
        return kp.secret_key if kp else None
    
    def __len__(self) -> int:
        return len(self._keys)
    
    def clear(self) -> None:
        """Clear all keys (useful for testing)."""
        self._keys.clear()
        KEYS_LOADED.set(0)
