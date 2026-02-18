"""Signing orchestration."""

import logging
import time

from py3signer_core import sign, SecretKey, Signature

from .storage import KeyStorage
from .metrics import SIGNING_REQUESTS_TOTAL, SIGNING_DURATION_SECONDS, SIGNING_ERRORS_TOTAL

logger = logging.getLogger(__name__)


class SignerError(Exception):
    """Error during signing operation."""
    pass


class Signer:
    """Handles BLS signing operations."""
    
    def __init__(self, storage: KeyStorage) -> None:
        self._storage = storage
        self._logger = logging.getLogger(__name__)
    
    def sign_data(
        self,
        pubkey_hex: str,
        data: bytes,
        domain: bytes,
    ) -> Signature:
        """
        Sign data with the specified key.
        
        Args:
            pubkey_hex: The public key hex identifier
            data: The data to sign
            domain: The 4-byte domain
        
        Returns:
            The BLS signature
        
        Raises:
            SignerError: If key not found or signing fails
        """
        if len(domain) != 4:
            raise SignerError(f"Domain must be 4 bytes, got {len(domain)}")
        
        # Track signing request
        SIGNING_REQUESTS_TOTAL.labels(key_type="bls").inc()
        
        start_time = time.perf_counter()
        
        # Get the secret key
        secret_key = self._storage.get_secret_key(pubkey_hex)
        if secret_key is None:
            SIGNING_ERRORS_TOTAL.labels(error_type="key_not_found").inc()
            raise SignerError(f"Key not found: {pubkey_hex}")
        
        try:
            signature = sign(secret_key, data, domain)
            duration = time.perf_counter() - start_time
            SIGNING_DURATION_SECONDS.labels(key_type="bls").observe(duration)
            self._logger.debug(f"Signed data with key: {pubkey_hex[:20]}...")
            return signature
        except Exception as e:
            SIGNING_ERRORS_TOTAL.labels(error_type="signing_failed").inc()
            raise SignerError(f"Signing failed: {e}")
