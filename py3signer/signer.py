"""Signing orchestration."""

import logging

from py3signer_core import sign, SecretKey, Signature

from .storage import KeyStorage

logger = logging.getLogger(__name__)


class SignerError(Exception):
    """Error during signing operation."""
    pass


class Signer:
    """Handles BLS signing operations."""
    
    # Standard Ethereum 2.0 domains
    DOMAINS: dict[str, bytes] = {
        "beacon_proposer": bytes.fromhex("00000000"),
        "beacon_attester": bytes.fromhex("01000000"),
        "randao": bytes.fromhex("02000000"),
        "deposit": bytes.fromhex("03000000"),
        "voluntary_exit": bytes.fromhex("04000000"),
        "selection_proof": bytes.fromhex("05000000"),
        "aggregate_and_proof": bytes.fromhex("06000000"),
        "sync_committee": bytes.fromhex("07000000"),
        "sync_committee_selection_proof": bytes.fromhex("08000000"),
        "contribution_and_proof": bytes.fromhex("09000000"),
        "application_mask": bytes.fromhex("0a000000"),
    }
    
    def __init__(self, storage: KeyStorage) -> None:
        self._storage = storage
        self._logger = logging.getLogger(__name__)
    
    def sign_data(
        self,
        pubkey_hex: str,
        data: bytes,
        domain: bytes | None = None,
        domain_name: str | None = None
    ) -> Signature:
        """
        Sign data with the specified key.
        
        Args:
            pubkey_hex: The public key hex identifier
            data: The data to sign
            domain: The 4-byte domain (overrides domain_name)
            domain_name: Named domain from DOMAINS dict
        
        Returns:
            The BLS signature
        
        Raises:
            SignerError: If key not found or signing fails
        """
        # Get the secret key
        secret_key = self._storage.get_secret_key(pubkey_hex)
        if secret_key is None:
            raise SignerError(f"Key not found: {pubkey_hex}")
        
        # Determine domain
        if domain is None:
            if domain_name is None:
                raise SignerError("Either domain or domain_name must be provided")
            domain = self.DOMAINS.get(domain_name)
            if domain is None:
                raise SignerError(f"Unknown domain: {domain_name}")
        
        if len(domain) != 4:
            raise SignerError(f"Domain must be 4 bytes, got {len(domain)}")
        
        try:
            signature = sign(secret_key, data, domain)
            self._logger.debug(f"Signed data with key: {pubkey_hex[:20]}...")
            return signature
        except Exception as e:
            raise SignerError(f"Signing failed: {e}")
    
    def sign_attestation(
        self,
        pubkey_hex: str,
        attestation_data: bytes
    ) -> Signature:
        """Sign an attestation."""
        return self.sign_data(
            pubkey_hex,
            attestation_data,
            domain_name="beacon_attester"
        )
    
    def sign_block(
        self,
        pubkey_hex: str,
        block_data: bytes
    ) -> Signature:
        """Sign a beacon block."""
        return self.sign_data(
            pubkey_hex,
            block_data,
            domain_name="beacon_proposer"
        )
    
    def sign_randao(
        self,
        pubkey_hex: str,
        epoch: bytes
    ) -> Signature:
        """Sign a RANDAO reveal."""
        return self.sign_data(
            pubkey_hex,
            epoch,
            domain_name="randao"
        )
    
    def sign_voluntary_exit(
        self,
        pubkey_hex: str,
        exit_data: bytes
    ) -> Signature:
        """Sign a voluntary exit."""
        return self.sign_data(
            pubkey_hex,
            exit_data,
            domain_name="voluntary_exit"
        )
