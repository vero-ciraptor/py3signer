"""Type stubs for py3signer_core Rust extension module.

This module provides BLS signature functionality and EIP-2335 keystore handling.
"""

class SecretKey:
    """BLS12-381 secret key for signing operations."""

    @staticmethod
    def from_bytes(data: bytes) -> SecretKey:
        """Create a SecretKey from 32 bytes.

        Args:
            data: 32 bytes representing the secret key

        Returns:
            A new SecretKey instance

        Raises:
            ValueError: If data is not exactly 32 bytes or invalid

        """

    def to_bytes(self) -> bytes:
        """Serialize the secret key to 32 bytes.

        Returns:
            32 bytes representing the secret key

        """

    def public_key(self) -> PublicKey:
        """Get the corresponding public key.

        Returns:
            The PublicKey derived from this secret key

        """

    def sign(self, message: bytes, domain: bytes) -> Signature:
        """Sign a message with this secret key.

        Args:
            message: The message to sign
            domain: Domain separation bytes (8 bytes for BLS signatures)

        Returns:
            The BLS signature

        """

class PublicKey:
    """BLS12-381 public key for verification operations."""

    @staticmethod
    def from_bytes(data: bytes) -> PublicKey:
        """Create a PublicKey from 48 bytes (compressed G1 point).

        Args:
            data: 48 bytes representing the compressed public key

        Returns:
            A new PublicKey instance

        Raises:
            ValueError: If data is not exactly 48 bytes or invalid

        """

    def to_bytes(self) -> bytes:
        """Serialize the public key to 48 bytes (compressed G1 point).

        Returns:
            48 bytes representing the compressed public key

        """

class Signature:
    """BLS12-381 signature."""

    @staticmethod
    def from_bytes(data: bytes) -> Signature:
        """Create a Signature from 96 bytes (compressed G2 point).

        Args:
            data: 96 bytes representing the compressed signature

        Returns:
            A new Signature instance

        Raises:
            ValueError: If data is not exactly 96 bytes or invalid

        """

    def to_bytes(self) -> bytes:
        """Serialize the signature to 96 bytes (compressed G2 point).

        Returns:
            96 bytes representing the compressed signature

        """

def sign(secret_key: SecretKey, message: bytes, domain: bytes) -> Signature:
    """Sign a message with a secret key and domain.

    This function releases the GIL during the BLS signing operation
    for better concurrency.

    Args:
        secret_key: The secret key to sign with
        message: The message to sign
        domain: Domain separation bytes (8 bytes for BLS signatures)

    Returns:
        The BLS signature

    """

def verify(
    public_key: PublicKey,
    message: bytes,
    signature: Signature,
    domain: bytes,
) -> bool:
    """Verify a BLS signature.

    This function releases the GIL during the BLS verification operation
    for better concurrency.

    Args:
        public_key: The public key to verify against
        message: The message that was signed
        signature: The signature to verify
        domain: Domain separation bytes used during signing

    Returns:
        True if the signature is valid, False otherwise

    """

def generate_random_key() -> SecretKey:
    """Generate a random secret key (for testing).

    Uses rejection sampling to ensure a valid BLS scalar.

    Returns:
        A randomly generated SecretKey

    Raises:
        RuntimeError: If failed to generate a valid key after 100 attempts

    """

def decrypt_keystore(keystore_json: str, password: str) -> bytes:
    """Decrypt an EIP-2335 keystore and return the secret key bytes.

    This function releases the GIL during the KDF and decryption operations
    for better concurrency.

    Args:
        keystore_json: The EIP-2335 keystore JSON string
        password: The password to decrypt the keystore

    Returns:
        The decrypted secret key bytes

    Raises:
        ValueError: If the keystore JSON is invalid, password is incorrect,
                    or decryption fails

    """
