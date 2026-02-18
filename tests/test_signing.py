"""Tests for signing operations."""

import pytest
from py3signer_core import SecretKey, PublicKey, Signature, sign, verify, generate_random_key

from py3signer.storage import KeyStorage
from py3signer.signer import Signer, SignerError


class TestCryptoCore:
    """Tests for the Rust crypto core."""
    
    def test_generate_random_key(self) -> None:
        """Test random key generation."""
        sk1 = generate_random_key()
        sk2 = generate_random_key()
        
        # Keys should be different
        assert sk1.to_bytes().hex() != sk2.to_bytes().hex()
    
    def test_secret_key_to_bytes(self) -> None:
        """Test secret key serialization."""
        sk = generate_random_key()
        bytes_data = sk.to_bytes()
        
        assert len(bytes_data) == 32
    
    def test_secret_key_from_bytes(self) -> None:
        """Test secret key deserialization."""
        sk1 = generate_random_key()
        bytes_data = sk1.to_bytes()
        
        sk2 = SecretKey.from_bytes(bytes_data)
        assert sk1.to_bytes().hex() == sk2.to_bytes().hex()
    
    def test_secret_key_invalid_length(self) -> None:
        """Test secret key with wrong length."""
        with pytest.raises(Exception) as exc_info:
            SecretKey.from_bytes(b"short")
        assert "32 bytes" in str(exc_info.value) or "Invalid" in str(exc_info.value)
    
    def test_public_key_from_secret(self) -> None:
        """Test deriving public key from secret key."""
        sk = generate_random_key()
        pk = sk.public_key()
        
        pk_bytes = pk.to_bytes()
        assert len(pk_bytes) == 48
    
    def test_public_key_roundtrip(self) -> None:
        """Test public key serialization roundtrip."""
        sk = generate_random_key()
        pk1 = sk.public_key()
        
        pk_bytes = pk1.to_bytes()
        pk2 = PublicKey.from_bytes(pk_bytes)
        
        assert pk1.to_bytes().hex() == pk2.to_bytes().hex()
    
    def test_sign_and_verify(self) -> None:
        """Test signing and verification."""
        sk = generate_random_key()
        pk = sk.public_key()
        
        message = b"test message"
        domain = b"\x00\x00\x00\x00"
        
        signature = sign(sk, message, domain)
        
        # Verify signature
        is_valid = verify(pk, message, signature, domain)
        assert is_valid is True
    
    def test_verify_wrong_message(self) -> None:
        """Test verification with wrong message."""
        sk = generate_random_key()
        pk = sk.public_key()
        
        message = b"test message"
        wrong_message = b"wrong message"
        domain = b"\x00\x00\x00\x00"
        
        signature = sign(sk, message, domain)
        is_valid = verify(pk, wrong_message, signature, domain)
        
        assert is_valid is False
    
    def test_verify_wrong_domain(self) -> None:
        """Test verification with wrong domain."""
        sk = generate_random_key()
        pk = sk.public_key()
        
        message = b"test message"
        domain = b"\x00\x00\x00\x00"
        wrong_domain = b"\x01\x00\x00\x00"
        
        signature = sign(sk, message, domain)
        is_valid = verify(pk, message, signature, wrong_domain)
        
        assert is_valid is False
    
    def test_signature_roundtrip(self) -> None:
        """Test signature serialization roundtrip."""
        sk = generate_random_key()
        
        message = b"test message"
        domain = b"\x00\x00\x00\x00"
        
        sig1 = sign(sk, message, domain)
        sig_bytes = sig1.to_bytes()
        
        sig2 = Signature.from_bytes(sig_bytes)
        assert sig1.to_bytes().hex() == sig2.to_bytes().hex()
    
class TestSigner:
    """Tests for the Signer class."""
    
    def test_signer_init(self, storage: KeyStorage) -> None:
        """Test signer initialization."""
        signer = Signer(storage)
        assert signer._storage == storage
    
    def test_sign_data_key_not_found(self, storage: KeyStorage) -> None:
        """Test signing with non-existent key."""
        signer = Signer(storage)
        
        with pytest.raises(SignerError) as exc_info:
            signer.sign_data("nonexistent", b"data", domain_name="beacon_attester")
        assert "not found" in str(exc_info.value).lower()
    
    @pytest.mark.parametrize("domain_name,domain_bytes,expected_error", [
        (None, None, "domain"),  # No domain provided
        ("unknown_domain", None, "unknown"),  # Unknown domain name
        (None, b"\x00\x00", "4 bytes"),  # Invalid domain length (2 bytes)
    ], ids=["no_domain", "unknown_domain", "invalid_domain_length"])
    def test_sign_data_domain_validation(self, storage: KeyStorage, domain_name, domain_bytes, expected_error) -> None:
        """Test domain validation errors."""
        signer = Signer(storage)
        
        with pytest.raises(SignerError) as exc_info:
            signer.sign_data("any", b"data", domain_name=domain_name, domain=domain_bytes)
        assert expected_error in str(exc_info.value).lower()
    
    def test_sign_data_success(self, storage: KeyStorage) -> None:
        """Test successful signing."""
        # Generate and add a key
        sk = generate_random_key()
        pk = sk.public_key()
        storage.add_key(pk, sk, path="m/12381/3600/0/0/0")
        
        signer = Signer(storage)
        
        message = b"\x00" * 32
        signature = signer.sign_data(
            pk.to_bytes().hex(),
            message,
            domain_name="beacon_attester"
        )
        
        assert signature is not None
        assert len(signature.to_bytes()) == 96
    
    def test_sign_with_custom_domain(self, storage: KeyStorage) -> None:
        """Test signing with custom domain bytes."""
        sk = generate_random_key()
        pk = sk.public_key()
        storage.add_key(pk, sk)
        
        signer = Signer(storage)
        
        custom_domain = b"\xab\xcd\xef\x01"
        message = b"\x00" * 32
        
        signature = signer.sign_data(
            pk.to_bytes().hex(),
            message,
            domain=custom_domain
        )
        
        assert signature is not None
        assert len(signature.to_bytes()) == 96


class TestSignerDomains:
    """Tests for different signing domains."""
    
    @pytest.fixture
    def signer_with_key(self, storage: KeyStorage):
        """Create a signer with a key added."""
        sk = generate_random_key()
        pk = sk.public_key()
        storage.add_key(pk, sk)
        
        signer = Signer(storage)
        return signer, pk.to_bytes().hex()
    
    @pytest.mark.parametrize("domain_method,test_data", [
        ("sign_attestation", b"\x00" * 32),
        ("sign_block", b"\x00" * 32),
        ("sign_randao", b"\x00" * 32),
        ("sign_voluntary_exit", b"\x00" * 32),
    ], ids=["attestation", "block", "randao", "voluntary_exit"])
    def test_sign_with_domain(self, signer_with_key, domain_method, test_data) -> None:
        """Test signing with different domain methods."""
        signer, pubkey = signer_with_key
        
        signature = getattr(signer, domain_method)(pubkey, test_data)
        
        assert signature is not None
        assert len(signature.to_bytes()) == 96
