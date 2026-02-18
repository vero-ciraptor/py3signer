"""Tests for keystore handling."""

import json
import pytest
from pathlib import Path
from py3signer.keystore import Keystore, KeystoreError


class TestKeystore:
    """Tests for Keystore class."""
    
    def test_from_json_valid(self, sample_keystore: dict) -> None:
        """Test loading valid keystore from JSON."""
        keystore_json = json.dumps(sample_keystore)
        ks = Keystore.from_json(keystore_json)
        
        assert ks.pubkey == sample_keystore["pubkey"]
        assert ks.uuid == sample_keystore["uuid"]
        assert ks.path == sample_keystore["path"]
    
    def test_from_json_invalid(self) -> None:
        """Test loading invalid JSON."""
        with pytest.raises(KeystoreError) as exc_info:
            Keystore.from_json("not valid json")
        assert "Invalid JSON" in str(exc_info.value)
    
    def test_missing_required_field(self) -> None:
        """Test validation of required fields."""
        incomplete: dict = {"crypto": {}, "version": 4}
        
        with pytest.raises(KeystoreError) as exc_info:
            Keystore(incomplete)
        assert "Missing required field" in str(exc_info.value)
    
    def test_invalid_crypto_structure(self) -> None:
        """Test validation of crypto structure."""
        bad_crypto: dict = {
            "crypto": {"kdf": {}},  # Missing checksum and cipher
            "pubkey": "aa" * 48,
            "path": "m/12381/3600/0/0/0",
            "uuid": "test-uuid",
            "version": 4
        }
        
        with pytest.raises(KeystoreError) as exc_info:
            Keystore(bad_crypto)
        assert "Invalid crypto structure" in str(exc_info.value)
    
    def test_description_property(self, sample_keystore: dict) -> None:
        """Test description property."""
        keystore_json = json.dumps(sample_keystore)
        ks = Keystore.from_json(keystore_json)
        
        assert ks.description == "Test keystore with scrypt KDF (N=262144)"
    
    def test_description_optional(self) -> None:
        """Test that description is optional."""
        keystore_data: dict = {
            "crypto": {
                "kdf": {
                    "function": "scrypt",
                    "params": {
                        "dklen": 32,
                        "n": 262144,
                        "p": 1,
                        "r": 8,
                        "salt": "aa" * 32
                    },
                    "message": ""
                },
                "checksum": {
                    "function": "sha256",
                    "params": {},
                    "message": "aa" * 32
                },
                "cipher": {
                    "function": "aes-256-ctr",
                    "params": {"iv": "aa" * 16},
                    "message": "aa" * 16
                }
            },
            "pubkey": "aa" * 48,
            "path": "m/12381/3600/0/0/0",
            "uuid": "test-uuid",
            "version": 4
        }
        
        ks = Keystore(keystore_data)
        assert ks.description is None


class TestKeystoreDecryption:
    """Tests for keystore decryption."""
    
    def test_decrypt_scrypt_keystore(self) -> None:
        """Test decryption of scrypt keystore with correct password."""
        keystore_path = Path(__file__).parent / "data" / "test_keystore_scrypt.json"
        ks = Keystore.from_file(keystore_path)
        
        secret_key = ks.decrypt("testpassword123")
        
        # Verify we got a valid secret key
        assert secret_key is not None
        # Verify we can get the public key
        pubkey = secret_key.public_key()
        assert pubkey is not None
        assert len(pubkey.to_bytes()) == 48
    
    def test_decrypt_pbkdf2_keystore(self) -> None:
        """Test decryption of PBKDF2 keystore with correct password."""
        keystore_path = Path(__file__).parent / "data" / "test_keystore_pbkdf2.json"
        ks = Keystore.from_file(keystore_path)
        
        secret_key = ks.decrypt("testpassword123")
        
        # Verify we got a valid secret key
        assert secret_key is not None
        # Verify we can get the public key
        pubkey = secret_key.public_key()
        assert pubkey is not None
        assert len(pubkey.to_bytes()) == 48
    
    def test_decrypt_scrypt_and_pbkdf2_same_key(self) -> None:
        """Test that both keystores decrypt to the same secret key."""
        scrypt_path = Path(__file__).parent / "data" / "test_keystore_scrypt.json"
        pbkdf2_path = Path(__file__).parent / "data" / "test_keystore_pbkdf2.json"
        
        ks_scrypt = Keystore.from_file(scrypt_path)
        ks_pbkdf2 = Keystore.from_file(pbkdf2_path)
        
        sk_scrypt = ks_scrypt.decrypt("testpassword123")
        sk_pbkdf2 = ks_pbkdf2.decrypt("testpassword123")
        
        # Both should decrypt to the same key
        assert sk_scrypt.to_bytes() == sk_pbkdf2.to_bytes()
        # And derive to the same public key
        assert sk_scrypt.public_key().to_bytes() == sk_pbkdf2.public_key().to_bytes()
    
    def test_decrypt_wrong_password_scrypt(self) -> None:
        """Test scrypt decryption with wrong password."""
        keystore_path = Path(__file__).parent / "data" / "test_keystore_scrypt.json"
        ks = Keystore.from_file(keystore_path)
        
        with pytest.raises(KeystoreError) as exc_info:
            ks.decrypt("wrongpassword")
        error_msg = str(exc_info.value).lower()
        assert "password" in error_msg or "invalid" in error_msg
    
    def test_decrypt_wrong_password_pbkdf2(self) -> None:
        """Test PBKDF2 decryption with wrong password."""
        keystore_path = Path(__file__).parent / "data" / "test_keystore_pbkdf2.json"
        ks = Keystore.from_file(keystore_path)
        
        with pytest.raises(KeystoreError) as exc_info:
            ks.decrypt("wrongpassword")
        error_msg = str(exc_info.value).lower()
        assert "password" in error_msg or "invalid" in error_msg


class TestKeystoreDecryptionLegacy:
    """Legacy tests using sample_keystore fixture."""
    
    def test_decrypt_wrong_password(self, sample_keystore: dict) -> None:
        """Test decryption with wrong password."""
        keystore_json = json.dumps(sample_keystore)
        ks = Keystore.from_json(keystore_json)
        
        with pytest.raises(KeystoreError) as exc_info:
            ks.decrypt("wrongpassword")
        error_msg = str(exc_info.value).lower()
        assert "password" in error_msg or "invalid" in error_msg
