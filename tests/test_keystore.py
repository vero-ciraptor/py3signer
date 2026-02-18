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
        
        assert ks.description == "Test keystore"
    
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
                    "function": "aes-128-ctr",
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
    
    def test_decrypt_wrong_password(self, sample_keystore: dict) -> None:
        """Test decryption with wrong password."""
        keystore_json = json.dumps(sample_keystore)
        ks = Keystore.from_json(keystore_json)
        
        with pytest.raises(KeystoreError) as exc_info:
            ks.decrypt("wrongpassword")
        error_msg = str(exc_info.value).lower()
        assert "password" in error_msg or "invalid" in error_msg
