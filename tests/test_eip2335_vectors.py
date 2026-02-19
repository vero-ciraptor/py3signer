"""Test against official EIP-2335 test vectors.

These tests verify compliance with the official EIP-2335 specification
test vectors from https://eips.ethereum.org/EIPS/eip-2335
"""

from typing import Any

import pytest

from py3signer.keystore import Keystore, KeystoreError, normalize_password

# Official EIP-2335 Scrypt Test Vector
# Password: "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑"
# Encoded Password: 0x7465737470617373776f7264f09f9491
# Secret: 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
EIP2335_SCRYPT_KEYSTORE: dict[str, Any] = {
    "crypto": {
        "kdf": {
            "function": "scrypt",
            "params": {
                "dklen": 32,
                "n": 262144,
                "p": 1,
                "r": 8,
                "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
            },
            "message": "",
        },
        "checksum": {
            "function": "sha256",
            "params": {},
            "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484",
        },
        "cipher": {
            "function": "aes-128-ctr",
            "params": {"iv": "264daa3f303d7259501c93d997d84fe6"},
            "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f",
        },
    },
    "description": "This is a test keystore that uses scrypt to secure the secret.",
    "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
    "path": "m/12381/60/3141592653/589793238",
    "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
    "version": 4,
}

# Official EIP-2335 PBKDF2 Test Vector
# Password: "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑"
# Encoded Password: 0x7465737470617373776f7264f09f9491
# Secret: 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
EIP2335_PBKDF2_KEYSTORE: dict[str, Any] = {
    "crypto": {
        "kdf": {
            "function": "pbkdf2",
            "params": {
                "dklen": 32,
                "c": 262144,
                "prf": "hmac-sha256",
                "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
            },
            "message": "",
        },
        "checksum": {
            "function": "sha256",
            "params": {},
            "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1",
        },
        "cipher": {
            "function": "aes-128-ctr",
            "params": {"iv": "264daa3f303d7259501c93d997d84fe6"},
            "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad",
        },
    },
    "description": "This is a test keystore that uses PBKDF2 to secure the secret.",
    "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
    "path": "m/12381/60/0/0",
    "uuid": "64625def-3331-4eea-ab6f-782f3ed16a83",
    "version": 4,
}

# Password with unicode characters (NFKD normalized and control codes stripped)
EIP2335_PASSWORD = "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑"  # noqa: RUF001

# Expected secret
EIP2335_SECRET = bytes.fromhex(
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
)


class TestEIP2335OfficialVectors:
    """Tests using official EIP-2335 test vectors."""

    def test_scrypt_official_vector(self) -> None:
        """Test decryption of official EIP-2335 scrypt test vector."""
        keystore = Keystore(**EIP2335_SCRYPT_KEYSTORE)
        secret_key = keystore.decrypt(EIP2335_PASSWORD)

        # Verify secret matches expected
        assert secret_key.to_bytes() == EIP2335_SECRET

        # Verify public key matches
        pubkey = secret_key.public_key()
        expected_pubkey = bytes.fromhex(
            "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27"
            "f4ae4040902382ae2910c15e2b420d07",
        )
        assert pubkey.to_bytes() == expected_pubkey

    def test_pbkdf2_official_vector(self) -> None:
        """Test decryption of official EIP-2335 PBKDF2 test vector."""
        keystore = Keystore(**EIP2335_PBKDF2_KEYSTORE)
        secret_key = keystore.decrypt(EIP2335_PASSWORD)

        # Verify secret matches expected
        assert secret_key.to_bytes() == EIP2335_SECRET

        # Verify public key matches
        pubkey = secret_key.public_key()
        expected_pubkey = bytes.fromhex(
            "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27"
            "f4ae4040902382ae2910c15e2b420d07",
        )
        assert pubkey.to_bytes() == expected_pubkey

    def test_keystore_structure_validation(self) -> None:
        """Test that official test vectors have valid structure."""
        ks_scrypt = Keystore(**EIP2335_SCRYPT_KEYSTORE)
        assert ks_scrypt.version == 4
        assert ks_scrypt.crypto["kdf"]["function"] == "scrypt"
        assert ks_scrypt.crypto["checksum"]["function"] == "sha256"
        assert ks_scrypt.crypto["cipher"]["function"] == "aes-128-ctr"

        ks_pbkdf2 = Keystore(**EIP2335_PBKDF2_KEYSTORE)
        assert ks_pbkdf2.version == 4
        assert ks_pbkdf2.crypto["kdf"]["function"] == "pbkdf2"
        assert ks_pbkdf2.crypto["checksum"]["function"] == "sha256"
        assert ks_pbkdf2.crypto["cipher"]["function"] == "aes-128-ctr"


class TestPasswordNormalization:
    """Tests for EIP-2335 password normalization."""

    def test_nfkd_normalization(self) -> None:
        """Test NFKD normalization of passwords."""
        # Mathematical bold letters normalize to regular ASCII
        password = "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑"
        normalized = normalize_password(password)

        # Should normalize to "testpassword🔑"
        assert normalized == "testpassword🔑"
        assert normalized.encode() == bytes.fromhex("7465737470617373776f7264f09f9491")

    def test_control_codes_stripped(self) -> None:
        """Test that control codes are stripped from passwords."""
        # Password with control codes (C0: 0x00-0x1F, DEL: 0x7F, C1: 0x80-0x9F)
        password = "test\x00pass\x1fword\x7f\x80\x9f"
        normalized = normalize_password(password)

        # Control codes should be stripped
        assert normalized == "testpassword"

    def test_space_preserved(self) -> None:
        """Test that space character is preserved (it's not a control code)."""
        password = "test password"
        normalized = normalize_password(password)

        # Space should be preserved
        assert normalized == "test password"

    def test_plain_password_unchanged(self) -> None:
        """Test that plain ASCII passwords without control codes pass through."""
        password = "simplepassword123"
        normalized = normalize_password(password)

        assert normalized == password


class TestCipherSupport:
    """Tests for cipher support (both aes-128-ctr and aes-256-ctr)."""

    def test_aes_128_ctr_support(self) -> None:
        """Test that aes-128-ctr cipher is supported."""
        keystore = Keystore(**EIP2335_SCRYPT_KEYSTORE)
        assert keystore.crypto["cipher"]["function"] == "aes-128-ctr"

        # Should decrypt successfully
        secret = keystore.decrypt(EIP2335_PASSWORD)
        assert secret.to_bytes() == EIP2335_SECRET

    def test_aes_256_ctr_support(self, sample_keystore: Any) -> None:
        """Test that aes-256-ctr cipher is supported (extended support)."""
        from py3signer.keystore import Keystore

        keystore = Keystore(**sample_keystore)
        # Our test keystores use aes-256-ctr as an extension
        assert keystore.crypto["cipher"]["function"] == "aes-256-ctr"

        # Should decrypt successfully
        secret = keystore.decrypt("testpassword123")
        assert secret is not None

    def test_unsupported_cipher_rejected(self) -> None:
        """Test that unsupported ciphers are rejected."""
        keystore_data: dict[str, Any] = EIP2335_SCRYPT_KEYSTORE.copy()
        keystore_data["crypto"] = dict(keystore_data["crypto"])
        keystore_data["crypto"]["cipher"] = {
            "function": "aes-256-gcm",  # Unsupported
            "params": {"iv": "264daa3f303d7259501c93d997d84fe6"},
            "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f",
        }

        keystore = Keystore(**keystore_data)

        with pytest.raises(KeystoreError) as exc_info:
            keystore.decrypt(EIP2335_PASSWORD)
        assert (
            "unsupported" in str(exc_info.value).lower()
            or "cipher" in str(exc_info.value).lower()
        )


class TestKDFSupport:
    """Tests for KDF support (scrypt and PBKDF2)."""

    def test_scrypt_kdf_params(self) -> None:
        """Test that scrypt KDF parameters are correctly parsed."""
        kdf = EIP2335_SCRYPT_KEYSTORE["crypto"]["kdf"]
        assert kdf["function"] == "scrypt"
        assert kdf["params"]["n"] == 262144
        assert kdf["params"]["r"] == 8
        assert kdf["params"]["p"] == 1
        assert kdf["params"]["dklen"] == 32

    def test_pbkdf2_kdf_params(self) -> None:
        """Test that PBKDF2 KDF parameters are correctly parsed."""
        kdf = EIP2335_PBKDF2_KEYSTORE["crypto"]["kdf"]
        assert kdf["function"] == "pbkdf2"
        assert kdf["params"]["c"] == 262144
        assert kdf["params"]["prf"] == "hmac-sha256"
        assert kdf["params"]["dklen"] == 32


class TestChecksumVerification:
    """Tests for checksum verification."""

    def test_checksum_failure_wrong_password(self) -> None:
        """Test that wrong password fails checksum verification."""
        keystore = Keystore(**EIP2335_SCRYPT_KEYSTORE)

        with pytest.raises(KeystoreError) as exc_info:
            keystore.decrypt("wrongpassword")
        assert "password" in str(exc_info.value).lower()

    def test_checksum_failure_modified_ciphertext(self) -> None:
        """Test that modified ciphertext fails checksum verification."""
        keystore_data: dict[str, Any] = EIP2335_SCRYPT_KEYSTORE.copy()
        keystore_data["crypto"] = dict(keystore_data["crypto"])
        keystore_data["crypto"]["cipher"] = dict(keystore_data["crypto"]["cipher"])
        # Modify the last byte of ciphertext
        original_msg = keystore_data["crypto"]["cipher"]["message"]
        modified_msg = original_msg[:-2] + "00"
        keystore_data["crypto"]["cipher"]["message"] = modified_msg

        keystore = Keystore(**keystore_data)

        with pytest.raises(KeystoreError) as exc_info:
            keystore.decrypt(EIP2335_PASSWORD)
        assert (
            "password" in str(exc_info.value).lower()
            or "checksum" in str(exc_info.value).lower()
        )


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_password(self) -> None:
        """Test that empty password is handled (checksum will fail)."""
        # Create a keystore with modified checksum for empty password test
        # This will fail checksum since original was encrypted with non-empty password
        keystore = Keystore(**EIP2335_SCRYPT_KEYSTORE)

        with pytest.raises(KeystoreError) as exc_info:
            keystore.decrypt("")
        assert "password" in str(exc_info.value).lower()

    def test_unicode_password_with_emoji(self) -> None:
        """Test password with emoji and unicode characters."""
        # The EIP2335 password already includes emoji
        keystore = Keystore(**EIP2335_SCRYPT_KEYSTORE)
        secret = keystore.decrypt(EIP2335_PASSWORD)
        assert secret.to_bytes() == EIP2335_SECRET

    def test_special_characters_password(self) -> None:
        """Test password normalization with special characters."""
        # Test various special unicode characters
        password = "парольñø密码🔐"  # Mix of scripts
        normalized = normalize_password(password)
        # Each script should normalize appropriately
        assert isinstance(normalized, str)
        # Control codes should be stripped
        assert "\x00" not in normalized
