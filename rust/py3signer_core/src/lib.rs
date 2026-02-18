use blst::min_pk::{PublicKey, SecretKey, Signature as BlstSignature};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Domain separation for BLS signatures (8 bytes)
fn hash_to_g2(message: &[u8], domain: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(message);
    hasher.finalize().into()
}

/// `PyO3` wrapper for BLS `SecretKey`
#[pyclass(name = "SecretKey", from_py_object)]
#[derive(Clone)]
pub struct PySecretKey {
    inner: Arc<SecretKey>,
}

#[pymethods]
impl PySecretKey {
    /// Create a `SecretKey` from 32 bytes
    #[staticmethod]
    fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        if bytes.len() != 32 {
            return Err(PyValueError::new_err(format!(
                "SecretKey must be 32 bytes, got {}",
                bytes.len()
            )));
        }

        let key_bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| PyValueError::new_err("Invalid byte length"))?;

        let sk = SecretKey::from_bytes(&key_bytes)
            .map_err(|e| PyValueError::new_err(format!("Invalid secret key: {e:?}")))?;

        Ok(PySecretKey {
            inner: Arc::new(sk),
        })
    }

    /// Serialize to 32 bytes
    #[allow(clippy::unnecessary_wraps)]
    fn to_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, pyo3::types::PyBytes>> {
        let bytes = self.inner.to_bytes();
        Ok(pyo3::types::PyBytes::new(py, &bytes))
    }

    /// Get the corresponding public key
    #[allow(clippy::unnecessary_wraps)]
    fn public_key(&self) -> PyResult<PyPublicKey> {
        Ok(PyPublicKey {
            inner: self.inner.sk_to_pk(),
        })
    }
}

/// `PyO3` wrapper for BLS `PublicKey`
#[pyclass(name = "PublicKey", from_py_object)]
#[derive(Clone)]
pub struct PyPublicKey {
    inner: PublicKey,
}

#[pymethods]
impl PyPublicKey {
    /// Create a `PublicKey` from 48 bytes (compressed)
    #[staticmethod]
    fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        if bytes.len() != 48 {
            return Err(PyValueError::new_err(format!(
                "PublicKey must be 48 bytes, got {}",
                bytes.len()
            )));
        }

        let pk = PublicKey::from_bytes(bytes)
            .map_err(|e| PyValueError::new_err(format!("Invalid public key: {e:?}")))?;

        Ok(PyPublicKey { inner: pk })
    }

    /// Serialize to 48 bytes (compressed G1 point)
    #[allow(clippy::unnecessary_wraps)]
    fn to_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, pyo3::types::PyBytes>> {
        // For min_sig, public keys are G1 points: 48 bytes compressed
        let bytes = self.inner.compress();
        Ok(pyo3::types::PyBytes::new(py, &bytes))
    }
}

/// `PyO3` wrapper for BLS `Signature`
#[pyclass(name = "Signature", from_py_object)]
#[derive(Clone)]
pub struct PySignature {
    inner: BlstSignature,
}

#[pymethods]
impl PySignature {
    /// Create a `Signature` from 96 bytes (compressed)
    #[staticmethod]
    fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        if bytes.len() != 96 {
            return Err(PyValueError::new_err(format!(
                "Signature must be 96 bytes, got {}",
                bytes.len()
            )));
        }

        let sig = BlstSignature::from_bytes(bytes)
            .map_err(|e| PyValueError::new_err(format!("Invalid signature: {e:?}")))?;

        Ok(PySignature { inner: sig })
    }

    /// Serialize to 96 bytes (compressed G2 point)
    #[allow(clippy::unnecessary_wraps)]
    fn to_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, pyo3::types::PyBytes>> {
        // For min_sig, signatures are G2 points: 96 bytes compressed
        let bytes = self.inner.compress();
        Ok(pyo3::types::PyBytes::new(py, &bytes))
    }
}

/// Sign a message with a secret key and domain
/// Releases the GIL during the BLS signing operation for better concurrency
#[pyfunction]
#[allow(clippy::unnecessary_wraps)]
fn sign(
    py: Python,
    secret_key: &PySecretKey,
    message: &[u8],
    domain: &[u8],
) -> PyResult<PySignature> {
    let hash = hash_to_g2(message, domain);

    // Clone the Arc to move it into the closure
    let sk = Arc::clone(&secret_key.inner);

    // Release the GIL during the BLS signing operation
    let signature = py.detach(move || {
        // blst::min_sig::SecretKey::sign returns Signature directly (not Result)
        sk.sign(&hash, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_", &[])
    });

    Ok(PySignature { inner: signature })
}

/// Verify a signature
/// Releases the GIL during the BLS verification operation for better concurrency
#[pyfunction]
fn verify(
    py: Python,
    public_key: &PyPublicKey,
    message: &[u8],
    signature: &PySignature,
    domain: &[u8],
) -> bool {
    let hash = hash_to_g2(message, domain);

    // Copy the inner values to move them into the closure
    let pk = public_key.inner;
    let sig = signature.inner;

    // Release the GIL during the BLS verification operation
    let result = py.detach(move || {
        // Correct API for min_pk: verify(sig_groupcheck, msg, dst, aug, pk, pk_validate)
        sig.verify(
            true,                                           // sig_groupcheck
            &hash,                                          // msg (already hashed)
            b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_", // dst
            &[],                                            // aug
            &pk,                                            // pk
            true,                                           // pk_validate
        )
    });

    matches!(result, blst::BLST_ERROR::BLST_SUCCESS)
}

/// Generate a random secret key (for testing)
/// Uses rejection sampling to ensure a valid BLS scalar
#[pyfunction]
fn generate_random_key(py: Python) -> PyResult<PySecretKey> {
    use pyo3::types::PyBytes;

    // Get random bytes from Python's secrets module
    let secrets = py.import("secrets")?;
    let token_bytes = secrets.getattr("token_bytes")?;

    // BLS12-381 scalar field order is slightly less than 2^255
    // We'll use rejection sampling: generate random bytes, check if valid
    for _ in 0..100 {
        // Limit iterations to prevent infinite loop
        let random_bytes: Bound<PyBytes> = token_bytes.call1((32,))?.extract()?;
        let bytes: &[u8] = random_bytes.as_bytes();

        // Try to create a secret key - it will fail if bytes >= curve order
        if let Ok(sk) = SecretKey::from_bytes(bytes) {
            return Ok(PySecretKey {
                inner: Arc::new(sk),
            });
        }
    }

    Err(PyRuntimeError::new_err(
        "Failed to generate valid random key after 100 attempts",
    ))
}

/// EIP-2335 Keystore handling
mod keystore {
    use super::{PyResult, PyRuntimeError, PyValueError};
    use aes::cipher::{KeyIvInit, StreamCipher};
    use serde::{Deserialize, Serialize};
    use sha3::{Digest as Sha3Digest, Keccak256};

    type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Keystore {
        pub crypto: Crypto,
        pub description: Option<String>,
        pub pubkey: String,
        pub path: String,
        pub uuid: String,
        pub version: u32,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Crypto {
        pub kdf: Kdf,
        pub checksum: Checksum,
        pub cipher: Cipher,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Kdf {
        pub function: String,
        pub params: KdfParams,
        pub message: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(untagged)]
    pub enum KdfParams {
        Scrypt {
            n: u32,
            r: u32,
            p: u32,
            dklen: u32,
            salt: String,
        },
        Pbkdf2 {
            c: u32,
            dklen: u32,
            prf: String,
            salt: String,
        },
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Checksum {
        pub function: String,
        pub params: serde_json::Value,
        pub message: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Cipher {
        pub function: String,
        pub params: CipherParams,
        pub message: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct CipherParams {
        pub iv: String,
    }

    /// Decrypt an EIP-2335 keystore
    pub fn decrypt_keystore(keystore_json: &str, password: &str) -> PyResult<Vec<u8>> {
        let keystore: Keystore = serde_json::from_str(keystore_json)
            .map_err(|e| PyValueError::new_err(format!("Invalid keystore JSON: {e}")))?;

        // Decode salt and ciphertext
        let salt = hex::decode(match &keystore.crypto.kdf.params {
            KdfParams::Scrypt { salt, .. } | KdfParams::Pbkdf2 { salt, .. } => salt,
        })
        .map_err(|e| PyValueError::new_err(format!("Invalid salt: {e}")))?;

        let ciphertext = hex::decode(&keystore.crypto.cipher.message)
            .map_err(|e| PyValueError::new_err(format!("Invalid ciphertext: {e}")))?;

        let iv = hex::decode(&keystore.crypto.cipher.params.iv)
            .map_err(|e| PyValueError::new_err(format!("Invalid IV: {e}")))?;

        // Derive key using specified KDF
        let mut key = vec![0u8; 32];
        match &keystore.crypto.kdf.params {
            KdfParams::Scrypt { n, r, p, dklen, .. } => {
                // Convert n to log2(n) for scrypt params
                // Note: n is always a power of 2 for valid keystores, so log2 is exact
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let log_n = f64::from(*n).log2() as u8;
                let params = scrypt::Params::new(log_n, *r, *p, *dklen as usize)
                    .map_err(|e| PyRuntimeError::new_err(format!("Invalid scrypt params: {e}")))?;

                scrypt::scrypt(password.as_bytes(), &salt, &params, &mut key)
                    .map_err(|e| PyRuntimeError::new_err(format!("Scrypt failed: {e}")))?;
            }
            KdfParams::Pbkdf2 { c, dklen, .. } => {
                pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), &salt, *c, &mut key);
                if *dklen as usize != key.len() {
                    key.truncate(*dklen as usize);
                }
            }
        }

        // Verify checksum (version-dependent)
        let expected_checksum = hex::decode(&keystore.crypto.checksum.message)
            .map_err(|e| PyValueError::new_err(format!("Invalid checksum hex: {e}")))?;

        let checksum_valid = match keystore.version {
            4 => {
                // Version 4 uses SHA-256 for checksum
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(&key[16..32]);
                hasher.update(&ciphertext);
                hasher.finalize().as_slice() == expected_checksum.as_slice()
            }
            _ => {
                // Version 3 uses Keccak-256 for checksum
                let mut hasher = Keccak256::new();
                hasher.update(&key[16..32]);
                hasher.update(&ciphertext);
                hasher.finalize().as_slice() == expected_checksum.as_slice()
            }
        };

        if !checksum_valid {
            return Err(PyValueError::new_err(
                "Invalid password - checksum mismatch",
            ));
        }

        // Decrypt
        let mut cipher = Aes256Ctr::new_from_slices(&key[0..32], &iv)
            .map_err(|e| PyRuntimeError::new_err(format!("Cipher init failed: {e}")))?;

        let mut plaintext = ciphertext.clone();
        cipher.apply_keystream(&mut plaintext);

        Ok(plaintext)
    }
}

/// Decrypt an EIP-2335 keystore and return the secret key bytes
/// Releases the GIL during the KDF and decryption operations for better concurrency
#[pyfunction]
fn decrypt_keystore(py: Python, keystore_json: &str, password: &str) -> PyResult<Vec<u8>> {
    // Clone the inputs to move them into the closure
    let keystore_json = keystore_json.to_string();
    let password = password.to_string();

    // Release the GIL during the expensive KDF and decryption operations
    py.detach(move || keystore::decrypt_keystore(&keystore_json, &password))
}

/// Module initialization
#[pymodule]
fn py3signer_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PySecretKey>()?;
    m.add_class::<PyPublicKey>()?;
    m.add_class::<PySignature>()?;
    m.add_wrapped(wrap_pyfunction!(sign))?;
    m.add_wrapped(wrap_pyfunction!(verify))?;
    m.add_wrapped(wrap_pyfunction!(generate_random_key))?;
    m.add_wrapped(wrap_pyfunction!(decrypt_keystore))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_roundtrip() {
        // Generate a test key (32 bytes)
        let key_bytes = [1u8; 32];
        let sk = PySecretKey::from_bytes(&key_bytes).unwrap();
        // Just test that it doesn't panic
        assert!(sk.public_key().is_ok());
    }

    #[test]
    fn test_public_key_from_secret() {
        let key_bytes = [1u8; 32];
        let sk = PySecretKey::from_bytes(&key_bytes).unwrap();
        let pk = sk.public_key().unwrap();
        // Public key should be valid
        let _ = pk.inner.to_bytes();
    }

    #[test]
    fn test_invalid_key_length() {
        let key_bytes = [1u8; 31]; // Wrong length
        let result = PySecretKey::from_bytes(&key_bytes);
        assert!(result.is_err());
    }
}
