# py3signer Code Review Report

**Date:** 2026-02-20
**Reviewer:** Security Audit Subagent
**Scope:** Full codebase review - Python and Rust components

---

## Executive Summary

py3signer is a Remote BLS Signer for Ethereum Consensus Layer implementing the Keymanager API. It uses a hybrid Python/Rust architecture where:
- **Python Layer (Litestar/Granian)**: HTTP server, request routing, business logic
- **Rust Layer (PyO3/blst)**: High-performance BLS signing and keystore decryption

The codebase is generally well-structured with proper separation of concerns, good test coverage, and follows modern Python/Rust practices. However, several security issues ranging from **Medium** to **Low** severity were identified.

---

## Codebase Overview

### Main Components

| Component | Purpose | Lines |
|-----------|---------|-------|
| `py3signer/server.py` | Litestar app factory, DI setup | 200 |
| `py3signer/handlers.py` | HTTP route handlers (Keymanager API) | 450 |
| `py3signer/storage.py` | In-memory key storage with disk persistence | 350 |
| `py3signer/signer.py` | BLS signing orchestration | 70 |
| `py3signer/keystore.py` | EIP-2335 keystore parsing/decryption | 110 |
| `py3signer/signing_types.py` | Ethereum signing request types | 350 |
| `py3signer/config.py` | Configuration management | 170 |
| `py3signer/metrics.py` | Prometheus metrics | 200 |
| `py3signer/bulk_loader.py` | Bulk keystore loading | 200 |
| `py3signer/path_utils.py` | File path utilities | 110 |
| `py3signer/asgi.py` | ASGI entry point for workers | 90 |
| `rust/py3signer_core/src/lib.rs` | Rust BLS/crypto implementation | 350 |

### Key Features
- EIP-2335 Keystore support (scrypt and PBKDF2 KDFs)
- Keymanager API compatibility (Web3Signer/Lighthouse)
- In-memory key storage with optional disk persistence
- Multi-process support with Granian
- Prometheus metrics
- Docker support with non-root user

---

## Security Issues

### 🔴 CRITICAL: None Found

No critical vulnerabilities were identified that would allow immediate compromise of signing keys or unauthorized signing.

### 🟠 HIGH: None Found

No high-severity issues found.

### 🟡 MEDIUM Severity Issues

#### 1. **No Authentication Mechanism** (MEDIUM)
**Location:** `py3signer/handlers.py`, `py3signer/server.py`

**Issue:** The application lacks any authentication mechanism for the Keymanager API. Anyone with network access to the server can:
- List all loaded public keys
- Import new keystores (if they know the password)
- Delete keystores
- Sign arbitrary data with any loaded key

**Code Evidence:**
```python
# handlers.py - No auth checks in any controller
class SigningController(Controller):
    @post("/sign/{identifier:str}")  # No auth decorator
    async def sign(self, request: Request, identifier: str, signer: Signer):
        # Signs without verifying requester identity
```

**Impact:** In a production environment, this could allow unauthorized signing operations if the network is compromised.

**Recommendation:**
- Implement API key/bearer token authentication
- Add TLS client certificate authentication option
- Document that the service should ONLY be accessible via localhost or through a secure reverse proxy

---

#### 2. **Timing Side-Channel in Keystore Decryption** (MEDIUM)
**Location:** `py3signer/keystore.py`, `rust/py3signer_core/src/lib.rs`

**Issue:** The keystore decryption uses different code paths for checksum validation failure vs decryption failure, potentially leaking information via timing.

**Code Evidence (Rust):**
```rust
// decrypt_keystore function
let checksum_valid = hasher.finalize().as_slice() == expected_checksum.as_slice();

if !checksum_valid {
    return Err(PyValueError::new_err(
        "Invalid password - checksum mismatch",  // Early return
    ));
}
// Continue to decryption...
```

**Impact:** An attacker with precise timing measurements could potentially distinguish between "wrong password" and "corrupted keystore".

**Recommendation:**
- Ensure constant-time comparison for checksum validation
- Add random delay to error responses to mask timing differences

---

#### 3. **Password Stored in Memory as Plain String** (MEDIUM)
**Location:** `py3signer/models.py`, `py3signer/storage.py`

**Issue:** Keystore passwords are stored as plain Python strings in memory (`KeystoreLoadResult.password`). Python strings are immutable and may persist in memory longer than necessary.

**Code Evidence:**
```python
# models.py
@dataclass(frozen=True, slots=True)
class KeystoreLoadResult:
    # ...
    password: str  # Stored as plain string
```

**Impact:** Passwords may remain in memory longer than necessary and could be exposed in core dumps or memory dumps.

**Recommendation:**
- Use `bytearray` for sensitive data (mutable, can be zeroed)
- Implement explicit memory clearing after use
- Consider using `secrets` module patterns for sensitive data

---

#### 4. **Missing Input Size Limits** (MEDIUM)
**Location:** `py3signer/handlers.py`

**Issue:** HTTP request bodies are not size-limited, potentially allowing DoS via large payloads.

**Code Evidence:**
```python
# handlers.py
async def _parse_sign_request(request: Request) -> SignRequest:
    body_bytes = await request.body()  # No size limit
    return cast("SignRequest", sign_request_decoder.decode(body_bytes))
```

**Impact:** An attacker could send very large requests to exhaust server memory.

**Recommendation:**
- Add maximum request body size limits in Litestar configuration
- Limit keystore import batch sizes

---

### 🟢 LOW Severity Issues

#### 5. **Weak Password File Permissions Not Enforced** (LOW)
**Location:** `py3signer/storage.py`

**Issue:** When persisting keystores and passwords to disk, file permissions are not explicitly set to restrict access.

**Code Evidence:**
```python
# storage.py - _save_to_managed_storage
keystore_temp.rename(keystore_file)
password_temp.rename(password_file)
# No chmod/permissions set
```

**Recommendation:**
- Set restrictive permissions (0o600) on password files
- Set permissions (0o644 or 0o600) on keystore files
- Verify permissions on read operations

---

#### 6. **Temp File Cleanup Race Condition** (LOW)
**Location:** `py3signer/storage.py`

**Issue:** Temporary file cleanup in exception handlers could fail silently.

**Code Evidence:**
```python
except Exception as e:
    for temp in (keystore_temp, password_temp):
        if temp:
            with suppress(OSError):
                temp.unlink()  # Could fail, temp file remains
```

**Recommendation:**
- Use `tempfile.NamedTemporaryFile` with `delete=True` in a context manager
- Or use atomic write libraries like `atomicwrites`

---

#### 7. **Information Leakage in Error Messages** (LOW)
**Location:** `py3signer/handlers.py`, `py3signer/keystore.py`

**Issue:** Some error messages may leak internal implementation details.

**Code Evidence:**
```python
# handlers.py
except Exception as e:
    logger.exception("Unexpected error importing keystore")
    return KeystoreImportResult(
        status="error",
        message=f"Internal error: {e}",  # May leak internal details
    )
```

**Recommendation:**
- Return generic error messages to clients
- Log detailed errors server-side only

---

#### 8. **No Rate Limiting on Signing Endpoint** (LOW)
**Location:** `py3signer/handlers.py`

**Issue:** The signing endpoint has no rate limiting, allowing potential DoS or brute force attempts.

**Recommendation:**
- Implement rate limiting per public key
- Add global rate limiting
- Consider implementing slashing protection (acknowledged as not implemented by design)

---

#### 9. **Potential Log Injection** (LOW)
**Location:** Multiple files

**Issue:** User-controlled data is logged without sanitization.

**Code Evidence:**
```python
# handlers.py
logger.info(f"Loaded managed keystore: {base_name}")  # User-controlled base_name
```

**Recommendation:**
- Sanitize logged data (remove newlines, control characters)
- Use structured logging with proper escaping

---

#### 10. **Dockerfile: Hadolint Warnings Ignored** (LOW)
**Location:** `Dockerfile`

**Issue:** Hadolint warnings are suppressed without justification comments.

**Code Evidence:**
```dockerfile
# hadolint ignore=DL3033
RUN yum install -y \
    openssl-devel \
    pkgconfig \
    && yum clean all
```

**Recommendation:**
- Add justification comments for each ignored warning
- Consider using hadolint configuration file instead of inline ignores

---

## Code Quality Improvements

### 1. **Type Safety Enhancements**

**Current:**
```python
def _clean_pubkey_hex(pubkey_hex: str) -> str:
    return pubkey_hex.removeprefix("0x").lower()
```

**Issue:** No validation that the input is actually a valid hex string.

**Recommendation:**
```python
def _clean_pubkey_hex(pubkey_hex: str) -> PubkeyHex:
    cleaned = pubkey_hex.removeprefix("0x").lower()
    if len(cleaned) != 64 or not all(c in '0123456789abcdef' for c in cleaned):
        raise ValueError(f"Invalid pubkey format: {pubkey_hex}")
    return PubkeyHex(cleaned)
```

---

### 2. **Documentation Gaps**

**Missing Documentation:**
- No API documentation (OpenAPI/Swagger not configured in Litestar)
- Missing docstrings for several public methods
- No architecture decision records (ADRs)

**Recommendation:**
- Enable Litestar's OpenAPI plugin
- Add comprehensive docstrings
- Document security considerations

---

### 3. **Test Coverage Gaps**

**Areas Needing More Coverage:**
- Error handling paths in `storage.py`
- Concurrent access scenarios
- Malformed input handling
- Metrics functionality

**Current Coverage:** ~85% (based on .coverage file)

---

### 4. **Refactoring Opportunities**

#### 4.1 **Duplicate Keystore Loading Logic**
**Files:** `py3signer/bulk_loader.py`, `py3signer/server.py`

Both files contain similar keystore loading logic that could be consolidated.

#### 4.2 **Large Handler File**
**File:** `py3signer/handlers.py` (450 lines)

Could be split into separate controllers per domain:
- `controllers/health.py`
- `controllers/keystores.py`
- `controllers/signing.py`

#### 4.3 **Configuration Validation**
**File:** `py3signer/config.py`

`__post_init__` method is very long. Consider extracting validators:
```python
@validator
def validate_port(self) -> None:
    if self.port < 1 or self.port > 65535:
        raise ValueError(...)
```

---

### 5. **Dependency Management**

**Observations:**
- `requirements.txt` and `requirements-dev.txt` are auto-generated from `uv.lock`
- Good: Uses `uv` for reproducible builds
- Good: Docker uses specific image tags

**Recommendation:**
- Consider adding dependency vulnerability scanning (e.g., `pip-audit`, `cargo-audit`)
- Pin exact versions in `Cargo.toml` for Rust dependencies

---

### 6. **Error Handling Patterns**

**Inconsistent Pattern:**
```python
# Some places catch generic Exception
except Exception as e:
    logger.exception("Error")

# Other places catch specific exceptions
except KeystoreError as e:
    logger.error(f"Keystore error: {e}")
```

**Recommendation:**
- Define custom exception hierarchy
- Use exception chaining consistently
- Document expected exceptions for each public function

---

## Cryptographic Review

### BLS Implementation (Rust)

**Good Practices:**
- Uses well-audited `blst` library
- Proper domain separation tag (BLS_DST)
- GIL released during crypto operations
- Constant-time operations where appropriate

**Observations:**
- Uses `min_pk` mode (public keys on G1, signatures on G2) - correct for Ethereum
- Signature verification available but not exposed in Python API
- Key generation uses rejection sampling with iteration limit (good)

### EIP-2335 Implementation

**Good Practices:**
- Supports both scrypt and PBKDF2
- Proper password normalization (NFKD)
- Version validation before expensive operations
- Uses stack-allocated arrays where possible

**Potential Improvements:**
- Consider adding memory locking for sensitive data
- Add constant-time comparison for checksum validation

---

## Deployment Security

### Docker Configuration

**Good Practices:**
- Multi-stage build reduces attack surface
- Non-root user (`py3signer`)
- Uses official base images
- Health check configured

**Recommendations:**
- Add `read_only: true` for root filesystem
- Add `security_opt: ["no-new-privileges:true"]`
- Consider using distroless base for runtime
- Add resource limits (CPU/memory)

### Configuration

**Observations:**
- Defaults to localhost binding (secure default)
- No TLS/HTTPS support implemented
- No authentication tokens

---

## Recommendations Summary

### Priority 1 (High Priority)
1. **Implement authentication mechanism** - API keys or client certificates
2. **Add request size limits** - Prevent DoS via large payloads
3. **Review timing side-channels** - Constant-time operations for crypto

### Priority 2 (Medium Priority)
4. **Implement proper file permissions** - 0o600 for sensitive files
5. **Add rate limiting** - Prevent abuse of signing endpoints
6. **Sanitize log output** - Prevent log injection
7. **Improve password memory handling** - Use mutable buffers, clear after use

### Priority 3 (Low Priority)
8. **Improve error handling** - Consistent patterns, less information leakage
9. **Refactor large files** - Split handlers.py
10. **Add dependency scanning** - Automated vulnerability checks
11. **Harden Docker configuration** - Read-only root, security options

---

## Positive Security Observations

1. **Secure Defaults:** Defaults to localhost binding
2. **No Secrets in Code:** No hardcoded credentials found
3. **Good Architecture:** Clean separation between Python and Rust layers
4. **Memory Safety:** Rust layer provides memory safety for crypto operations
5. **Test Coverage:** Good test coverage with security-focused tests
6. **Code Quality:** Uses modern tools (ruff, mypy, clippy)
7. **Documentation:** Clear warning about lack of slashing protection

---

## Conclusion

The py3signer codebase demonstrates good engineering practices with a clean architecture separating cryptographic operations (Rust) from business logic (Python). The use of well-audited libraries (`blst`, `pyo3`, `msgspec`) and modern Python/Rust tooling reduces the attack surface.

The main security concerns are:
1. **Lack of authentication** - This is the most significant issue
2. **Potential timing side-channels** - Should be addressed for defense in depth
3. **Password handling** - Could be improved with secure memory practices

With the recommended improvements implemented, this codebase would be suitable for production use in a properly secured network environment.

---

*End of Report*
