# Architecture

py3signer uses a hybrid Python/Rust architecture to combine Python's developer productivity with Rust's cryptographic performance.

!!! danger "Experimental Software"

    This architecture is part of experimental software not suitable for production validators.

## Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Client Request                                  │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │ HTTP
                                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Python Layer (Litestar)                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Router    │→ │  Handlers   │→ │   Signer    │→ │ Dependency Injection│ │
│  │             │  │  (Keystores,│  │             │  │ (Storage, Signer)   │ │
│  │             │  │  Signing)   │  │             │  │                     │ │
│  └─────────────┘  └─────────────┘  └──────┬──────┘  └─────────────────────┘ │
│                                           │                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌──────┴──────┐  ┌─────────────────────┐ │
│  │   Storage   │  │   Metrics   │  │   Config    │  │   Bulk Loader       │ │
│  │  (In-Mem)   │  │ (Prometheus)│  │  (msgspec)  │  │   (Startup)         │ │
│  └──────┬──────┘  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────┼───────────────────────────────────────────────────────────────────┘
          │ PyO3 FFI
          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Rust Layer (PyO3)                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                           blst Library                                   │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────────┐ │ │
│  │  │ SecretKey   │  │ PublicKey   │  │  Signature  │  │    Verify      │ │ │
│  │  │             │  │             │  │             │  │  Aggregate     │ │ │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └────────────────┘ │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Python Layer

The Python layer handles HTTP requests, business logic, and orchestration. It uses [Litestar](https://litestar.dev/){:target="_blank"}, a modern, high-performance ASGI framework.

### Components

#### HTTP Server (Litestar + Granian)

```python
# Simplified architecture
Granian (HTTP server) → Litestar (ASGI app) → Routers → Controllers
```

- **Granian**: High-performance Rust-based HTTP server
- **Litestar**: ASGI framework with dependency injection and structured routing
- **Multi-worker**: Supports multiple processes for concurrent request handling

#### Controllers

py3signer organizes endpoints into controllers:

| Controller | Path | Purpose |
|------------|------|---------|
| `LocalKeyManagerController` | `/eth/v1/keystores` | Key import/list/delete |
| `SigningController` | `/api/v1/eth2` | Signing operations |
| `HealthController` | `/health` | Health checks |
| `MetricsController` | `/metrics` | Prometheus metrics |

Example controller structure:

```python
class SigningController(Controller):
    path = "/api/v1/eth2"

    @get("/publicKeys")
    async def list_public_keys(self, storage: KeyStorage) -> list[str]:
        # Handler implementation
        pass

    @post("/sign/{identifier:str}")
    async def sign(self, request: Request, identifier: str, signer: Signer):
        # Handler implementation
        pass
```

#### Dependency Injection

Litestar's DI system provides clean access to shared resources:

```python
def provide_storage(state: State) -> KeyStorage:
    return state["storage"]

def provide_signer(state: State) -> Signer:
    return state["signer"]

# In handlers
async def handler(self, storage: KeyStorage, signer: Signer):
    # Dependencies are automatically injected
    pass
```

#### Key Storage

The `KeyStorage` class manages validator keys in memory:

```python
class KeyStorage:
    def add_key(self, pubkey, secret_key, ...)
    def remove_key(self, pubkey_hex)
    def list_keys(self) -> list[KeyInfo]
    def get_key(self, pubkey_hex) -> SecretKey
```

Features:

- **In-memory only**: Keys never touch disk decrypted
- **Managed keystores**: Persist encrypted keystores to disk
- **External keystores**: Load from external paths without copying
- **Thread-safe**: Uses locks for concurrent access

#### Signer

The `Signer` class orchestrates signing operations:

```python
class Signer:
    def sign_data(self, pubkey_hex, data, domain) -> Signature:
        # 1. Retrieve secret key from storage
        # 2. Call Rust layer via PyO3
        # 3. Return signature
        pass
```

Signing flow:

1. Validate signing root
2. Determine BLS domain from request type
3. Call Rust `sign_message` function
4. Return hex-encoded signature

#### Configuration

Uses [msgspec](https://jcristharif.com/msgspec/){:target="_blank"} for fast, type-safe configuration:

```python
class Config(msgspec.Struct, frozen=True):
    host: str = "127.0.0.1"
    port: int = 8080
    log_level: str = "INFO"
    # ... validation in __post_init__
```

Benefits:

- **Type validation**: Automatic type checking
- **Performance**: Faster than dataclasses/pydantic
- **Immutability**: `frozen=True` prevents accidental mutation

#### Metrics

Prometheus metrics using `prometheus_client`:

- `py3signer_sign_requests_total` – Signing request count
- `py3signer_sign_errors_total` – Error count
- `py3signer_keys_loaded` – Current key count
- HTTP request latency histograms

Multi-process support via `PROMETHEUS_MULTIPROC_DIR`.

## Rust Layer

The Rust layer provides high-performance BLS operations via [PyO3](https://pyo3.rs/){:target="_blank"} bindings.

### PyO3 Extension

The `py3signer_core` module exposes Rust types to Python:

```rust
#[pymodule]
fn py3signer_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PySecretKey>()?;
    m.add_class::<PyPublicKey>()?;
    m.add_class::<PySignature>()?;
    m.add_function(wrap_pyfunction!(sign_message, m)?)?;
    m.add_function(wrap_pyfunction!(verify_signature, m)?)?;
    Ok(())
}
```

### BLS Operations (blst)

Uses [blst](https://github.com/supranational/blst){:target="_blank"}, a highly optimized BLS12-381 library:

| Operation | Description |
|-----------|-------------|
| `SecretKey::from_bytes` | Deserialize 32-byte secret key |
| `SecretKey::sign` | Sign message with domain |
| `PublicKey::from_bytes` | Deserialize 48-byte public key |
| `Signature::verify` | Verify signature |
| `AggregateSignature::aggregate` | Aggregate multiple signatures |

### Signing Flow

```
Python: sign_request()
    → Extract secret key from storage
    → Call Rust: sign_message(secret_key_bytes, message, domain)
Rust:   Deserialize SecretKey
    → Sign message with BLS_DST domain
    → Return Signature bytes
Python: Wrap in response
```

### Domain Separation

Ethereum BLS uses domain separation for different message types:

```rust
const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

fn sign_message(sk: &PySecretKey, msg: &[u8], domain: u32) -> PyResult<PySignature> {
    let domain_bytes = domain.to_be_bytes();
    let mut full_msg = Vec::with_capacity(msg.len() + 4);
    full_msg.extend_from_slice(msg);
    full_msg.extend_from_slice(&domain_bytes);

    let sig = sk.inner.sign(&full_msg, BLS_DST, &[]);
    Ok(PySignature { inner: sig })
}
```

## Data Flow

### Startup Sequence

```
1. Parse CLI arguments → Config
2. Create KeyStorage
3. Load managed keystores from data_dir/keystores/
4. Load external keystores from --keystores-path
5. Create Signer with storage
6. Create Litestar app with DI providers
7. Start Granian server with N workers
8. Start Prometheus metrics server
```

### Signing Request Flow

```
1. HTTP POST /api/v1/eth2/sign/{pubkey}
2. Litestar routes to SigningController.sign()
3. Parse and validate SignRequest
4. DI injects KeyStorage and Signer
5. Signer retrieves SecretKey from storage
6. Signer calls Rust: sign_message()
7. Rust blst operation
8. Return signature to Python
9. Return JSON response
```

### Key Import Flow

```
1. HTTP POST /eth/v1/keystores
2. Validate request (keystores + passwords)
3. For each keystore:
   a. Decrypt with password (scrypt/PBKDF2)
   b. Extract secret key
   c. Derive public key
   d. Add to KeyStorage
   e. Persist encrypted keystore (if managed)
4. Return import results
```

## Security Model

### Threat Model

py3signer is designed for experimentation, not production. It assumes:

- **Trusted network**: No authentication on API endpoints
- **Trusted operator**: No multi-sig or threshold schemes
- **Single instance**: No distributed consensus

### Key Security

| Aspect | Implementation |
|--------|----------------|
| Storage | In-memory only (RAM) |
| Encryption | At rest (EIP-2335 scrypt/PBKDF2) |
| Access | No access controls beyond network binding |
| Persistence | Encrypted keystores only |

### Network Security

- **Default binding**: `127.0.0.1` (localhost only)
- **No TLS**: Use reverse proxy (nginx, Caddy) for TLS termination
- **No auth**: Implement at reverse proxy layer if needed

## Performance Characteristics

### Benchmarks

Approximate performance on modern hardware:

| Operation | Latency | Throughput |
|-----------|---------|------------|
| Single sign | ~1-2ms | ~500-1000 signs/sec/core |
| Key import | ~100-500ms | Depends on scrypt iterations |
| List keys | <1ms | - |

### Scaling

- **Vertical**: Increase `--workers` to use more CPU cores
- **Horizontal**: Run multiple instances (⚠️ **dangerous without proper key distribution**)

## Minimal Dependencies

py3signer intentionally maintains a lean dependency tree:

### Python Runtime (4 dependencies)

| Dependency | Purpose | Why It Was Chosen |
|------------|---------|-------------------|
| [Litestar](https://litestar.dev/){:target="_blank"} | ASGI web framework | Modern, fast, excellent DI system, msgspec-native |
| [Granian](https://github.com/emmett-framework/granian){:target="_blank"} | HTTP server | Rust-based, high performance, minimal overhead |
| [msgspec](https://jcristharif.com/msgspec/){:target="_blank"} | Serialization/validation | Faster than pydantic, smaller footprint, JSON/MsgPack support |
| [prometheus-client](https://github.com/prometheus/client_python){:target="_blank"} | Metrics | Standard Prometheus instrumentation |

No ORM, no database drivers, no caching layer, no message queue clients. Just what's needed for an HTTP signer.

### Rust (8 dependencies)

| Dependency | Purpose |
|------------|---------|
| [blst](https://github.com/supranational/blst){:target="_blank"} | BLS12-381 cryptography |
| [pyo3](https://pyo3.rs/){:target="_blank"} | Python FFI bindings |
| [scrypt](https://docs.rs/scrypt/){:target="_blank"} | Keystore KDF (EIP-2335) |
| [aes](https://docs.rs/aes/){:target="_blank"} | Keystore encryption |
| [ctr](https://docs.rs/ctr/){:target="_blank"} | Counter mode for AES |
| [pbkdf2](https://docs.rs/pbkdf2/){:target="_blank"} | Alternative KDF |
| [sha2](https://docs.rs/sha2/){:target="_blank"} | SHA-256 hashing |
| [hex](https://docs.rs/hex/){:target="_blank"} | Hex encoding/decoding |

All Rust dependencies are focused on cryptography and FFI—no networking, no async runtime, no serialization frameworks.

### Why Minimal Dependencies Matter

1. **Security surface** – Fewer dependencies = fewer potential vulnerabilities
2. **Build times** – Faster compilation and smaller binaries
3. **Auditability** – Can review all dependencies in a reasonable timeframe
4. **Maintenance** – Less version churn, fewer breaking changes
5. **Comprehension** – New contributors can understand the full stack quickly

## Trade-offs

### Python/Rust Split

| Aspect | Python | Rust |
|--------|--------|------|
| HTTP handling | ✅ Litestar | ❌ Would be complex |
| Business logic | ✅ Easy to modify | ❌ Slower iteration |
| BLS operations | ❌ Slow (pure Python) | ✅ Fast (blst) |
| FFI overhead | Minor | Acceptable for batch ops |

### In-Memory Storage

| Pros | Cons |
|------|------|
| Simple, no DB dependencies | Lost on restart |
| Fast access | No persistence of signing history |
| No disk I/O for signing | Memory-limited key capacity |

## Future Considerations

Potential improvements (not implemented):

- **Slashing protection database**: Persistent signing history
- **Threshold signatures**: Distributed key generation
- **HSM support**: Hardware security module integration
- **gRPC API**: Binary protocol for lower latency
- **Authentication**: API key or TLS client cert auth

## Code Organization

```
py3signer/
├── __init__.py
├── __main__.py          # Entry point
├── cli.py               # CLI argument parsing
├── config.py            # Configuration (msgspec)
├── server.py            # Litestar + Granian setup
├── asgi.py              # ASGI app factory
├── storage.py           # KeyStorage implementation
├── signer.py            # Signer orchestration
├── keystore.py          # EIP-2335 keystore handling
├── bulk_loader.py       # Startup key loading
├── signing_types.py     # Request type definitions
├── models.py            # Data models
├── path_utils.py        # Path validation
├── metrics.py           # Prometheus metrics
└── handlers/            # HTTP route handlers
    ├── __init__.py
    ├── base.py          # Shared handler utilities
    ├── keystores.py     # Keymanager API
    └── signing.py       # Signing API

rust/
└── py3signer_core/
    ├── Cargo.toml
    └── src/
        └── lib.rs       # PyO3 extension with blst bindings
```
