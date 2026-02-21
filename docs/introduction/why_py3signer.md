# Why py3signer

There are already several remote signers available for Ethereum validators – why build another one?

The short answer is: **py3signer was created for experimentation, prototyping, and testing.** You'll find the longer answer below.

## The Problem Space

Remote signers are critical infrastructure for Ethereum validators. They hold the private keys that sign attestations, blocks, and other consensus messages. Any signer needs to be:

1. **Secure** – Keys must be protected from unauthorized access
2. **Reliable** – Downtime means missed rewards and potentially penalties
3. **Performant** – Must handle signing requests quickly under load

Existing solutions like [Web3Signer](https://docs.web3signer.consensys.io/){:target="_blank"} and [Dirk](https://github.com/attestantio/dirk){:target="_blank"} fulfill these requirements well for production use.

## Where Does py3signer Come In?

At [Serenita](https://serenita.io){:target="_blank"}, we wanted to explore:

1. **Hybrid Python/Rust architectures** – Can we get Python's developer productivity with Rust's performance?
2. **Alternative signing implementations** – How do different BLS libraries compare?
3. **Rapid prototyping** – Can we iterate quickly on new features or APIs?

py3signer was built as an experimental platform to answer these questions.

## Simplicity by Design

One of py3signer's defining characteristics is its **minimal footprint**:

| Metric | Value |
|--------|-------|
| Python code | ~3,000 lines |
| Rust code | ~800 lines |
| Python runtime dependencies | 4 (litestar, granian, msgspec, prometheus-client) |
| Rust dependencies | 8 (mostly crypto: blst, pyo3, scrypt, aes, etc.) |

Compare this to Web3Signer (Java) or Dirk (Go), which have tens of thousands of lines and dozens of dependencies. py3signer's small codebase means:

- **Faster comprehension** – Understand the entire system in an afternoon
- **Easier auditing** – Review the complete security surface quickly
- **Simpler debugging** – Fewer places for bugs to hide
- **Faster iteration** – Make changes with confidence

This minimalism is intentional. For experimental and educational use, simplicity trumps feature completeness.

## Use Cases

### When to Use py3signer

py3signer is appropriate for:

- **Local development and testing** – Spin up a signer quickly for validator client testing
- **CI/CD pipelines** – Automated testing of validator setups
- **Educational purposes** – Understanding how remote signers work
- **Protocol research** – Experimenting with new signing schemes or APIs
- **Performance benchmarking** – Comparing against other signing implementations

### When NOT to Use py3signer

!!! danger "Do Not Use For Production Validators"

    py3signer is **explicitly NOT suitable** for:

    - Production validators with real ETH at stake
    - Mainnet validators
    - Any scenario where slashing would have financial consequences
    - Production infrastructure requiring 99.9%+ uptime guarantees

## Key Differences from Production Signers

| Feature | py3signer | Web3Signer/Dirk |
|---------|:---------:|:---------------:|
| Code Size | ~3,800 LOC | Tens of thousands |
| Runtime Dependencies | 4 Python + 8 Rust | Dozens |
| Slashing Protection | ❌ None | ✅ Full protection |
| Production Ready | ❌ Experimental | ✅ Battle-tested |
| Multi-key support | ✅ Basic | ✅ Enterprise-grade |
| Audit History | ❌ None | ✅ Multiple audits |
| Community Usage | ❌ Minimal | ✅ Widespread |
| Enterprise Support | ❌ None | ✅ Available |

## Design Goals

1. ### Simplicity

    py3signer's codebase is intentionally minimal:

    - **~3,000 lines of Python** – HTTP server, business logic, keystore handling
    - **~800 lines of Rust** – BLS cryptographic operations
    - **4 runtime Python dependencies** – litestar, granian, msgspec, prometheus-client

    Less code means fewer potential bugs, faster comprehension, and easier modification. You can read the entire codebase in an afternoon and understand exactly how it works.

2. ### Performance

    By using Rust for the cryptographic operations via the `blst` library, py3signer achieves high signing throughput while maintaining Python's ease of use for the application layer.

3. ### Hackability

    Python's dynamic nature and rich ecosystem make it ideal for rapid experimentation. Want to add a new endpoint? Modify the signing logic? It's straightforward.

4. ### Compatibility

    py3signer implements the standard Keymanager API, making it compatible with existing validator clients and tooling.

## Trade-offs

py3signer makes several trade-offs that make it unsuitable for production:

- **No slashing protection** – It signs whatever is requested
- **In-memory only** – No persistence of signing history
- **Limited testing** – Not battle-tested at scale
- **Single maintainer** – Experimental project with no SLA

These trade-offs are intentional. They keep the code simple and focused on its experimental purpose.

## Contributing

If you're interested in experimenting with py3signer or contributing improvements, contributions are welcome! Just remember the experimental nature of this project.
