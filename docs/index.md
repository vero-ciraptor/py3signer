# py3signer Documentation

**py3signer** is a high-performance remote BLS signer for Ethereum Consensus Layer with a hybrid Python/Rust architecture.

!!! danger "Experimental Software"

    py3signer is **experimental software** meant for prototyping, testing, and development.

    **DO NOT use py3signer in production with real validators.**

    See [Risks](introduction/risks.md) for details.

## Overview

py3signer implements the [Keymanager API](https://ethereum.github.io/keymanager-APIs/) for importing BLS12-381 keys and signing Ethereum consensus data:

- **Python layer** ([Litestar](https://litestar.dev/){:target="_blank"}): HTTP server, request routing, business logic
- **Rust layer** ([PyO3](https://pyo3.rs/){:target="_blank"}): High-performance BLS signing via the battle-tested [`blst`](https://github.com/supranational/blst){:target="_blank"} library

## Features

- **Simplicity** – ~3,000 lines of Python, ~800 lines of Rust, minimal dependencies
- **EIP-2335 Keystore Support** – Import password-encrypted BLS keystores
- **Keymanager API** – Compatible with Web3Signer/Lighthouse APIs
- **In-Memory Key Storage** – Keys never touch disk in decrypted form
- **Multiple Signing Domains** – Attestations, blocks, RANDAO, exits, sync committee, and more
- **Prometheus Metrics** – Built-in observability
- **Bulk Loading** – Load keystores at startup from configurable paths

## Quick Links

- [Why py3signer?](introduction/why_py3signer.md) – Why this was built
- [Risks](introduction/risks.md) – Warnings about experimental status
- [Installation](quick-start/installation.md) – Setup instructions
- [Running py3signer](quick-start/running.md) – How to run
- [API Reference](reference/api.md) – Endpoint documentation
- [Configuration](reference/configuration.md) – CLI options
- [Architecture](reference/architecture.md) – Technical design

## Architecture Overview

```
┌─────────────┐      HTTP       ┌─────────────────┐     PyO3 FFI     ┌─────────────┐
│   Client    │ ─────────────── │  Python/Litestar │ ─────────────── │  Rust/blst  │
└─────────────┘                 └─────────────────┘                 └─────────────┘
                                      │                                    │
                                 ┌────┴────┐                          ┌──┴──┐
                                 │ handlers│                          │sign │
                                 │ storage │                          │verify
                                 │ metrics │                          │aggregate
                                 └─────────┘                          └─────┘
```

## License

MIT License – see [LICENSE](https://github.com/serenita-org/py3signer/blob/main/LICENSE){:target="_blank"} for details.
