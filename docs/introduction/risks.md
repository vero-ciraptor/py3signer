# Risks

!!! danger "EXPERIMENTAL SOFTWARE – USE AT YOUR OWN RISK"

    **py3signer is experimental software. It is NOT suitable for production use with real validators.**

    Using py3signer with validators that have real ETH at stake will likely result in **slashing** and **loss of funds**.

## Critical Risks

### No Slashing Protection

**py3signer has NO slashing protection.** This is the most critical risk.

What this means:

- py3signer will sign **whatever is requested**, regardless of whether it's safe
- Running multiple validators with the same keys WILL result in slashing
- There is no database tracking what has been signed
- No validation of attestation or block timing

!!! warning "Double Signing = Slashing"

    If you run py3signer alongside another validator client with the same keys, **both validators will sign**, causing a double-signing slashing event. This results in:

    - **Immediate ejection** from the validator set
    - **Loss of 0.5-1 ETH** (or more on testnets with modified penalties)
    - **32 ETH stake locked** until withdrawals are enabled (if on mainnet)

### In-Memory State

py3signer stores keys only in memory:

- **No persistence** of signing history between restarts
- **No protection** against restart-related double signing
- **No slashing protection database** to import/export

## Operational Risks

### Single Instance Only

You MUST run py3signer as a **single instance** per validator key:

```bash
# ❌ WRONG: Running multiple instances
Instance A (py3signer) ──► Signs attestation for slot 100
Instance B (py3signer) ──► Also signs attestation for slot 100
                              ↓
                        SLASHING EVENT
```

If you need high availability, use a production signer like Web3Signer with proper slashing protection.

### No Downtime Protection

py3signer does not implement:

- Automatic failover
- Leader election
- Distributed consensus

A restart or crash means **missed attestations** and **missed rewards**.

## Security Risks

### Network Exposure

By default, py3signer binds to `127.0.0.1` (localhost). If you change this to `0.0.0.0`:

```bash
# ⚠️ Dangerous – exposes signer to network
uv run python -m py3signer --host 0.0.0.0
```

Anyone with network access can request signatures if there's no additional firewall protection.

### Key Material

- Keys are decrypted in memory
- Memory dumps or core dumps could expose private keys
- No memory encryption or secure enclave support

## Software Quality Risks

### Experimental Status

py3signer is:

- **Not audited** by security professionals
- **Not battle-tested** at scale
- **Not widely used** in production
- **Subject to breaking changes** without notice

### Limited Testing

While py3signer has unit tests, it lacks:

- Formal verification of cryptographic operations
- Chaos testing under network partitions
- Long-running soak tests
- Multi-client integration testing at scale

## Mitigation Strategies

If you choose to use py3signer despite these risks:

1. **Use testnet only** – Never use with mainnet validators
2. **Single instance** – Never run multiple copies with the same keys
3. **Firewall protection** – Restrict network access appropriately
4. **Monitor closely** – Watch for missed attestations or unusual behavior
5. **Have an exit strategy** – Be ready to switch to a production signer

## When to Use a Production Signer Instead

Use Web3Signer, Dirk, or another production-grade signer if you need:

| Requirement | Solution |
|-------------|----------|
| Slashing protection | Web3Signer, Dirk |
| High availability | Web3Signer with redundancy |
| Production support | Commercial signing services |
| Audit history | Established open-source signers |
| Enterprise features | Dirk with threshold signing |

## Reporting Issues

If you discover a security issue or bug in py3signer, please report it responsibly. Remember that this is experimental software with no production support guarantees.
