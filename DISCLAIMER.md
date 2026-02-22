# Experimental Software Disclaimer

## ⚠️ Not for Production Use

**py3signer is experimental software intended for experimentation, prototyping, and testing purposes only.**

### What This Means

Do **NOT** use py3signer in production environments with:
- Real validator keys on Ethereum mainnet
- Significant amounts of staked ETH at risk
- Any scenario where key compromise would cause financial loss

### Security Limitations

This software has fundamental security limitations that make it unsuitable for production validator operations:

#### 1. Private Keys in Memory
- All private keys are held in **process memory continuously** while the signer is running
- Keys can be extracted via:
  - Memory dumps (`/proc/[pid]/mem` on Linux)
  - Core dumps (if enabled)
  - Process debugging tools
  - Container escape scenarios

#### 2. No Hardware Security
- **No HSM (Hardware Security Module) integration** – keys are not protected by dedicated hardware
- **No TEE (Trusted Execution Environment)** – no secure enclaves for key operations
- Keys exist in the same memory space as the Python runtime

#### 3. Limited Memory Protection
- While efforts are made to clear passwords from memory after use, this provides **limited real protection**
- For a continuous signer, the private keys themselves must remain in memory to perform signing operations
- Memory clearing is "security theater" in this context – the keys are still accessible

#### 4. No Slashing Protection
- py3signer has **no slashing protection mechanism**
- Running multiple instances with the same keys will result in **slashable offenses**
- No safeguards against double-signing or surround votes

### Recommended Production Alternatives

For securing real validator keys in production, use established solutions:

| Solution | Description | Key Protection |
|----------|-------------|----------------|
| [Web3Signer](https://github.com/Consensys/web3signer) | Enterprise remote signer by Consensys | Slashing protection, HSM support |
| [Dirk](https://github.com/attestantio/dirk) | Distributed remote key manager | Multi-party computation, threshold signing |
| HSM-based signers | Hardware security modules | Keys never leave hardware |

### Appropriate Use Cases

py3signer is suitable for:
- **Local development** – Testing validator integrations on devnets
- **CI/CD pipelines** – Automated testing with throwaway keys
- **Educational purposes** – Understanding remote signer architectures
- **Rapid prototyping** – Experimenting with Keymanager API implementations

### Responsibility

The authors and contributors of py3signer assume **no liability** for:
- Loss of funds due to key compromise
- Slashing penalties from improper usage
- Security incidents resulting from the use of this software

**Use at your own risk.**

### Questions?

For production validator operations, consult with:
- Ethereum staking infrastructure teams
- Security auditors specializing in blockchain operations
- The Ethereum Foundation's validator documentation
