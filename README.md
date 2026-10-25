# Counterfactual Preimage Rescue (`0x20` $\leftrightarrow$ `0xff`)

> *"The key was never lost. Only the prefix changed."*

Zero-trust cryptographic recovery architecture and multi-chain scanner for assets trapped in cross-VM counterfactual smart accounts (EraVM `zksyncCreate2` $\leftrightarrow$ EVM `CREATE2`).

---

## Overview

When Account Abstraction (AA) smart wallets are deployed on non-standard EVM / EraVM chains (ZKsync Era, Abstract, Sophon, Lens, Cronos zkEVM), their counterfactual address is derived using a 160-byte domain-separated preimage beginning with `0x2020dba9...` (`keccak256("zksyncCreate2")`), whereas standard EVM chains (`CREATE2`, EIP-1014) enforce an 85-byte preimage beginning with `0xff`.

However, because the account factory deterministically commits the owner's EOA address inside the `salt` (`salt = keccak256(abi.encodePacked(ownerEOA))`), the 160-byte preimage itself acts as a **160-bit collision-resistant cryptographic proof of ownership** that can be verified on any EVM chain in ~60 gas without bridges, oracles, or centralized intermediaries.

$$\text{stuckWallet} = \text{keccak256}\Big(\texttt{0x2020dba9...} \;\|\; \text{pad32}(\text{factory}) \;\|\; \text{keccak256}(\mathbf{\text{msg.sender}}) \;\|\; \text{bytecodeHash} \;\|\; \text{keccak256}(\text{pad32}(\text{impl}))\Big)[12..32]$$

---

## Repository Structure

| File | Description |
| :--- | :--- |
| [`contracts/CounterfactualRescue.sol`](contracts/CounterfactualRescue.sol) | Solidity abstract module (`CounterfactualPreimageRescue`) enabling zero-trust self-service token recovery via `keccak256` preimage verification. |
| [`test_rescue_poc.py`](test_rescue_poc.py) | Pure-Python Keccak-256 verification and simulation suite tested against real on-chain parameters (`0x6ae0145e60b073e8c47b922f16c0f9e71e3efa86`). |
| [`scan_stuck_funds.py`](scan_stuck_funds.py) | Live multi-chain scanner that derives EraVM counterfactual addresses from an EOA owner and detects trapped native/ERC-20 balances across BNB Smart Chain, Base, and Arbitrum. |
| [`KNOWLEDGE_BASE.md`](KNOWLEDGE_BASE.md) | Forensic breakdown, preimage derivation proofs, and security invariants. |

---

## Quick Start

```bash
# 1. Run the cryptographic preimage rescue simulation
python test_rescue_poc.py

# 2. Scan live EVM chains for trapped counterfactual balances by EOA owner
python scan_stuck_funds.py --owner 0x07c65fe9f29a86b937604fa8d20a3fae19d7be48
```
