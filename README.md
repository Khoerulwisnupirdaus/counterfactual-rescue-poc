# Counterfactual Preimage Rescue (`0x20` $\leftrightarrow$ `0xff`)

> *"The key was never lost. Only the prefix changed."*

Zero-trust cryptographic recovery standard (`ERC-CounterfactualPreimageRescue`), compiled Solidity reference implementation, `py-evm` bytecode execution test suite, and multi-chain scanner for assets trapped in cross-VM counterfactual smart accounts (EraVM `zksyncCreate2` $\leftrightarrow$ EVM `CREATE2`).

---

## Overview

When Account Abstraction (AA) smart wallets are deployed on non-standard EVM / EraVM chains (ZKsync Era, Abstract, Sophon, Lens, Cronos zkEVM, Elastic Network), their counterfactual address is derived using a 160-byte domain-separated preimage beginning with `0x2020dba9...` (`keccak256("zksyncCreate2")`), whereas standard EVM chains (`CREATE2`, EIP-1014) enforce an 85-byte preimage beginning with `0xff`.

Because the account factory deterministically commits the owner's EOA address inside the `salt` (`salt = keccak256(abi.encodePacked(ownerEOA))`), the 160-byte preimage itself acts as a **160-bit collision-resistant cryptographic proof of ownership** that can be verified on any EVM chain in **1,254 gas** without bridges, oracles, ZK proofs, or centralized intermediaries.

$$\text{stuckWallet} = \text{keccak256}\Big(\texttt{0x2020dba9...} \;\|\; \text{pad32}(\text{factory}) \;\|\; \text{keccak256}(\mathbf{\text{ownerEOA}}) \;\|\; \text{bytecodeHash} \;\|\; \text{keccak256}(\text{constructorInput})\Big)[12..32]$$

---

## Repository Structure

| File | Description |
| :--- | :--- |
| [`contracts/CounterfactualRescue.sol`](contracts/CounterfactualRescue.sol) | Production Solidity module supporting 4 derivation modes (`ERA_VM_PACKED_20`, `ERA_VM_ABI_32`, `ERA_VM_INDEXED`, `EVM_CREATE2_PACKED_20`) plus **EIP-712 gasless relayer rescue (`rescueCounterfactualWithSig`)**. |
| [`contracts/RescueableERC20.sol`](contracts/RescueableERC20.sol) | Standalone ERC-20 / BEP-20 reference token implementing `CounterfactualPreimageRescue` (compiled with `solc 0.8.24` in [`build/`](build/)). |
| [`docs/ERC-Counterfactual-Preimage-Rescue.md`](docs/ERC-Counterfactual-Preimage-Rescue.md) | Formal ERC / BEP standard specification for grant & EIP/RIP submission. |
| [`test_evm_bytecode.py`](test_evm_bytecode.py) | Real EVM bytecode execution test suite (`py-evm`) verifying `RescueableERC20.bin`, gas profiling, EIP-712 `ecrecover`, and replay resistance. |
| [`test_rescue_poc.py`](test_rescue_poc.py) | Pure-Python Keccak-256 verification suite across all 4 derivation modes. |
| [`scan_stuck_funds.py`](scan_stuck_funds.py) | Live multi-chain scanner detecting trapped counterfactual balances across BNB Smart Chain, Base, and Arbitrum. |
| [`KNOWLEDGE_BASE.md`](KNOWLEDGE_BASE.md) | Forensic breakdown, preimage derivation proofs, and security invariants. |

---

## Verified Benchmark (`py-evm` Bytecode Execution)

```text
============================================================================
REAL SOLC BYTECODE EXECUTION SUITE (py-evm, Shanghai/Cancun VM)
============================================================================
[OK] Deployed RescueableERC20 at 0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d (runtime size: 4910 bytes)
[PASS] EVM computeEraVMCounterfactualAddress -> 0x6ae0145e60b073e8c47b922f16c0f9e71e3efa86 (gas: 1,254)
[PASS] EVM Attacker Call Reverted with selector 0x92397075 (NothingToRescue)
[PASS] EVM Direct Rescue by 0x07c65fe9f29a86b937604fa8d20a3fae19d7be48 -> Rescued 19,998.00 USDC (gas: 53,700)
[PASS] EVM EIP-712 Gasless Relayer Rescue -> Rescued 7,500.00 USDC to 0x3333333333333333333333333333333333333333 (gas: 59,192)
[PASS] EVM EIP-712 Signature Replay Rejected (Nonce Incremented)
============================================================================
```

## Quick Start

```bash
# 1. Run pure-Python verification suite (zero external dependencies)
python test_rescue_poc.py

# 2. Run real solc-compiled EVM bytecode execution suite
uv run --with py-evm --with eth-abi --with eth-account python test_evm_bytecode.py

# 3. Scan live EVM chains for trapped counterfactual balances by EOA owner
python scan_stuck_funds.py --owner 0x07c65fe9f29a86b937604fa8d20a3fae19d7be48
```
