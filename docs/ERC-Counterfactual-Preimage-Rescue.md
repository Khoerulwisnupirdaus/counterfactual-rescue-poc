---
eip: TBD
title: Zero-Trust Counterfactual Preimage Token Rescue (Cross-VM CREATE2 Recovery)
description: Standard interface and verification logic enabling EOA owners to rescue tokens trapped in cross-VM counterfactual smart accounts via Keccak-256 preimage verification.
author: Khoerul Wisnu Pirdaus (@Khoerulwisnupirdaus)
status: Draft
type: Standards Track
category: ERC
created: 2026-10-26
---

## Abstract

This standard defines a zero-trust, permissionless mechanism (`IERC_CounterfactualPreimageRescue`) for ERC-20 / BEP-20 tokens that enables the cryptographic owner (`ownerEOA`) of a counterfactual Smart Contract Account (such as an EraVM `zksyncCreate2` wallet on ZKsync Era, Abstract, Sophon, Lens, or an EVM `CREATE2` wallet trapped on a non-EVM chain) to recover tokens mistakenly sent to that counterfactual address on a chain with an incompatible `CREATE2` domain prefix.

By verifying the 160-byte (`zksyncCreate2`, prefix `0x2020dba9...`) or 85-byte (`CREATE2`, prefix `0xff`) address derivation preimage in which `salt` is deterministically bound to `ownerEOA` (`salt = keccak256(abi.encodePacked(ownerEOA))`), the token contract mathematically verifies ownership in ~60 gas using a single `keccak256` evaluation—requiring **zero bridges, zero oracles, zero ZK proofs, and zero centralized customer support**.

---

## Motivation

With the proliferation of native Account Abstraction (AA) on Layer-2 and Layer-1 networks, millions of users interact primarily through smart contract wallets whose addresses are deterministically derived from an underlying EOA signer (`ownerEOA`).

However, virtual machines use incompatible, domain-separated `CREATE2` formulas:

1. **Standard EVM (`CREATE2`, EIP-1014)**:
   $$\text{address} = \text{keccak256}\Big(\texttt{0xff} \;\|\; \text{factory}_{20} \;\|\; \text{salt}_{32} \;\|\; \text{initCodeHash}_{32}\Big)[12..32]$$
2. **EraVM (`zksyncCreate2`, ZKsync Stack / Abstract / Elastic Network)**:
   $$\text{address} = \text{keccak256}\Big(\text{keccak256}(\text{"zksyncCreate2"})_{32} \;\|\; \text{pad32}(\text{factory})_{32} \;\|\; \text{salt}_{32} \;\|\; \text{bytecodeHash}_{32} \;\|\; \text{constructorInputHash}_{32}\Big)[12..32]$$

Because `keccak256("zksyncCreate2")` begins with `0x20` (160-byte preimage) whereas EIP-1014 begins with `0xff` (85-byte preimage), **an EraVM smart wallet address can never be deployed on a standard EVM chain**, and vice versa. When users withdraw from centralized exchanges or bridge tokens across chains to their own smart wallet address, those funds become permanently frozen at an undeployable address (`code.length == 0`), even though the user holds the valid private key for `ownerEOA`.

---

## Specification

### Derivation Modes

```solidity
enum DerivationMode {
    ERA_VM_PACKED_20,      // salt = keccak256(abi.encodePacked(ownerEOA))
    ERA_VM_ABI_32,         // salt = keccak256(abi.encode(ownerEOA))
    ERA_VM_INDEXED,        // salt = keccak256(abi.encodePacked(ownerEOA, accountIndex))
    EVM_CREATE2_PACKED_20  // 0xff || factory || keccak256(abi.encodePacked(ownerEOA)) || bytecodeHash
}

struct CounterfactualProof {
    DerivationMode mode;
    address factory;
    bytes32 bytecodeHash;
    bytes constructorInput;
    uint256 accountIndex;
}
```

### Verification Invariants

A compliant implementation MUST enforce:
1. **Cryptographic Owner Binding**: `salt` MUST be computed directly from the authenticated caller (`msg.sender`) or the EIP-712 recovered signer (`ownerEOA`). It MUST NOT accept a raw, arbitrary `bytes32 salt` supplied by the caller without binding it to `ownerEOA`.
2. **Undeployed Target Check**: `stuckWallet.code.length == 0` MUST hold on the executing chain so active smart contracts cannot have their balances swept.
3. **EIP-2 Malleability & Nonce Protection**: Delegated EIP-712 signatures (`rescueCounterfactualWithSig`) MUST enforce `uint256(s) <= SECP256K1_HALF_N`, `v in {27, 28}`, `block.timestamp <= deadline`, and increment `rescueNonces[stuckWallet]`.

---

## Security Considerations

### Second-Preimage Resistance ($2^{160}$)
Can an attacker `A != ownerEOA` craft fake `(factory', bytecodeHash', constructorInput')` parameters such that `computeCounterfactualAddress(A, fakeProof) == stuckWallet`?
* Because `stuckWallet` was generated prior to the deposit using genuine parameters on the origin chain, finding `(factory', bytecodeHash', constructorInput')` for a fixed `salt' = keccak256(A)` that collides with the 160-bit truncated output `stuckWallet` is equivalent to a **160-bit second-preimage attack on Keccak-256**, requiring $\approx 2^{160}$ operations (infeasible, matching the security bound of Ethereum addresses themselves).
