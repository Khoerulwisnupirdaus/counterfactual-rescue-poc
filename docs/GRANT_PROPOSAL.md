# Grant Application & Forum Proposal Package
**Project**: Zero-Trust Counterfactual Preimage Rescue (`ERC / BEP Counterfactual Preimage Recovery`)  
**Repository**: https://github.com/Khoerulwisnupirdaus/counterfactual-rescue-poc  
**Author / Applicant**: Khoerul Wisnu Pirdaus (`@Khoerulwisnupirdaus`)

---

## PART 1: Ready-to-Copy Grant Application Form Answers
*(Use these answers directly in the application forms for **BNB Chain Grants**, **Ethereum Foundation ESP**, or **ZKsync Developer Grants**)*

### 1. Project Name
**Counterfactual Preimage Rescue (`ERC/BEP-CounterfactualRescue`): Zero-Trust Cross-VM Smart Account Asset Recovery**

### 2. Project Category
- Account Abstraction (ERC-4337 / EIP-7702 / Native AA)
- Cross-Chain Interoperability & Security Tooling
- Protocol Standards (ERC / BEP / RIP) & Public Goods

### 3. Executive Summary (Short Description — < 300 words)
Millions of dollars in user funds are permanently trapped across EVM chains (Ethereum, BNB Smart Chain, Base, Arbitrum) and EraVM/ZK Stack chains (ZKsync Era, Abstract, Sophon, Lens) when users or cross-chain bridges transfer ERC-20/BEP-20 tokens to a user's Smart Contract Wallet address on a chain with an incompatible `CREATE2` address derivation formula. Because EraVM `zksyncCreate2` uses a 160-byte preimage starting with `0x2020dba9...` while standard EVM `CREATE2` (EIP-1014) enforces an 85-byte preimage starting with `0xff`, the user's smart wallet can never be redeployed at the same address on the destination chain—even though the user holds the valid `secp256k1` private key (`ownerEOA`) that created the wallet.

We discovered and proved on real mainnet data (e.g., BSC Tx `0x512b66bef7392f9d1dd8fc3a9ee9234bd87dfdb7b0cd5c0395010f6576491f20`, where `19,998.00 Binance-Peg USDC` is trapped at counterfactual address `0x6ae0145e60b073e8c47b922f16c0f9e71e3efa86`) that the underlying `salt` (`salt = keccak256(abi.encodePacked(ownerEOA))`) acts as a **160-bit collision-resistant cryptographic commitment to the EOA owner**.

We built **Counterfactual Preimage Rescue**, a lightweight Solidity standard (`CounterfactualRescue.sol`) and multi-chain diagnostic scanner that verifies the 160-byte/85-byte `CREATE2` preimage directly inside the EVM in **1,254 gas**—allowing the true key holder (`ownerEOA`) to rescue trapped funds self-servingly (or gaslessly via **EIP-712 signatures**) with **zero bridges, zero oracles, zero ZK proofs, and zero centralized customer support**.

### 4. Problem Statement & Real On-Chain Evidence
1. **The Cross-VM `CREATE2` Trap**:
   - Over **4.27 million** native AA smart wallets on EraVM chains alone derive their addresses via `ContractDeployer.getNewAddressCreate2` (`0x2020dba9...` prefix).
   - Standard EVM chains (`CREATE2`) strictly use `0xff`.
   - Because of domain separation (`0x20` vs `0xff`), redeploying an EraVM smart account on an EVM chain (or an EVM Safe/AA account on an EraVM chain) requires breaking 160-bit Keccak-256 second-preimage resistance ($2^{160}$ operations).
2. **Real On-Chain Case Study**:
   - **BNB Smart Chain Tx**: `0x512b66bef7392f9d1dd8fc3a9ee9234bd87dfdb7b0cd5c0395010f6576491f20` (`19,998.00 USDC` trapped at `0x6ae0145e60b073e8c47b922f16c0f9e71e3efa86`).
   - **Origin Creation Tx**: `0xcdb63bfcbb7eab1f404dc9de6b79e787048f38307b1abce9fa5557405d7d5b9f` (deployed by `AccountFactory` `0x9B947df68D35281C972511B3E7BC875926f26C1A` for owner EOA `0x07c65fe9f29a86b937604fa8d20a3fae19d7be48`).
   - Currently, victims must rely on slow, manual centralized recovery programs (such as the *BNB Pioneer Burn Program*) or lose their funds forever.

### 5. Technical Architecture & Working Prototype
Our open-source repository (https://github.com/Khoerulwisnupirdaus/counterfactual-rescue-poc) already delivers a working, `solc 0.8.24`-compiled and `py-evm`-verified prototype:
- **`contracts/CounterfactualRescue.sol` & `contracts/RescueableERC20.sol`**:
  - Supports 4 canonical derivation modes (`ERA_VM_PACKED_20`, `ERA_VM_ABI_32`, `ERA_VM_INDEXED`, `EVM_CREATE2_PACKED_20`).
  - Supports **Direct EOA Rescue (`rescueCounterfactual`)** (~53,700 gas total execution).
  - Supports **Gasless Relayer Rescue via EIP-712 (`rescueCounterfactualWithSig`)** (~59,192 gas total execution) for embedded signers (Privy/Turnkey) or EOAs without destination-chain gas.
- **`test_evm_bytecode.py`**: In-memory Shanghai/Cancun EVM execution test suite proving $2^{160}$ attacker rejection, active-contract guards (`code.length == 0`), and EIP-712 replay resistance.
- **`scan_stuck_funds.py`**: Multi-chain scanner detecting trapped counterfactual balances across BNB Smart Chain, Base, and Arbitrum.

### 6. Milestones & Funding Request ($15,000 Total)

| Milestone | Deliverables | Timeline | Requested Budget |
| :--- | :--- | :---: | :---: |
| **Milestone 1: Completed PoC & Formal ERC/BEP Specification** | • Production Solidity contracts (`CounterfactualRescue.sol`, `RescueableERC20.sol`)<br>• `py-evm` bytecode execution test suite & gas benchmarks<br>• Formal ERC/BEP specification draft & multi-chain CLI scanner | Completed (Ready for Review) | **$5,000** |
| **Milestone 2: Multi-Factory Registry & Precompile Specification (`RIP / BEP-7702 Extension`)** | • Expand support to Safe, Clave, ZeroDev Kernel, Biconomy, and Coinbase Smart Wallet counterfactual layouts<br>• Write C++/Go client precompile patch (`geth` / `bsc`) for chain-level `CounterfactualAccountDelegation` (recovering native BNB/ETH in addition to ERC-20 tokens) | 4 Weeks | **$5,000** |
| **Milestone 3: Public Web Dashboard & Open-Source SDK** | • Open-source web interface where affected users can connect their EOA signer, scan all EVM/EraVM chains for trapped counterfactual funds, and generate cryptographic preimage proofs / EIP-712 rescue payloads | 4 Weeks | **$5,000** |

---

## PART 2: Ready-to-Post Forum Thread (Ethereum Magicians / BNB Chain Forum)
*(Post this on https://ethereum-magicians.org or https://forum.bnbchain.org/c/bep/7 first, then include the forum link in your grant application!)*

**Thread Title**:
`[ERC/BEP Proposal] Zero-Trust Counterfactual Preimage Token Rescue (Cross-VM 0x20 <-> 0xff Recovery)`

**Thread Body**:
```markdown
## Summary
We propose a lightweight, zero-trust ERC-20 / BEP-20 extension (`CounterfactualPreimageRescue`) that allows the EOA owner (`ownerEOA`) of a cross-VM counterfactual smart wallet (e.g., EraVM `zksyncCreate2` wallets on ZKsync/Abstract/Sophon/Lens, or EVM `CREATE2` wallets on non-EVM chains) to self-rescue tokens trapped on a chain with an incompatible `CREATE2` prefix (`0x2020dba9...` vs `0xff`).

- **Reference Implementation, `py-evm` Tests & Scanner**: https://github.com/Khoerulwisnupirdaus/counterfactual-rescue-poc
- **Full Draft Specification**: https://github.com/Khoerulwisnupirdaus/counterfactual-rescue-poc/blob/master/docs/ERC-Counterfactual-Preimage-Rescue.md

## The Problem (Verified on Mainnet)
When a user withdraws or bridges tokens to their Smart Account address on a chain with a different VM `CREATE2` formula, the address cannot be deployed on the destination chain due to domain separation:
- **EVM `CREATE2` (EIP-1014)**: `keccak256(0xff || factory || salt || initCodeHash)[12..32]` (85 bytes)
- **EraVM `zksyncCreate2`**: `keccak256(keccak256("zksyncCreate2") || bytes32(uint256(uint160(factory))) || salt || bytecodeHash || keccak256(constructorInput))[12..32]` (160 bytes)

For example, in BSC transaction `0x512b66bef7392f9d1dd8fc3a9ee9234bd87dfdb7b0cd5c0395010f6576491f20`, `19,998.00 USDC` was sent to `0x6ae0145e60b073e8c47b922f16c0f9e71e3efa86` (an EraVM smart wallet owned by EOA `0x07c65fe9f29a86b937604fa8d20a3fae19d7be48`). Because `0x6ae0...` was derived from a 160-byte `0x2020dba9...` preimage, it is mathematically impossible ($2^{160}$) to deploy on BSC via `0xff`.

## The Cryptographic Insight
In canonical AA factories (`AccountFactory.sol`), `salt` is deterministically bound to the owner's EOA:
`salt = keccak256(abi.encodePacked(ownerEOA))`

Because `stuckWallet` is the 160-bit truncated Keccak-256 digest of a preimage containing `keccak256(ownerEOA)`, any upgradeable ERC-20/BEP-20 token (or chain precompile) can verify ownership in **1,254 gas** using pure `keccak256` arithmetic—without bridges, oracles, or ZK proofs!

We welcome feedback from wallet teams, token issuers, and core developers on standardizing `CounterfactualPreimageRescue`.
```
