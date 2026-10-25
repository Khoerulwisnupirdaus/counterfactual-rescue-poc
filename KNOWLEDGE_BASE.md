# KNOWLEDGE BASE — Counterfactual Preimage Recovery (Cross-VM Fund Rescue)

## 1. Problem Statement
Millions of dollars in user funds are permanently frozen across EVM and non-EVM/EraVM chains (e.g., Abstract Chain, ZKsync Era, Starknet, BNB Smart Chain, Ethereum, Arbitrum, Base) when users or cross-chain bridges send tokens to a user's **Smart Contract Wallet (Account Abstraction)** address on a chain with a different `CREATE2` address derivation formula.

Even though the user **holds the exact private key (`EOA Signer`)** that created and controls the smart wallet on the origin chain, the destination chain's VM rejects deploying the wallet at the same address because of domain-separated `CREATE2` prefixes:
- **EVM `CREATE2` (EIP-1014)**: 85-byte preimage starting with `0xff`.
- **EraVM `zksyncCreate2` (Abstract / ZKsync)**: 160-byte preimage starting with `0x2020dba9...` (`keccak256("zksyncCreate2")`).

---

## 2. Real-World Case Study (Verified On-Chain)
- **Stuck Address (`stuckWallet`)**: `0x6ae0145e60b073e8c47b922f16c0f9e71e3efa86`
- **Destination Chain (Where Funds Are Frozen)**: BNB Smart Chain (Chain ID `56`)
  - **Transaction Hash**: `0x512b66bef7392f9d1dd8fc3a9ee9234bd87dfdb7b0cd5c0395010f6576491f20` (Block `80681471`, Feb 11, 2026)
  - **Locked Balance**: `19,998.00 USDC` (`0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d`) + `0.0014 BNB`
  - **Code at Address on BSC**: `0x` (`nonce = 0`)
- **Origin Chain (Where Wallet Was Deployed)**: Abstract Mainnet (Chain ID `2741`)
  - **Creation Tx Hash**: `0xcdb63bfcbb7eab1f404dc9de6b79e787048f38307b1abce9fa5557405d7d5b9f` (Block `101456`)
  - **Factory Contract (`AccountFactory`)**: `0x9B947df68D35281C972511B3E7BC875926f26C1A`
  - **Proxy Bytecode Hash**: `0x0100003316a98e88b9e8931575675eed8e30eee97abeff3816fb98333ab085bc`
  - **Implementation Address (`AGWAccount`)**: `0xaa3633b417483f932969edaef7cc4f1068f6faa9`
  - **Salt**: `0x9c40f26d0e218dc6219fe7bae7b50af65cd87a6e1da558c4fa7bdaa33fad5185`
  - **Authorized K1 Owner EOA**: `0x07c65fe9f29a86b937604fa8d20a3fae19d7be48`

---

## 3. Core Cryptographic Discovery
In Abstract Global Wallet (`AccountFactory.sol`, >4.27M deployed wallets), the `salt` passed to `DEPLOYER_SYSTEM_CONTRACT.create2Account` is deterministically derived from the owner's 20-byte EOA address:
$$\text{salt} = \text{keccak256}(\text{abi.encodePacked}(\text{owner\_EOA}))$$

Verification:
- `owner_EOA` = `0x07c65fe9f29a86b937604fa8d20a3fae19d7be48`
- `keccak256(0x07c65fe9f29a86b937604fa8d20a3fae19d7be48)` = `0x9c40f26d0e218dc6219fe7bae7b50af65cd87a6e1da558c4fa7bdaa33fad5185`
- `keccak256(CREATE2_PREFIX || pad32(factory) || salt || proxyBytecodeHash || keccak256(pad32(implementation)))[12..32]` = `0x6ae0145e60b073e8c47b922f16c0f9e71e3efa86`

### Security Implication
Because `stuckWallet` is the 160-bit truncated Keccak-256 hash of a 160-byte preimage that contains `keccak256(owner_EOA)`:
1. Finding a different `attacker_EOA != owner_EOA` that produces the same `stuckWallet` requires finding a 160-bit second preimage in Keccak-256 ($\approx 2^{160}$ operations).
2. Therefore, **any EVM smart contract or chain precompile can verify ownership of `stuckWallet` in ~60 gas using pure `keccak256` arithmetic**, without requiring cross-chain bridges, oracles, ZK proofs, or centralized customer support.

---

## 4. Architectural Requirement (Important Constraint)
- This recovery mechanism requires either:
  1. **Token-Level Adoption (`IERC78xxCounterfactualRescue`)**: The token contract (e.g., `Binance-Peg USDC`, `USDC`, `USDT`, `OFT`) includes the `rescueCounterfactualEraVM` function in its implementation.
  2. **Chain-Level Adoption (`EIP-7702-Counterfactual` / BEP Precompile)**: The destination chain adds a system precompile that sets an EIP-7702 delegation designator (`0xef0100 || owner_EOA`) on `stuckWallet` upon verifying the 160-byte counterfactual preimage signed by `owner_EOA`.
- **WARNING**: Until a destination chain or token contract deploys this module on mainnet, sending real mainnet funds to a cross-VM counterfactual address will still freeze those funds on mainnet. All testing MUST be performed on local forks or testnets ($0 cost).
