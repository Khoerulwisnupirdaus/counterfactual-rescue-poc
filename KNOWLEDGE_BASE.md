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

## 4. Empirical Multi-Chain Scan Results (21 Trapped Counterfactual Wallets Discovered)

Using [`mass_scan_stuck_wallets.py`](mass_scan_stuck_wallets.py) (`Multicall3.aggregate3` batch scanner) across a 0.4% sample (`17,083` out of `4,271,683` deployed EraVM `AGW` smart wallets), we identified **21 distinct counterfactual wallets** holding trapped funds on standard EVM chains where `eth_getCode == 0x`:

| # | Stuck Counterfactual Wallet | Destination Chain (`code == 0x`) | Trapped Balance | Verified Origin EOA Owner (`salt = keccak256(owner)`) | Origin Deployment Tx (Abstract) |
| :- | :--- | :--- | :--- | :--- | :--- |
| 1 | `0x6ae0145e60b073e8c47b922f16c0f9e71e3efa86` | **BNB Smart Chain** | **19,998.00 USDC** + 0.0014 BNB | `0x07c65fe9f29a86b937604fa8d20a3fae19d7be48` | `0xcdb63bfc...5d7d5b9f` |
| 2 | `0x87f5a13a9ef0d839df3be1c6317c2e54f1ca88d5` | **Base Mainnet** | **500.00 USDC** | `0x5cb4fe4324cb88816a8f2cbf8d8ccc4bb9e60233` | `0xe39532ae...70173658` |
| 3 | `0x006e3a1b9c3b419761f2a7a0411cc37c0da453a7` | **BNB Smart Chain** | **333.41 USDT** | `0xd36d3af50fd3ab162cbb2e1b83655df20c8a3d36` | `0xc6101a1d...f967b67d` |
| 4 | `0xac3940699a89b5543bd855c899565d35e16fb4a9` | **Base Mainnet** | **238.32 USDC** | `0x502a0b23845834cf2c368edfb1e4e7c8891ee245` | `0x916537dd...aeb8fbbe` |
| 5 | `0xe8c90ca25ecaaed8711ad1bc9946bc9868e74926` | **Base Mainnet** | **0.0851 ETH** | `0x0e3e247bac4e40e948566515d1e67e8e650333ba` | `0xa28fee16...a445594` |
| 6 | `0x838c0891efa420de109e5d5daad7d34ea5a6cfdf` | **Base Mainnet** | **0.0576 ETH** | Verified `AGWAccount` (`0x20` EraVM) | `AccountFactory` |
| 7 | `0x76323362a0c4bdd76161be72e8bfb5a829499ab8` | **Base Mainnet** | **0.0496 ETH** | Verified `AGWAccount` (`0x20` EraVM) | `AccountFactory` |
| 8 | `0x79154987dbe24053eb8c63c02c57ecd663b7bdd9` | **Arbitrum One** | **62.30 USDC** | `0x03093b26781376ec6b97b7f13f3cbf25ff4e30df` | `0x183ecae6...99a9e8` |
| 9 | `0x8e3d58d201a62bdac918c77c186b9990a5d01386` | **Arbitrum One** | **31.19 USDC** | Verified `AGWAccount` (`0x20` EraVM) | `AccountFactory` |
| 10 | `0x1f373d94a2d7546c983e562169cb23058ab08825` | **Base Mainnet** | **0.0250 ETH** | Verified `AGWAccount` (`0x20` EraVM) | `AccountFactory` |
| 11 | `0x19dd483d159fdb253f3fc300ab831c7ab26aa9d1` | **Arbitrum One** | **0.0200 ETH** | Verified `AGWAccount` (`0x20` EraVM) | `AccountFactory` |
| 12 | `0xedd90999e2d5701b389d741b7dd5d8f0ebbf1c9e` | **Base Mainnet** | **20.00 USDC** | Verified `AGWAccount` (`0x20` EraVM) | `AccountFactory` |
| 13 | `0x9ddd7813813f3e828cbde267639fad431b2ce354` | **Base Mainnet** | **0.0180 ETH** | Verified `AGWAccount` (`0x20` EraVM) | `AccountFactory` |
| 14 | `0x1b5e26b7751737552cdb28fd602b276eb9d5d077` | **Base Mainnet** | **0.0151 ETH** | Verified `AGWAccount` (`0x20` EraVM) | `AccountFactory` |
| 15 | `0x406c44345ffed47c429a047ce28ef915fe76d1f9` | **Arbitrum One** | **0.0140 ETH** | Verified `AGWAccount` (`0x20` EraVM) | `AccountFactory` |
| 16 | `0x0bc4bcaa440b48f807048c979c2b6576f88e4aa8` | **Arbitrum One** | **0.0120 ETH** | Verified `AGWAccount` (`0x20` EraVM) | `AccountFactory` |
| 17 | `0x6ff3f09f451f23eeee96d0e9c16d2dfec11b1c55` | **Arbitrum One** | **10.00 USDC** | Verified `AGWAccount` (`0x20` EraVM) | `AccountFactory` |
| 18 | `0x805c1e25d3e8121ad30b9bcda532458f4d2d52dc` | **Base Mainnet** | **0.0100 ETH** | Verified `AGWAccount` (`0x20` EraVM) | `AccountFactory` |
| 19 | `0x90ff4fcb9553bb3e0773c46767283072e8912039` | **Base Mainnet** | **0.0062 ETH** | Verified `AGWAccount` (`0x20` EraVM) | `AccountFactory` |
| 20 | `0xea1329b1bd7e88c01cca02ad3eca1fb450b1f8cb` | **Base Mainnet** | **0.0053 ETH** | Verified `AGWAccount` (`0x20` EraVM) | `AccountFactory` |
| 21 | `0x966ab709b9a7aa3c81207d0bde0c0e0ae254d787` | **Base Mainnet** | **0.0051 ETH** | Verified `AGWAccount` (`0x20` EraVM) | `AccountFactory` |

---

## 5. Architectural Requirement (Important Constraint)
- This recovery mechanism requires either:
  1. **Token-Level Adoption (`IERC78xxCounterfactualRescue`)**: The token contract (e.g., `Binance-Peg USDC`, `USDC`, `USDT`, `OFT`) includes the `rescueCounterfactualEraVM` function in its implementation.
  2. **Chain-Level Adoption (`EIP-7702-Counterfactual` / BEP Precompile)**: The destination chain adds a system precompile that sets an EIP-7702 delegation designator (`0xef0100 || owner_EOA`) on `stuckWallet` upon verifying the 160-byte counterfactual preimage signed by `owner_EOA`.
- **WARNING**: Until a destination chain or token contract deploys this module on mainnet, sending real mainnet funds to a cross-VM counterfactual address will still freeze those funds on mainnet. All testing MUST be performed on local forks or testnets ($0 cost).
