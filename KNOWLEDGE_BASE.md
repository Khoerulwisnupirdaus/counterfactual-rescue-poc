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

## 5. Forensic Inbound Transaction Trace (Root-Cause Protocols)

Using [`trace_inbound_txs.py`](trace_inbound_txs.py), we traced the exact destination-chain blocks, transaction hashes, and bridge/off-ramp protocols that delivered funds into the top 8 trapped counterfactual wallets:

| # | Chain | Trapped Wallet (`code == 0x`) | Trapped Amount | Arrival Block | Inbound Tx Hash | Sender / Router Contract | Root-Cause Source Protocol |
| :- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | **BSC** | `0x6ae0145e60b073e8c47b922f16c0f9e71e3efa86` | **19,998.00 USDC** | `80681471` | `0x512b66bef7392f9d1dd8fc3a9ee9234bd87dfdb7b0cd5c0395010f6576491f20` | `0xe2fc31f816a9b94326492132018c3aecc4a93ae1` | **Binance Hot Wallet 20** (Direct CEX Withdrawal to `AGW` address) |
| 2 | **Base** | `0x87f5a13a9ef0d839df3be1c6317c2e54f1ca88d5` | **500.00 USDC** | `28218758` | `0xf47362bdc90eec1c50ba28bd5e08f4a07196a643b6b3d6611134d76dd54a7464` | `0x887749abb233682aa7d5594a54659c51501445b1` | **EIP-3009 Batch Relayer** (`receiveWithAuthorization` from `0x95ec8292...`) |
| 3 | **BSC** | `0x006e3a1b9c3b419761f2a7a0411cc37c0da453a7` | **333.41 USDT** | `63794694` | `0xa6294c3554e622dc2e1dff7993e23332ecd05d1fbd062a51efda56075a43efe6` | `0xe93685f3bba03016f02bd1828badd6195988d950` -> `0x3ebd570e...` | **Stargate V2 / LayerZero V2** (`lzReceive` from `srcEid=30324` Abstract Mainnet) |
| 4 | **Base** | `0xac3940699a89b5543bd855c899565d35e16fb4a9` | **238.32 USDC** | `27117222` | `0x72f2e1a8bdb26a2fd299b5f501ad34b3a75efef71c873fb7053b86d3248adeaf` | `0xf70da97812cb96acdf810712aa562db8dfa3dbef` | **Relay.link Solver** (Order ID `0xd77b0de0...5204557b`) |
| 5 | **Base** | `0xe8c90ca25ecaaed8711ad1bc9946bc9868e74926` | **0.0851 ETH** | `25980056` | `0xb0d7a1167b82e53b4d492f72edf73b201987a1bab19743e63ab1a31bd4e3c50c` | `0xe93685f3bba03016f02bd1828badd6195988d950` -> `0x2cca08ae...` | **Stargate V2 / LayerZero V2** (`lzReceive` from `srcEid=30324` Abstract Mainnet) |
| 6 | **Base** | `0x838c0891efa420de109e5d5daad7d34ea5a6cfdf` | **0.0576 ETH** | `37875988` | `0x7f4775c27ecfb9acdc7cc53fccd46d5c07911f42cd0b43195fdb3ea1be7dd7fb` | `0xf70da97812cb96acdf810712aa562db8dfa3dbef` -> `0xbbbfd134...` | **Relay.link Solver + Router** (`0xf5042e6ffac5a625d4e7848e0b01373d8eb9e222`) |
| 7 | **Arbitrum** | `0x79154987dbe24053eb8c63c02c57ecd663b7bdd9` | **62.30 USDC** | `311753197` | `0xc4728f4127e73915ebc3f412edfa985ab7a0d8c5ee67bd446310b955e109174a` | `0xf70da97812cb96acdf810712aa562db8dfa3dbef` | **Relay.link Solver** (Order ID `0x4ec0b36e...3a69a706`) |
| 8 | **Arbitrum** | `0x8e3d58d201a62bdac918c77c186b9990a5d01386` | **31.19 USDC** | `447713848` | `0x179789509e21dd24a272bb0f2a1aabbd9381102b99c93b784ad9a48b4aaa4340` | `0xf70da97812cb96acdf810712aa562db8dfa3dbef` | **Relay.link Solver** (Order ID `0x368982c2...48b5c8d0`) |

### Breakdown of Root Causes Across the Top 8 Cases
1. **Cross-Chain Intent Bridges (`Relay.link` — 50% of top cases, 4/8)**:
   - When an Abstract Global Wallet (`AGW`) user bridges out of Abstract (`chainId = 2741`) to Base or Arbitrum, if the `recipient` defaults to or is set to their `AGW` smart contract wallet address (`0x20` `zksyncCreate2` derivation), the Relay Solver (`0xf70da97812cb96acdf810712aa562db8dfa3dbef`) fulfills the order directly into the undeployed counterfactual address on the EVM destination chain.
2. **Omnichain Liquidity Bridges (`Stargate V2 / LayerZero V2` — 25% of top cases, 2/8)**:
   - When an `AGW` user bridges ETH or USDT from Abstract (`srcEid = 30324`) to Base or BNB Smart Chain via Stargate V2, `sendParam.to` defaults to `addressToBytes32(msg.sender)` (`stuckWallet`). Stargate's destination pool (`0xdc181bd6...` on Base, `0x138eb30f...` on BSC) delivers the tokens to `stuckWallet` where no contract can ever be deployed on EVM.
3. **CEX / Off-Ramp Withdrawals (`Binance Hot Wallet 20` & `EIP-3009 Relayer` — 25% of top cases, 2/8)**:
   - Users copy their `AGW` wallet address from Abstract UI and paste it as their withdrawal address on Binance (`19,998 USDC` on BSC) or Coinbase/EIP-3009 (`500 USDC` on Base).

---

## 6. Architectural Requirement (Important Constraint)
- This recovery mechanism requires either:
  1. **Token-Level Adoption (`IERC78xxCounterfactualRescue`)**: The token contract (e.g., `Binance-Peg USDC`, `USDC`, `USDT`, `OFT`) includes the `rescueCounterfactualEraVM` function in its implementation.
  2. **Chain-Level Adoption (`EIP-7702-Counterfactual` / BEP Precompile)**: The destination chain adds a system precompile that sets an EIP-7702 delegation designator (`0xef0100 || owner_EOA`) on `stuckWallet` upon verifying the 160-byte counterfactual preimage signed by `owner_EOA`.
- **WARNING**: Until a destination chain or token contract deploys this module on mainnet, sending real mainnet funds to a cross-VM counterfactual address will still freeze those funds on mainnet. All testing MUST be performed on local forks or testnets ($0 cost).
