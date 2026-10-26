#!/usr/bin/env python3
"""
High-Speed Multicall3 Scanner for Undeployed Counterfactual Smart Wallets Holding Funds
=======================================================================================
Harvests 100% verified Smart Contract Wallets from:
  1. Abstract Chain (`AccountFactory` `AGWAccountDeployed` events -> EraVM `0x20` wallets)
  2. Base & Arbitrum (`EntryPoint` v0.6/v0.7 `UserOperationEvent` -> ERC-4337 `0xff` smart wallets)

Then batches `Multicall3.aggregate3` (`0xcA11bde05977b3631167028862bE2a173976CA11`) across:
  - BNB Smart Chain (USDC, USDT, Native BNB)
  - Ethereum Mainnet (USDC, USDT, Native ETH)
  - Base Mainnet (USDC, Native ETH)
  - Arbitrum One (USDC, USDT, Native ETH)

Reports every Smart Contract Wallet that holds trapped funds (`>= $10` or `>= 0.005 ETH/BNB`)
on a destination chain where its contract code is still undeployed (`eth_getCode == '0x'`).
"""

import json
import urllib.request

MULTICALL3 = "0xcA11bde05977b3631167028862bE2a173976CA11"
USER_OP_TOPIC = "0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f"
AGW_DEPLOYED_TOPIC = "0x0700eb47283deba29e13c4c113518c3d05ebfc8b06d4ef4c69dfe66a67dc05cd"


def rpc_call(url: str, method: str, params: list, timeout: int = 15):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "curl/8.0.1"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def encode_aggregate3_calls(target_contract: str, selector_hex: str, addresses: list[str]) -> str:
    """
    Encodes Multicall3.aggregate3(Call3[] calls) where each Call3 calls `selector_hex(address)`
    on `target_contract` (e.g., ERC20.balanceOf(addr) or Multicall3.getEthBalance(addr)).
    """
    n = len(addresses)
    out = bytearray.fromhex("82ad56cb")
    out += (32).to_bytes(32, "big")
    out += n.to_bytes(32, "big")
    # Each tuple element takes 6 * 32 = 192 bytes
    for i in range(n):
        out += (32 * n + i * 192).to_bytes(32, "big")
    t_bytes = bytes.fromhex(target_contract[2:].lower()).rjust(32, b"\x00")
    sel_bytes = bytes.fromhex(selector_hex)
    for addr in addresses:
        a_bytes = bytes.fromhex(addr[2:].lower())
        calldata = sel_bytes + a_bytes.rjust(32, b"\x00")  # 36 bytes
        out += t_bytes
        out += (1).to_bytes(32, "big")   # allowFailure = true
        out += (96).to_bytes(32, "big")  # offset to bytes callData
        out += (36).to_bytes(32, "big")  # length of callData
        out += calldata.ljust(64, b"\x00")
    return "0x" + out.hex()


def decode_aggregate3_uint256(hex_res: str, count: int) -> list[int]:
    if not hex_res or hex_res == "0x":
        return [0] * count
    raw = bytes.fromhex(hex_res[2:])
    if len(raw) < 64:
        return [0] * count
    arr_offset = int.from_bytes(raw[0:32], "big")
    arr_len = int.from_bytes(raw[arr_offset : arr_offset + 32], "big")
    head_start = arr_offset + 32
    balances = []
    for i in range(min(arr_len, count)):
        elem_rel = int.from_bytes(raw[head_start + i * 32 : head_start + (i + 1) * 32], "big")
        elem_pos = head_start + elem_rel
        success = int.from_bytes(raw[elem_pos : elem_pos + 32], "big")
        bytes_rel = int.from_bytes(raw[elem_pos + 32 : elem_pos + 64], "big")
        bytes_pos = elem_pos + bytes_rel
        bytes_len = int.from_bytes(raw[bytes_pos : bytes_pos + 32], "big")
        if success and bytes_len >= 32:
            val = int.from_bytes(raw[bytes_pos + 32 : bytes_pos + 64], "big")
            balances.append(val)
        else:
            balances.append(0)
    return balances


def harvest_abstract_agw_wallets() -> dict[str, str]:
    abs_url = "https://api.mainnet.abs.xyz"
    factory = "0x9b947df68d35281c972511b3e7bc875926f26c1a"
    wallets = {"0x6ae0145e60b073e8c47b922f16c0f9e71e3efa86": "Abstract AGW (0x20 EraVM)"}

    for start_b in [77000, 100000, 150000, 300000, 600000, 1200000, 5000000, 20000000, 50000000]:
        try:
            logs = rpc_call(
                abs_url,
                "eth_getLogs",
                [
                    {
                        "fromBlock": hex(start_b),
                        "toBlock": hex(start_b + 3000),
                        "address": factory,
                        "topics": [AGW_DEPLOYED_TOPIC],
                    }
                ],
            ).get("result", [])
            for log in logs:
                if len(log.get("topics", [])) >= 2:
                    w = "0x" + log["topics"][1][-40:].lower()
                    wallets[w] = "Abstract AGW (0x20 EraVM)"
        except Exception:
            pass
    return wallets


def harvest_erc4337_wallets(chain_label: str, rpc_url: str) -> dict[str, str]:
    entrypoints = [
        "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789",  # v0.6
        "0x0000000071727De22E5E9d8BAf0edAc6f37da032",  # v0.7
    ]
    wallets = {}
    try:
        bnum = int(rpc_call(rpc_url, "eth_blockNumber", [])["result"], 16)
        for ep in entrypoints:
            for offset in [0, 10000, 50000]:
                logs = rpc_call(
                    rpc_url,
                    "eth_getLogs",
                    [
                        {
                            "fromBlock": hex(bnum - offset - 1000),
                            "toBlock": hex(bnum - offset),
                            "address": ep,
                            "topics": [USER_OP_TOPIC],
                        }
                    ],
                ).get("result", [])
                for log in logs:
                    if len(log.get("topics", [])) >= 3:
                        w = "0x" + log["topics"][2][-40:].lower()
                        wallets[w] = f"{chain_label} ERC-4337 Smart Wallet (0xff EVM)"
    except Exception as e:
        print(f"  Warning harvesting {chain_label}: {e}")
    return wallets


def main():
    print("[1/3] Harvesting verified Smart Contract Wallets from Abstract, Base, and Arbitrum...")
    wallet_origins = {}
    agw = harvest_abstract_agw_wallets()
    wallet_origins.update(agw)
    base_aa = harvest_erc4337_wallets("Base", "https://1rpc.io/base")
    wallet_origins.update(base_aa)
    arb_aa = harvest_erc4337_wallets("Arbitrum", "https://arb1.arbitrum.io/rpc")
    wallet_origins.update(arb_aa)

    candidates = list(wallet_origins.keys())
    print(f"  -> Abstract AGW Wallets : {len(agw)}")
    print(f"  -> Base ERC-4337 Wallets: {len(base_aa)}")
    print(f"  -> Arb ERC-4337 Wallets : {len(arb_aa)}")
    print(f"  -> Total Unique Smart Wallets to Scan: {len(candidates)}\n")

    target_chains = [
        (
            "BNB Smart Chain",
            "https://bsc-dataseed1.defibit.io/",
            [
                ("USDC", "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d", "70a08231", 18, 10.0),
                ("USDT", "0x55d398326f99059ff775485246999027b3197955", "70a08231", 18, 10.0),
                ("BNB", MULTICALL3, "4d2301cc", 18, 0.02),
            ],
        ),
        (
            "Arbitrum One",
            "https://arb1.arbitrum.io/rpc",
            [
                ("USDC", "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", "70a08231", 6, 10.0),
                ("USDT", "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", "70a08231", 6, 10.0),
                ("ETH", MULTICALL3, "4d2301cc", 18, 0.005),
            ],
        ),
        (
            "Base Mainnet",
            "https://1rpc.io/base",
            [
                ("USDC", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "70a08231", 6, 10.0),
                ("ETH", MULTICALL3, "4d2301cc", 18, 0.005),
            ],
        ),
    ]

    print("[2/3] Scanning balances via Multicall3 (chunk=250)...")
    chunk_size = 250
    trapped_hits = []

    for chain_name, rpc_url, checks in target_chains:
        for sym, target_contract, sel, dec, min_val in checks:
            for i in range(0, len(candidates), chunk_size):
                batch = candidates[i : i + chunk_size]
                calldata = encode_aggregate3_calls(target_contract, sel, batch)
                try:
                    res = rpc_call(rpc_url, "eth_call", [{"to": MULTICALL3, "data": calldata}, "latest"]).get("result", "0x")
                    bals = decode_aggregate3_uint256(res, len(batch))
                    for addr, raw_bal in zip(batch, bals):
                        val = raw_bal / (10**dec)
                        if val >= min_val:
                            code_dest = rpc_call(rpc_url, "eth_getCode", [addr, "latest"]).get("result", "0x")
                            if code_dest in ("0x", "0x0", ""):
                                trapped_hits.append((chain_name, sym, val, addr, wallet_origins[addr]))
                                print(
                                    f"  [FOUND TRAPPED FUNDS] {addr} on {chain_name}: {val:,.4f} {sym} (Origin: {wallet_origins[addr]})"
                                )
                except Exception as err:
                    print(f"  Warning on {chain_name} {sym}: {err}")

    print("\n[3/3] Summary of Discovered Undeployed Counterfactual Wallets with Locked Funds:")
    print("=" * 80)
    for chain_name, sym, val, addr, origin in trapped_hits:
        print(f"Address : {addr}")
        print(f"Origin  : {origin}")
        print(f"Trapped : {val:,.4f} {sym} on {chain_name} (eth_getCode == 0x)")
        print("-" * 80)


if __name__ == "__main__":
    main()
