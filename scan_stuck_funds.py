#!/usr/bin/env python3
"""
Multi-Chain Stuck Counterfactual Wallet Scanner
===============================================
Given either:
  1. An EOA Owner address (`--owner 0x...`), OR
  2. A known EraVM / AA Smart Wallet address (`--wallet 0x...`)

This tool:
  - Derives the deterministic EraVM (`zksyncCreate2`) counterfactual address from the EOA owner
  - Queries live EVM chains (BNB Smart Chain, Ethereum, Base, Arbitrum)
  - Detects when funds (Native ETH/BNB + USDC/USDT) are trapped at an address where `eth_getCode == 0x`
"""

import argparse
import json
import urllib.request

from test_rescue_poc import SimulatedTokenWithCounterfactualRescue, keccak256

AGW_DEFAULT_FACTORY = "0x9b947df68d35281c972511b3e7bc875926f26c1a"
AGW_DEFAULT_BYTECODE_HASH = "0x0100003316a98e88b9e8931575675eed8e30eee97abeff3816fb98333ab085bc"
AGW_DEFAULT_IMPLEMENTATION = "0xaa3633b417483f932969edaef7cc4f1068f6faa9"

EVM_CHAINS = {
    "BNB Smart Chain (BSC)": {
        "rpc": "https://bsc-dataseed1.defibit.io/",
        "native_symbol": "BNB",
        "tokens": {
            "USDC": ("0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d", 18),
            "USDT": ("0x55d398326f99059ff775485246999027b3197955", 18),
        },
    },
    "Base Mainnet": {
        "rpc": "https://mainnet.base.org",
        "native_symbol": "ETH",
        "tokens": {
            "USDC": ("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", 6),
        },
    },
    "Arbitrum One": {
        "rpc": "https://arb1.arbitrum.io/rpc",
        "native_symbol": "ETH",
        "tokens": {
            "USDC": ("0xaf88d065e77c8cC2239327C5EDb3A432268e5831", 6),
            "USDT": ("0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", 6),
        },
    },
}


def rpc_call(url: str, method: str, params: list):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "curl/8.0.1"},
    )
    with urllib.request.urlopen(req, timeout=12) as resp:
        return json.loads(resp.read().decode())


def scan_address_across_chains(wallet_addr: str):
    addr_clean = wallet_addr.lower()
    padded_addr = "0x70a08231" + addr_clean[2:].rjust(64, "0")

    print("=" * 72)
    print(f"SCANNING COUNTERFACTUAL WALLET ACROSS EVM CHAINS: {wallet_addr}")
    print("=" * 72)

    for chain_name, cfg in EVM_CHAINS.items():
        rpc = cfg["rpc"]
        try:
            code_res = rpc_call(rpc, "eth_getCode", [wallet_addr, "latest"]).get("result", "0x")
            bal_res = rpc_call(rpc, "eth_getBalance", [wallet_addr, "latest"]).get("result", "0x0")
            native_bal = int(bal_res, 16) / 1e18
            has_code = code_res not in ("0x", "0x0", "")

            token_balances = {}
            for sym, (taddr, dec) in cfg["tokens"].items():
                tres = rpc_call(rpc, "eth_call", [{"to": taddr, "data": padded_addr}, "latest"]).get("result", "0x0")
                if tres and tres != "0x":
                    tval = int(tres, 16) / (10 ** dec)
                    if tval > 0:
                        token_balances[sym] = tval

            status = "DEPLOYED CONTRACT" if has_code else "UNDEPLOYED (COUNTERFACTUAL / TRAPPED IF FUNDED)"
            print(f"\n[{chain_name}]")
            print(f"  Code Status : {status}")
            print(f"  Native Bal  : {native_bal:.6f} {cfg['native_symbol']}")
            for sym, val in token_balances.items():
                print(f"  TRAPPED {sym:<4}: {val:,.2f} {sym}  <-- STUCK COUNTERFACTUAL FUNDS DETECTED!")
            if not token_balances and native_bal == 0:
                print("  Token Bal   : 0.00")
        except Exception as err:
            print(f"\n[{chain_name}] RPC Error: {err}")
    print("=" * 72)


def main():
    parser = argparse.ArgumentParser(description="Scan stuck counterfactual funds across EVM chains")
    parser.add_argument(
        "--owner",
        default="0x07c65fe9f29a86b937604fa8d20a3fae19d7be48",
        help="EOA owner address that created the EraVM smart wallet",
    )
    parser.add_argument(
        "--wallet",
        default=None,
        help="Direct smart wallet address to scan (optional; derived from --owner if omitted)",
    )
    args = parser.parse_args()

    if args.wallet:
        target_wallet = args.wallet
    else:
        target_wallet = SimulatedTokenWithCounterfactualRescue.compute_eravm_counterfactual_address(
            owner_eoa=args.owner,
            factory=AGW_DEFAULT_FACTORY,
            proxy_bytecode_hash=AGW_DEFAULT_BYTECODE_HASH,
            implementation=AGW_DEFAULT_IMPLEMENTATION,
        )
        print(f"Owner EOA              : {args.owner}")
        print(f"Salt = keccak256(EOA)  : 0x{keccak256(bytes.fromhex(args.owner[2:])).hex()}")
        print(f"Derived EraVM Wallet   : {target_wallet}\n")

    scan_address_across_chains(target_wallet)


if __name__ == "__main__":
    main()
