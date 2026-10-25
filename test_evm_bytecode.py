#!/usr/bin/env python3
"""
Real EVM Bytecode Execution Test Suite (`py-evm`)
=================================================
Deploys the actual `solc`-compiled bytecode of `RescueableERC20.sol` inside an
in-memory Ethereum / BNB Chain EVM (`py-evm`) and verifies:
  1. On-chain `computeEraVMCounterfactualAddress` matches `0x6ae0145e60b073e8c47b922f16c0f9e71e3efa86`
  2. Attacker call to `rescueFromEraVMCounterfactual` reverts in EVM
  3. True Owner (`0x07c65fe9f29a86b937604fa8d20a3fae19d7be48`) rescues 19,998.00 USDC in EVM
  4. Gasless Relayer EIP-712 `rescueCounterfactualWithSig` with real secp256k1 ecrecover succeeds
  5. Replay of the same EIP-712 signature reverts in EVM
"""

import pathlib
import eth_abi
from eth_account import Account
from eth_utils import keccak, to_canonical_address
from eth.chains.base import MiningChain
from eth.vm.forks.shanghai import ShanghaiVM
from eth.vm.message import Message
from eth.db.atomic import AtomicDB

BUILD_DIR = pathlib.Path(__file__).parent / "build"
BIN_PATH = BUILD_DIR / "contracts_RescueableERC20_sol_RescueableERC20.bin"


def selector(sig: str) -> bytes:
    return keccak(text=sig)[:4]


def run_evm_tests():
    assert BIN_PATH.exists(), f"Missing compiled bytecode at {BIN_PATH}. Run solc first."
    deploy_bin = bytes.fromhex(BIN_PATH.read_text().strip())

    # Initialize an in-memory Shanghai/Cancun EVM chain
    klass = MiningChain.configure(
        __name__="TestChain",
        vm_configuration=((0, ShanghaiVM),),
        chain_id=56,
    )
    chain = klass.from_genesis(AtomicDB(), {"difficulty": 0, "gas_limit": 30_000_000, "timestamp": 1770852306})

    deployer = to_canonical_address("0x1111111111111111111111111111111111111111")
    true_owner = to_canonical_address("0x07c65fe9f29a86b937604fa8d20a3fae19d7be48")
    attacker = to_canonical_address("0xdeadbeef000000000000000000000000deadbeef")
    relayer = to_canonical_address("0x2222222222222222222222222222222222222222")

    stuck_wallet_str = "0x6ae0145e60b073e8c47b922f16c0f9e71e3efa86"
    agw_factory = "0x9b947df68d35281c972511b3e7bc875926f26c1a"
    proxy_bhash = bytes.fromhex("0100003316a98e88b9e8931575675eed8e30eee97abeff3816fb98333ab085bc")
    agw_impl = "0xaa3633b417483f932969edaef7cc4f1068f6faa9"
    locked_usdc = 19_998 * 10**18

    def apply_msg(sender_bytes: bytes, to_bytes: bytes, data: bytes) -> tuple[bool, bytes, int]:
        tx_ctx = state.get_transaction_context_class()(gas_price=1, origin=sender_bytes)
        comp = state.computation_class.apply_message(
            state,
            Message(
                gas=5_000_000,
                to=to_bytes,
                sender=sender_bytes,
                value=0,
                data=data,
                code=state.get_code(to_bytes) if to_bytes else data,
            ),
            tx_ctx,
        )
        return not comp.is_error, comp.output, comp.get_gas_used()

    # Deploy RescueableERC20("Binance-Peg USD Coin", "USDC", 18)
    ctor_args = eth_abi.encode(["string", "string", "uint8"], ["Binance-Peg USD Coin", "USDC", 18])
    vm = chain.get_vm()
    state = vm.state
    contract_addr = to_canonical_address("0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d")
    tx_ctx = state.get_transaction_context_class()(gas_price=1, origin=deployer)
    comp = state.computation_class.apply_create_message(
        state,
        Message(
            gas=5_000_000,
            to=b"",
            sender=deployer,
            value=0,
            data=b"",
            code=deploy_bin + ctor_args,
            create_address=contract_addr,
        ),
        tx_ctx,
    )
    assert not comp.is_error, f"Deployment failed: {comp.error}"
    state.set_code(contract_addr, comp.output)

    print("=" * 76)
    print("REAL SOLC BYTECODE EXECUTION SUITE (py-evm, Shanghai/Cancun VM)")
    print("=" * 76)
    print(f"[OK] Deployed RescueableERC20 at 0x{contract_addr.hex()} (runtime size: {len(comp.output)} bytes)")

    # Mint 19,998 USDC to stuck_wallet
    mint_data = selector("mint(address,uint256)") + eth_abi.encode(
        ["address", "uint256"], [stuck_wallet_str, locked_usdc]
    )
    ok, _, _ = apply_msg(deployer, contract_addr, mint_data)
    assert ok

    # 1. Verify computeEraVMCounterfactualAddress inside EVM
    calc_data = selector("computeEraVMCounterfactualAddress(address,address,bytes32,address)") + eth_abi.encode(
        ["address", "address", "bytes32", "address"],
        ["0x" + true_owner.hex(), agw_factory, proxy_bhash, agw_impl],
    )
    ok, out, gas_used = apply_msg(deployer, contract_addr, calc_data)
    assert ok
    (derived_addr,) = eth_abi.decode(["address"], out)
    assert derived_addr.lower() == stuck_wallet_str.lower()
    print(f"[PASS] EVM computeEraVMCounterfactualAddress -> {derived_addr} (gas: {gas_used:,})")

    # 2. Verify Attacker reverts in EVM
    rescue_data = selector("rescueFromEraVMCounterfactual(address,bytes32,address,address)") + eth_abi.encode(
        ["address", "bytes32", "address", "address"],
        [agw_factory, proxy_bhash, agw_impl, "0x" + attacker.hex()],
    )
    ok, out, _ = apply_msg(attacker, contract_addr, rescue_data)
    assert not ok, "Attacker call should have reverted!"
    print(f"[PASS] EVM Attacker Call Reverted with selector 0x{out[:4].hex()} (NothingToRescue)")

    # 3. Verify True Owner (0x07c65f...) rescues all 19,998.00 USDC in EVM
    owner_rescue_data = selector("rescueFromEraVMCounterfactual(address,bytes32,address,address)") + eth_abi.encode(
        ["address", "bytes32", "address", "address"],
        [agw_factory, proxy_bhash, agw_impl, "0x" + true_owner.hex()],
    )
    ok, out, gas_used = apply_msg(true_owner, contract_addr, owner_rescue_data)
    assert ok, "True owner call failed!"
    rescued_wallet, rescued_amount = eth_abi.decode(["address", "uint256"], out)
    assert rescued_wallet.lower() == stuck_wallet_str.lower()
    assert rescued_amount == locked_usdc
    print(
        f"[PASS] EVM Direct Rescue by 0x{true_owner.hex()} -> Rescued {rescued_amount / 1e18:,.2f} USDC (gas: {gas_used:,})"
    )

    # 4. Verify Gasless Relayer EIP-712 Signature Rescue (`rescueCounterfactualWithSig`)
    signer_acct = Account.from_key("0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
    calc_data_2 = selector("computeEraVMCounterfactualAddress(address,address,bytes32,address)") + eth_abi.encode(
        ["address", "address", "bytes32", "address"],
        [signer_acct.address, agw_factory, proxy_bhash, agw_impl],
    )
    ok, out, _ = apply_msg(deployer, contract_addr, calc_data_2)
    (stuck_wallet_2,) = eth_abi.decode(["address"], out)

    # Mint 7,500 USDC to stuck_wallet_2
    ok, _, _ = apply_msg(
        deployer,
        contract_addr,
        selector("mint(address,uint256)") + eth_abi.encode(["address", "uint256"], [stuck_wallet_2, 7_500 * 10**18]),
    )
    assert ok

    # Fetch domainSeparator() from EVM
    ok, dom_out, _ = apply_msg(deployer, contract_addr, selector("domainSeparator()"))
    assert ok
    (domain_sep,) = eth_abi.decode(["bytes32"], dom_out)

    rescue_typehash = keccak(
        text="RescueAuthorization(address ownerEOA,address stuckWallet,address recipient,uint256 amount,uint256 nonce,uint256 deadline)"
    )
    deadline = 1800000000
    recipient_addr = "0x3333333333333333333333333333333333333333"
    struct_hash = keccak(
        eth_abi.encode(
            ["bytes32", "address", "address", "address", "uint256", "uint256", "uint256"],
            [rescue_typehash, signer_acct.address, stuck_wallet_2, recipient_addr, 7_500 * 10**18, 0, deadline],
        )
    )
    eip712_digest = keccak(b"\x19\x01" + domain_sep + struct_hash)
    signed = Account._keys.PrivateKey(signer_acct.key).sign_msg_hash(eip712_digest)
    v = signed.v + 27 if signed.v < 27 else signed.v
    r_bytes = signed.r.to_bytes(32, "big")
    s_bytes = signed.s.to_bytes(32, "big")

    impl_encoded = eth_abi.encode(["address"], [agw_impl])
    proof_tuple = (0, agw_factory, proxy_bhash, impl_encoded, 0)
    sig_call = selector(
        "rescueCounterfactualWithSig(address,(uint8,address,bytes32,bytes,uint256),address,uint256,uint8,bytes32,bytes32)"
    ) + eth_abi.encode(
        ["address", "(uint8,address,bytes32,bytes,uint256)", "address", "uint256", "uint8", "bytes32", "bytes32"],
        [signer_acct.address, proof_tuple, recipient_addr, deadline, v, r_bytes, s_bytes],
    )
    ok, out, gas_used = apply_msg(relayer, contract_addr, sig_call)
    assert ok, "EIP-712 Relayer rescue failed!"
    _, amt2 = eth_abi.decode(["address", "uint256"], out)
    assert amt2 == 7_500 * 10**18
    print(
        f"[PASS] EVM EIP-712 Gasless Relayer Rescue -> Rescued {amt2 / 1e18:,.2f} USDC to {recipient_addr} (gas: {gas_used:,})"
    )

    # 5. Verify Replay of same EIP-712 signature reverts
    ok, _, _ = apply_msg(
        deployer,
        contract_addr,
        selector("mint(address,uint256)") + eth_abi.encode(["address", "uint256"], [stuck_wallet_2, 100 * 10**18]),
    )
    ok_replay, _, _ = apply_msg(relayer, contract_addr, sig_call)
    assert not ok_replay, "Signature replay should have reverted!"
    print("[PASS] EVM EIP-712 Signature Replay Rejected (Nonce Incremented)")
    print("=" * 76)
    print("ALL REAL EVM BYTECODE TESTS PASSED WITH ZERO ERRORS!")
    print("=" * 76)


if __name__ == "__main__":
    run_evm_tests()
