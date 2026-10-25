#!/usr/bin/env python3
"""
End-to-End Verification & Simulation of CounterfactualPreimageRescue
Using Real On-Chain Data from the Abstract -> BNB Smart Chain $19,998 USDC Case:
  - Stuck Wallet on BSC: 0x6ae0145e60b073e8c47b922f16c0f9e71e3efa86
  - True Owner EOA:      0x07c65fe9f29a86b937604fa8d20a3fae19d7be48
  - BSC Transaction:     0x512b66bef7392f9d1dd8fc3a9ee9234bd87dfdb7b0cd5c0395010f6576491f20
  - Abstract Creation:   0xcdb63bfcbb7eab1f404dc9de6b79e787048f38307b1abce9fa5557405d7d5b9f
"""

# Pure-Python Keccak-256 (Ethereum / EVM standard)
RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rol64(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def keccak256(msg: bytes) -> bytes:
    rate = 136
    padded = bytearray(msg)
    padded.append(0x01)
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] |= 0x80
    S = [[0] * 5 for _ in range(5)]
    for off in range(0, len(padded), rate):
        for i in range(rate // 8):
            S[i % 5][i // 5] ^= int.from_bytes(padded[off + 8 * i : off + 8 * i + 8], "little")
        for r in range(24):
            C = [S[x][0] ^ S[x][1] ^ S[x][2] ^ S[x][3] ^ S[x][4] for x in range(5)]
            D = [C[(x - 1) % 5] ^ _rol64(C[(x + 1) % 5], 1) for x in range(5)]
            S = [[S[x][y] ^ D[x] for y in range(5)] for x in range(5)]
            B = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    B[y][(2 * x + 3 * y) % 5] = _rol64(S[x][y], ROT[x][y])
            S = [[B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
            S[0][0] ^= RC[r]
    return b"".join(S[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


class SimulatedTokenWithCounterfactualRescue:
    ZKSYNC_CREATE2_PREFIX = keccak256(b"zksyncCreate2")

    def __init__(self):
        self.balances = {}
        self.code = {}

    @classmethod
    def compute_eravm_counterfactual_address(
        cls,
        owner_eoa: str,
        factory: str,
        proxy_bytecode_hash: str,
        implementation: str,
    ) -> str:
        owner_bytes = bytes.fromhex(owner_eoa[2:].lower())
        assert len(owner_bytes) == 20
        salt = keccak256(owner_bytes)

        factory_padded = bytes.fromhex(factory[2:].lower()).rjust(32, b"\x00")
        bytecode_hash_bytes = bytes.fromhex(proxy_bytecode_hash[2:].lower())
        impl_padded = bytes.fromhex(implementation[2:].lower()).rjust(32, b"\x00")
        constructor_input_hash = keccak256(impl_padded)

        preimage = (
            cls.ZKSYNC_CREATE2_PREFIX
            + factory_padded
            + salt
            + bytecode_hash_bytes
            + constructor_input_hash
        )
        assert len(preimage) == 160
        digest = keccak256(preimage)
        return "0x" + digest[12:].hex()

    def rescue_from_eravm_counterfactual(
        self,
        msg_sender: str,
        factory: str,
        proxy_bytecode_hash: str,
        implementation: str,
        recipient: str,
    ):
        stuck_wallet = self.compute_eravm_counterfactual_address(
            owner_eoa=msg_sender,
            factory=factory,
            proxy_bytecode_hash=proxy_bytecode_hash,
            implementation=implementation,
        )
        if self.code.get(stuck_wallet.lower(), b"") != b"":
            raise RuntimeError(f"AddressIsActiveContract({stuck_wallet})")

        amount = self.balances.get(stuck_wallet.lower(), 0)
        if amount == 0:
            raise RuntimeError(
                f"NothingToRescue: msg.sender={msg_sender} derived address={stuck_wallet} (balance=0)"
            )

        self.balances[stuck_wallet.lower()] = 0
        self.balances[recipient.lower()] = self.balances.get(recipient.lower(), 0) + amount
        return stuck_wallet, amount


def main():
    # Exact on-chain constants from Abstract Mainnet & BNB Smart Chain
    STUCK_WALLET = "0x6ae0145e60b073e8c47b922f16c0f9e71e3efa86"
    TRUE_OWNER_EOA = "0x07c65fe9f29a86b937604fa8d20a3fae19d7be48"
    ATTACKER_EOA = "0xdeadbeef000000000000000000000000deadbeef"
    AGW_FACTORY = "0x9b947df68d35281c972511b3e7bc875926f26c1a"
    PROXY_BYTECODE_HASH = "0x0100003316a98e88b9e8931575675eed8e30eee97abeff3816fb98333ab085bc"
    AGW_IMPLEMENTATION = "0xaa3633b417483f932969edaef7cc4f1068f6faa9"
    LOCKED_USDC = 19_998_000000000000000000  # 19,998.00 USDC (18 decimals on BSC)

    token = SimulatedTokenWithCounterfactualRescue()
    token.balances[STUCK_WALLET.lower()] = LOCKED_USDC

    print("=" * 72)
    print("COUNTERFACTUAL PREIMAGE RECOVERY — ON-CHAIN DATA SIMULATION")
    print("=" * 72)
    print(f"Initial Stuck Balance at {STUCK_WALLET}: {token.balances[STUCK_WALLET.lower()] / 1e18:,.2f} USDC\n")

    # Test 1: Attacker attempts to steal the stuck funds
    print("[Test 1] Attacker (0xdeadbeef...) tries calling rescueFromEraVMCounterfactual:")
    try:
        token.rescue_from_eravm_counterfactual(
            msg_sender=ATTACKER_EOA,
            factory=AGW_FACTORY,
            proxy_bytecode_hash=PROXY_BYTECODE_HASH,
            implementation=AGW_IMPLEMENTATION,
            recipient=ATTACKER_EOA,
        )
        raise AssertionError("Attacker should have failed!")
    except RuntimeError as err:
        print(f"  -> REVERTED as expected: {err}")
        print(f"  -> Balance at {STUCK_WALLET} remains: {token.balances[STUCK_WALLET.lower()] / 1e18:,.2f} USDC\n")

    # Test 2: True Key Owner (0x07c65f...) calls rescueFromEraVMCounterfactual
    print(f"[Test 2] True Owner ({TRUE_OWNER_EOA}) calls rescueFromEraVMCounterfactual:")
    rescued_from, rescued_amt = token.rescue_from_eravm_counterfactual(
        msg_sender=TRUE_OWNER_EOA,
        factory=AGW_FACTORY,
        proxy_bytecode_hash=PROXY_BYTECODE_HASH,
        implementation=AGW_IMPLEMENTATION,
        recipient=TRUE_OWNER_EOA,
    )
    print(f"  -> SUCCESS! Verified counterfactual address: {rescued_from}")
    print(f"  -> Rescued Amount: {rescued_amt / 1e18:,.2f} USDC")
    print(f"  -> New Balance at Stuck Wallet ({STUCK_WALLET}): {token.balances[STUCK_WALLET.lower()] / 1e18:,.2f} USDC")
    print(f"  -> New Balance at True Owner ({TRUE_OWNER_EOA}): {token.balances[TRUE_OWNER_EOA.lower()] / 1e18:,.2f} USDC")
    print("=" * 72)


if __name__ == "__main__":
    main()
