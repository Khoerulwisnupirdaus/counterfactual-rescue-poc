// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title CounterfactualPreimageRescue
 * @notice Zero-trust cryptographic recovery module for funds trapped in cross-VM
 *         counterfactual smart wallet addresses (e.g., Abstract Global Wallet / ZKsync EraVM
 *         addresses on standard EVM chains like BNB Smart Chain, Ethereum, Base, Arbitrum).
 *
 * @dev Mathematical Security Proof:
 *      An EraVM CREATE2 address is derived as:
 *        addr = keccak256(
 *            0x2020dba91b30cc0006188af794c2fb30dd8520db7e2c088b7fc7c103c00ca494 || // keccak256("zksyncCreate2")
 *            bytes32(uint256(uint160(factory))) ||
 *            keccak256(abi.encodePacked(ownerEOA)) ||                                // salt commits to ownerEOA
 *            proxyBytecodeHash ||
 *            keccak256(abi.encode(implementation))
 *        )[12..32]
 *
 *      Because `salt` is computed directly from `msg.sender` (the EOA private key holder),
 *      no other address `attacker != msg.sender` can produce `addr` without breaking
 *      160-bit second-preimage resistance of Keccak-256 (2^160 security).
 */
abstract contract CounterfactualPreimageRescue {
    /// @notice keccak256("zksyncCreate2") constant used by all ZKsync Stack / EraVM chains (Abstract, ZKsync Era, etc.)
    bytes32 public constant ZKSYNC_CREATE2_PREFIX =
        0x2020dba91b30cc0006188af794c2fb30dd8520db7e2c088b7fc7c103c00ca494;

    /// @notice Emitted when trapped tokens are cryptographically rescued by the verified counterfactual owner
    event CounterfactualFundsRescued(
        address indexed stuckWallet,
        address indexed verifiedOwner,
        address indexed recipient,
        uint256 amount
    );

    error AddressIsActiveContract(address target);
    error NothingToRescue(address target);
    error InvalidRecipient();

    /**
     * @notice Computes the exact EraVM counterfactual wallet address for a given EOA owner and factory parameters.
     * @param ownerEOA The 20-byte EOA address that owns the counterfactual wallet (committed via salt = keccak256(ownerEOA))
     * @param factory The AccountFactory contract address on the origin EraVM chain
     * @param proxyBytecodeHash The EraVM bytecode hash of the account proxy
     * @param implementation The implementation contract address encoded in the proxy constructor input
     * @return stuckWallet The deterministically derived 20-byte address
     */
    function computeEraVMCounterfactualAddress(
        address ownerEOA,
        address factory,
        bytes32 proxyBytecodeHash,
        address implementation
    ) public pure returns (address stuckWallet) {
        bytes32 salt = keccak256(abi.encodePacked(ownerEOA));
        bytes32 constructorInputHash = keccak256(abi.encode(implementation));

        bytes32 digest = keccak256(
            bytes.concat(
                ZKSYNC_CREATE2_PREFIX,
                bytes32(uint256(uint160(factory))),
                salt,
                proxyBytecodeHash,
                constructorInputHash
            )
        );

        stuckWallet = address(uint160(uint256(digest)));
    }

    /**
     * @notice Self-service, zero-trust rescue of tokens trapped at an EraVM counterfactual address on an EVM chain.
     * @dev Only the holder of `msg.sender` whose address hashes into the preimage of `stuckWallet` can rescue its balance.
     * @param factory The AccountFactory address on the origin EraVM chain
     * @param proxyBytecodeHash The EraVM bytecode hash of the account proxy
     * @param implementation The implementation contract address on the origin EraVM chain
     * @param recipient The destination address on this EVM chain to receive the rescued tokens
     * @return stuckWallet The counterfactual address from which funds were rescued
     * @return rescuedAmount The amount of tokens rescued
     */
    function rescueFromEraVMCounterfactual(
        address factory,
        bytes32 proxyBytecodeHash,
        address implementation,
        address recipient
    ) external returns (address stuckWallet, uint256 rescuedAmount) {
        if (recipient == address(0)) revert InvalidRecipient();

        // 1. Reconstruct the counterfactual address using msg.sender as the cryptographically committed owner EOA
        stuckWallet = computeEraVMCounterfactualAddress(
            msg.sender,
            factory,
            proxyBytecodeHash,
            implementation
        );

        // 2. Ensure the address has no deployed EVM bytecode on this chain
        if (stuckWallet.code.length != 0) {
            revert AddressIsActiveContract(stuckWallet);
        }

        // 3. Check and transfer the trapped balance to the verified owner's chosen recipient
        rescuedAmount = _getBalance(stuckWallet);
        if (rescuedAmount == 0) {
            revert NothingToRescue(stuckWallet);
        }

        _rescueTransfer(stuckWallet, recipient, rescuedAmount);

        emit CounterfactualFundsRescued(stuckWallet, msg.sender, recipient, rescuedAmount);
    }

    /// @dev Implemented by the inheriting ERC-20 / BEP-20 token contract
    function _getBalance(address account) internal view virtual returns (uint256);

    /// @dev Implemented by the inheriting ERC-20 / BEP-20 token contract
    function _rescueTransfer(address from, address to, uint256 amount) internal virtual;
}
