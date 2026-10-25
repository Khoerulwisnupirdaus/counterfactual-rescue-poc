// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title CounterfactualPreimageRescue
 * @notice Production-grade, zero-trust cryptographic recovery module for assets trapped in
 *         cross-VM counterfactual smart accounts (EraVM zksyncCreate2 <-> EVM CREATE2).
 *
 * @dev Supports:
 *      1. Direct EOA rescue (`rescueCounterfactual`) — ~60 gas Keccak-256 preimage verification.
 *      2. Gasless / Relayer EIP-712 rescue (`rescueCounterfactualWithSig`) — for embedded signers
 *         (Privy/Turnkey/Passkey K1) or EOAs without native gas on the destination chain.
 *      3. Multiple canonical salt & VM derivation modes:
 *         - ERA_VM_PACKED_20:      salt = keccak256(abi.encodePacked(ownerEOA)) [Abstract AGW standard]
 *         - ERA_VM_ABI_32:         salt = keccak256(abi.encode(ownerEOA))       [32-byte padded standard]
 *         - ERA_VM_INDEXED:        salt = keccak256(abi.encodePacked(ownerEOA, accountIndex))
 *         - EVM_CREATE2_PACKED_20: 0xff || factory || keccak256(abi.encodePacked(ownerEOA)) || initCodeHash
 *                                  [For EVM smart wallets trapped on EraVM chains]
 */
abstract contract CounterfactualPreimageRescue {
    /// @notice keccak256("zksyncCreate2") — 32-byte domain prefix in EraVM ContractDeployer
    bytes32 public constant ZKSYNC_CREATE2_PREFIX =
        0x2020dba91b30cc0006188af794c2fb30dd8520db7e2c088b7fc7c103c00ca494;

    /// @notice EIP-712 Domain Typehash
    bytes32 public constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /// @notice EIP-712 RescueAuthorization Typehash
    bytes32 public constant RESCUE_AUTH_TYPEHASH =
        keccak256(
            "RescueAuthorization(address ownerEOA,address stuckWallet,address recipient,uint256 amount,uint256 nonce,uint256 deadline)"
        );

    /// @notice Half of secp256k1 curve order N to prevent EIP-2 signature malleability
    uint256 internal constant SECP256K1_HALF_N =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

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

    /// @notice Per-stuckWallet replay nonce for EIP-712 signatures
    mapping(address stuckWallet => uint256 nonce) public rescueNonces;

    event CounterfactualFundsRescued(
        address indexed stuckWallet,
        address indexed verifiedOwner,
        address indexed recipient,
        uint256 amount,
        DerivationMode mode
    );

    error AddressIsActiveContract(address target);
    error NothingToRescue(address target);
    error InvalidRecipient();
    error SignatureExpired(uint256 deadline, uint256 currentTimestamp);
    error InvalidSignature();

    /**
     * @notice Computes the deterministic counterfactual address from an EOA owner and proof parameters.
     */
    function computeCounterfactualAddress(
        address ownerEOA,
        CounterfactualProof calldata proof
    ) public pure returns (address stuckWallet) {
        bytes32 salt;
        if (
            proof.mode == DerivationMode.ERA_VM_PACKED_20 ||
            proof.mode == DerivationMode.EVM_CREATE2_PACKED_20
        ) {
            salt = keccak256(abi.encodePacked(ownerEOA));
        } else if (proof.mode == DerivationMode.ERA_VM_ABI_32) {
            salt = keccak256(abi.encode(ownerEOA));
        } else {
            salt = keccak256(abi.encodePacked(ownerEOA, proof.accountIndex));
        }

        if (proof.mode == DerivationMode.EVM_CREATE2_PACKED_20) {
            bytes32 evmDigest = keccak256(
                abi.encodePacked(bytes1(0xff), proof.factory, salt, proof.bytecodeHash)
            );
            return address(uint160(uint256(evmDigest)));
        }

        bytes32 constructorInputHash = keccak256(proof.constructorInput);
        bytes32 eraDigest = keccak256(
            bytes.concat(
                ZKSYNC_CREATE2_PREFIX,
                bytes32(uint256(uint160(proof.factory))),
                salt,
                proof.bytecodeHash,
                constructorInputHash
            )
        );
        stuckWallet = address(uint160(uint256(eraDigest)));
    }

    /**
     * @notice Convenience helper for the standard Abstract Global Wallet (AGW) EraVM derivation.
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
     * @notice Direct self-service rescue when `msg.sender` is the EOA owner (`ownerEOA`).
     */
    function rescueCounterfactual(
        CounterfactualProof calldata proof,
        address recipient
    ) external returns (address stuckWallet, uint256 rescuedAmount) {
        stuckWallet = computeCounterfactualAddress(msg.sender, proof);
        rescuedAmount = _executeRescue(stuckWallet, msg.sender, recipient, proof.mode);
    }

    /**
     * @notice Convenience wrapper for standard Abstract Global Wallet (AGW) EraVM rescue.
     */
    function rescueFromEraVMCounterfactual(
        address factory,
        bytes32 proxyBytecodeHash,
        address implementation,
        address recipient
    ) external returns (address stuckWallet, uint256 rescuedAmount) {
        stuckWallet = computeEraVMCounterfactualAddress(
            msg.sender,
            factory,
            proxyBytecodeHash,
            implementation
        );
        rescuedAmount = _executeRescue(
            stuckWallet,
            msg.sender,
            recipient,
            DerivationMode.ERA_VM_PACKED_20
        );
    }

    /**
     * @notice Gasless / Relayer rescue using an EIP-712 signature from `ownerEOA`.
     * @dev Useful when `ownerEOA` is an embedded signer (Privy/Turnkey) or has 0 gas on the destination chain.
     */
    function rescueCounterfactualWithSig(
        address ownerEOA,
        CounterfactualProof calldata proof,
        address recipient,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (address stuckWallet, uint256 rescuedAmount) {
        if (block.timestamp > deadline) {
            revert SignatureExpired(deadline, block.timestamp);
        }
        if (ownerEOA == address(0)) revert InvalidSignature();
        if (uint256(s) > SECP256K1_HALF_N || (v != 27 && v != 28)) {
            revert InvalidSignature();
        }

        stuckWallet = computeCounterfactualAddress(ownerEOA, proof);
        rescuedAmount = _getBalance(stuckWallet);
        if (rescuedAmount == 0) {
            revert NothingToRescue(stuckWallet);
        }

        _verifyRescueSig(ownerEOA, stuckWallet, recipient, rescuedAmount, deadline, v, r, s);
        _verifyAndTransfer(stuckWallet, ownerEOA, recipient, rescuedAmount, proof.mode);
    }

    function _verifyRescueSig(
        address ownerEOA,
        address stuckWallet,
        address recipient,
        uint256 rescuedAmount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal {
        uint256 currentNonce = rescueNonces[stuckWallet]++;
        bytes32 structHash = keccak256(
            abi.encode(
                RESCUE_AUTH_TYPEHASH,
                ownerEOA,
                stuckWallet,
                recipient,
                rescuedAmount,
                currentNonce,
                deadline
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator(), structHash)
        );

        address recovered = ecrecover(digest, v, r, s);
        if (recovered == address(0) || recovered != ownerEOA) {
            revert InvalidSignature();
        }
    }

    /**
     * @notice Returns the EIP-712 domain separator for this token contract.
     */
    function domainSeparator() public view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    EIP712_DOMAIN_TYPEHASH,
                    keccak256(bytes("CounterfactualPreimageRescue")),
                    keccak256(bytes("1")),
                    block.chainid,
                    address(this)
                )
            );
    }

    function _executeRescue(
        address stuckWallet,
        address verifiedOwner,
        address recipient,
        DerivationMode mode
    ) internal returns (uint256 rescuedAmount) {
        rescuedAmount = _getBalance(stuckWallet);
        if (rescuedAmount == 0) {
            revert NothingToRescue(stuckWallet);
        }
        rescueNonces[stuckWallet]++;
        _verifyAndTransfer(stuckWallet, verifiedOwner, recipient, rescuedAmount, mode);
    }

    function _verifyAndTransfer(
        address stuckWallet,
        address verifiedOwner,
        address recipient,
        uint256 rescuedAmount,
        DerivationMode mode
    ) internal {
        if (recipient == address(0)) revert InvalidRecipient();
        if (stuckWallet.code.length != 0) {
            revert AddressIsActiveContract(stuckWallet);
        }

        _rescueTransfer(stuckWallet, recipient, rescuedAmount);

        emit CounterfactualFundsRescued(
            stuckWallet,
            verifiedOwner,
            recipient,
            rescuedAmount,
            mode
        );
    }

    /// @dev Must return the token balance of `account`
    function _getBalance(address account) internal view virtual returns (uint256);

    /// @dev Must move `amount` tokens from `from` to `to`
    function _rescueTransfer(address from, address to, uint256 amount) internal virtual;
}
