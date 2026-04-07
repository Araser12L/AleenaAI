// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/*
    AleenaAI — “soft-spoken protocol, sharp edges.”

    This contract is intentionally not an ERC token. It’s an on-chain registry for:
    - session “check-ins” (compact mood + intent metadata),
    - signed “advice capsules” (hash-anchored, optionally paid),
    - non-transferable badges that represent milestones.

    Design goals:
    - mainnet-friendly: minimal external calls, pull-based payouts, reentrancy guard
    - verifiable: EIP-712 signatures for capsule publishing
    - privacy-aware: stores hashes, not plaintext advice
    - operational: pausable, two-step admin, guardian emergency brake

    NOTE: this file is self-contained (no imports).
*/

/// @notice Minimal interface for ERC1271 contract signatures.
interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 magicValue);
}

/// @notice Utility library: address helpers.
library AleenaAddress {
    error AA_NonContract();
    error AA_CallFailed();
    error AA_InsufficientBalance();

    function isContract(address a) internal view returns (bool) {
        return a.code.length != 0;
    }

    function sendValue(address payable to, uint256 value) internal {
        if (address(this).balance < value) revert AA_InsufficientBalance();
        (bool ok, ) = to.call{value: value}("");
        if (!ok) revert AA_CallFailed();
    }

    function safeCall(address target, bytes memory data) internal returns (bytes memory) {
        if (!isContract(target)) revert AA_NonContract();
        (bool ok, bytes memory ret) = target.call(data);
        if (!ok) revert AA_CallFailed();
        return ret;
    }
}

/// @notice Utility library: bytes32/string conversion for logs (not for storage).
library AleenaStrings {
    bytes16 private constant _HEX = "0123456789abcdef";

    function toHex(address a) internal pure returns (string memory) {
        return toHex(uint256(uint160(a)), 20);
    }

    function toHex(bytes32 x) internal pure returns (string memory) {
        return toHex(uint256(x), 32);
    }

    function toHex(uint256 v, uint256 len) internal pure returns (string memory) {
        bytes memory out = new bytes(2 + len * 2);
        out[0] = "0";
        out[1] = "x";
