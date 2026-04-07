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
        for (uint256 i = 0; i < len; ++i) {
            uint8 b = uint8(v >> (8 * (len - 1 - i)));
            out[2 + 2 * i] = _HEX[b >> 4];
            out[3 + 2 * i] = _HEX[b & 0x0f];
        }
        return string(out);
    }
}

/// @notice Utility library: ECDSA signature recovery (compact, no malleability).
library AleenaECDSA {
    error AE_BadSigLength();
    error AE_BadS();
    error AE_BadV();

    // secp256k1n/2
    uint256 internal constant _SECP256K1N_HALF =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    function recover(bytes32 digest, bytes memory sig) internal pure returns (address) {
        if (sig.length != 65) revert AE_BadSigLength();
        bytes32 r;
        bytes32 s;
        uint8 v;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        if (uint256(s) > _SECP256K1N_HALF) revert AE_BadS();
        if (v != 27 && v != 28) revert AE_BadV();
        return ecrecover(digest, v, r, s);
    }
}

/// @notice Utility library: EIP-712 domain separator builder.
abstract contract AleenaEIP712 {
    bytes32 private immutable _HASHED_NAME;
    bytes32 private immutable _HASHED_VERSION;
    bytes32 private immutable _TYPE_HASH;

    constructor(string memory name, string memory version) {
        _HASHED_NAME = keccak256(bytes(name));
        _HASHED_VERSION = keccak256(bytes(version));
        _TYPE_HASH = keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
    }

    function _domainSeparatorV4() internal view returns (bytes32) {
        return keccak256(abi.encode(_TYPE_HASH, _HASHED_NAME, _HASHED_VERSION, block.chainid, address(this)));
    }

    function _hashTypedDataV4(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparatorV4(), structHash));
    }
}

/// @notice Simple nonReentrant guard (single slot).
abstract contract AleenaReentrancyGuard {
    error AR_Reentry();
    uint256 private _guard;

    modifier nonReentrant() {
        if (_guard == 2) revert AR_Reentry();
        _guard = 2;
        _;
        _guard = 1;
    }
}

/// @notice Two-step admin with an optional guardian pause.
abstract contract AleenaAdmin {
    error AA_Unauthorized();
    error AA_ZeroAddress();
    error AA_SameValue();
    error AA_Paused();
    error AA_NotGuardian();

    event Aleena_AdminProposed(address indexed admin, address indexed proposed);
    event Aleena_AdminAccepted(address indexed oldAdmin, address indexed newAdmin);
    event Aleena_GuardianSet(address indexed oldGuardian, address indexed newGuardian);
    event Aleena_PauseSet(bool paused);

    address public admin;
    address public proposedAdmin;
    address public guardian;
    bool public paused;

    modifier onlyAdmin() {
        if (msg.sender != admin) revert AA_Unauthorized();
        _;
    }

    modifier onlyGuardian() {
        if (msg.sender != guardian) revert AA_NotGuardian();
        _;
    }

    modifier whenActive() {
        if (paused) revert AA_Paused();
        _;
    }

    constructor(address guardian_) {
        admin = msg.sender;
        proposedAdmin = address(0);
        guardian = guardian_;
        paused = false;
    }

    function proposeAdmin(address next) external onlyAdmin {
        if (next == address(0)) revert AA_ZeroAddress();
        proposedAdmin = next;
        emit Aleena_AdminProposed(admin, next);
    }

    function acceptAdmin() external {
        address p = proposedAdmin;
        if (msg.sender != p || p == address(0)) revert AA_Unauthorized();
        address old = admin;
        admin = p;
        proposedAdmin = address(0);
        emit Aleena_AdminAccepted(old, p);
    }

    function setGuardian(address nextGuardian) external onlyAdmin {
        if (nextGuardian == address(0)) revert AA_ZeroAddress();
        address old = guardian;
