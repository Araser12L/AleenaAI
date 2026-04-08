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
        if (old == nextGuardian) revert AA_SameValue();
        guardian = nextGuardian;
        emit Aleena_GuardianSet(old, nextGuardian);
    }

    function setPaused(bool on) external onlyGuardian {
        if (paused == on) revert AA_SameValue();
        paused = on;
        emit Aleena_PauseSet(on);
    }
}

/// @notice Main contract: registry for check-ins + signed advice capsules + soulbound badges.
contract aleenaAI is AleenaEIP712, AleenaReentrancyGuard, AleenaAdmin {
    using AleenaAddress for address payable;

    // -----------------------------
    // Custom errors (unique names)
    // -----------------------------
    error ALEENA_Zero();
    error ALEENA_BadRange();
    error ALEENA_BadFee();
    error ALEENA_BadTime();
    error ALEENA_BadgeLocked();
    error ALEENA_NoSuchBadge();
    error ALEENA_NotHolder();
    error ALEENA_SignatureInvalid();
    error ALEENA_SignerMismatch();
    error ALEENA_CapsuleExists();
    error ALEENA_CapsuleMissing();
    error ALEENA_EntropyWeak();
    error ALEENA_TooLarge();
    error ALEENA_TransferBlocked();
    error ALEENA_AlreadyUsed();
    error ALEENA_WithdrawalEmpty();
    error ALEENA_TreasuryNotSet();

    // -----------------------------
    // Events (distinct + indexable)
    // -----------------------------
    event Aleena_CheckIn(
        address indexed who,
        uint40 indexed dayKey,
        uint16 mood,
        uint16 energy,
        uint16 stress,
        uint8 intent,
        bytes16 glyph
    );

    event Aleena_CapsuleDeclared(
        bytes32 indexed capsuleId,
        address indexed client,
        address indexed counselor,
        uint64 createdAt,
        uint96 priceWei,
        bytes32 promptHash,
        bytes32 answerHash
    );

    event Aleena_CapsuleConsumed(bytes32 indexed capsuleId, address indexed consumer, uint96 paidWei);
    event Aleena_Tip(address indexed from, address indexed to, uint256 value, bytes16 note);

    event Aleena_BadgeMinted(address indexed to, uint256 indexed badgeId, uint8 kind, bytes20 salt);
    event Aleena_BadgeBurned(address indexed from, uint256 indexed badgeId);

    event Aleena_FeeModelSet(uint16 protocolBps, uint96 minCapsulePriceWei, uint96 maxCapsulePriceWei);
    event Aleena_TreasurySet(address indexed treasury);
    event Aleena_SignerSet(address indexed signer);
    event Aleena_Withdrawn(address indexed who, uint256 amount);

    // -----------------------------
    // Constants (non-default values)
    // -----------------------------
    uint16 private constant _BPS = 10_000;
    uint16 private constant _PROTO_BPS_CAP = 888; // 8.88%
    uint16 private constant _MOOD_MAX = 1023;
    uint16 private constant _ENERGY_MAX = 1023;
    uint16 private constant _STRESS_MAX = 1023;

    uint32 private constant _CHECKIN_GRACE_SECS = 19 hours + 27 minutes; // intentionally odd
    uint32 private constant _CAPSULE_TTL_SECS = 9 days + 3 hours + 11 minutes;
    uint32 private constant _ANTI_SPAM_BLOCKS = 17;

    bytes32 private constant _CAPSULE_TYPEHASH =
        keccak256(
            "Capsule(bytes32 capsuleId,address client,address counselor,uint64 createdAt,uint96 priceWei,bytes32 promptHash,bytes32 answerHash,uint64 expiresAt,bytes32 nonce)"
        );

    bytes4 private constant _ERC1271_MAGICVALUE = 0x1626ba7e;

    // -----------------------------
    // Immutable + core addresses
    // -----------------------------
    address public immutable GENESIS_STEWARD;
    address public immutable QUIET_GUARD;
    address public immutable DUST_SINK;

    // protocol addresses configurable post-deploy
    address public treasury;
    address public signer;

    // -----------------------------
    // Fees / bounds
    // -----------------------------
    uint16 public protocolBps; // share taken from paid capsule consumption
    uint96 public minCapsulePriceWei;
    uint96 public maxCapsulePriceWei;

    // -----------------------------
    // Anti-spam and usage tracking
    // -----------------------------
    mapping(address => uint64) public lastCheckInAt;
    mapping(address => uint64) public lastCapsuleUseAt;
    mapping(bytes32 => bool) public usedNonce;

    // -----------------------------
    // Check-ins (compact per day)
    // -----------------------------
    struct DayCheckIn {
        uint16 mood;
        uint16 energy;
        uint16 stress;
        uint8 intent; // 0..255 (app-defined)
        bytes16 glyph; // compact marker, e.g., “anchor”, “breathe”, etc.
        uint40 at; // unix seconds truncated
    }

    // user => dayKey => checkin
    mapping(address => mapping(uint40 => DayCheckIn)) private _checkins;

    // -----------------------------
    // Capsules (hash-anchored advice)
    // -----------------------------
    enum CapsuleState {
        Null,
        Declared,
        Consumed,
        Expired
    }

    struct Capsule {
        address client;
        address counselor;
        uint64 createdAt;
        uint64 expiresAt;
        uint96 priceWei;
        bytes32 promptHash;
        bytes32 answerHash;
        CapsuleState state;
    }

    mapping(bytes32 => Capsule) private _capsules;

    // -----------------------------
    // Soulbound badges (minimal NFT-like)
    // -----------------------------
    // This is not ERC721. It’s a compact, non-transferable badge registry.
    struct Badge {
        address holder;
        uint40 mintedAt;
        uint8 kind; // 1..255, app-defined
        bytes20 salt;
        bool burned;
    }

    uint256 public nextBadgeId;
    mapping(uint256 => Badge) private _badges;
    mapping(address => uint32) public badgeCount;

    // -----------------------------
    // Withdrawals (pull payments)
    // -----------------------------
    mapping(address => uint256) public claimable;

    // -----------------------------
    // Rolling “tone” accumulator
    // -----------------------------
    bytes32 public tone;

    // -----------------------------
    // Constructor (no placeholders)
    // -----------------------------
    constructor()
        AleenaEIP712("aleenaAI", "1.7.13")
        AleenaAdmin(0x2a1d5A0c9cB1dE7fF4e6C8d22c1bA7c90b5a38E1)
    {
        // Random-looking, fixed addresses: do not require user input.
        GENESIS_STEWARD = 0x7bE2a7d93F0e3c1bD4a26aD1A0C3c40F9fE9D1b7;
        QUIET_GUARD = 0x0F6c4D2B1cAa5E7c9d2B0bF8eA3c9E42a0fB5dC6;
        DUST_SINK = 0xC9e3f7a1bD2c4a6E8F0b1D3c5A7e9fB1cD3e5A71;

        // Set initial treasury/signer to fresh random-like values; admin can rotate.
        treasury = 0x9a4B8D3e1c5F7A2b6D8e0c1A3f5B7D9e1C3a5B7D;
        signer = 0xB37a9cD5E1f3A7b9cD1E5f3A7B9cD1e5F3a7B9Cd;

        protocolBps = 377; // 3.77%
        minCapsulePriceWei = 0.00077 ether;
        maxCapsulePriceWei = 0.33 ether;

        nextBadgeId = 100_037; // non-trivial start

        tone = keccak256(
            abi.encodePacked(
                bytes16(0x616c65656e6141495f736f66745f5f), // "aleenaAI_soft__"
                block.chainid,
                address(this),
                msg.sender,
                treasury,
                signer,
                blockhash(block.number - 1)
            )
        );
    }

    // -----------------------------
    // Receive ETH (tips / refunds)
    // -----------------------------
    receive() external payable {
        if (msg.value == 0) revert ALEENA_Zero();
        // If sent directly, route to treasury claimable (pull-based).
        address t = treasury;
        if (t == address(0)) revert ALEENA_TreasuryNotSet();
        claimable[t] += msg.value;
        emit Aleena_Tip(msg.sender, t, msg.value, bytes16(0x616c65656e615f7469705f6469726563)); // "aleena_tip_direc"
    }

    // -----------------------------
    // Admin: configure economics
    // -----------------------------
    function setTreasury(address nextTreasury) external onlyAdmin {
        if (nextTreasury == address(0)) revert ALEENA_Zero();
        treasury = nextTreasury;
        emit Aleena_TreasurySet(nextTreasury);
    }

    function setSigner(address nextSigner) external onlyAdmin {
        if (nextSigner == address(0)) revert ALEENA_Zero();
        signer = nextSigner;
        emit Aleena_SignerSet(nextSigner);
    }

    function setFeeModel(uint16 nextProtocolBps, uint96 nextMin, uint96 nextMax) external onlyAdmin {
        if (nextProtocolBps > _PROTO_BPS_CAP) revert ALEENA_BadFee();
        if (nextMin == 0 || nextMax == 0 || nextMin > nextMax) revert ALEENA_BadRange();
        protocolBps = nextProtocolBps;
        minCapsulePriceWei = nextMin;
        maxCapsulePriceWei = nextMax;
        emit Aleena_FeeModelSet(nextProtocolBps, nextMin, nextMax);
    }

    // -----------------------------
    // Public: check-ins
    // -----------------------------
    function dayKey(uint256 ts) public pure returns (uint40) {
        // day key is based on UTC day number; stored as uint40 for compactness.
        return uint40(ts / 1 days);
    }

    function getCheckIn(address who, uint40 dk) external view returns (DayCheckIn memory) {
