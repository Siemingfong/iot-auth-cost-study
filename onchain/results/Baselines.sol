// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// Shared record format and anchoring logic.
/// A record is (ct, ts, chk, seed): camera type, timestamp, image checksum, storage pointer.
abstract contract Anchoring {
    mapping(bytes32 => uint256) public recordBlock;   // one storage slot per record
    mapping(bytes32 => uint256) public rootBlock;     // one storage slot per batch (Merkle root)
    event BatchAnchored(bytes32 indexed root, uint256 n);

    function _merkleRoot(bytes32[] memory h) internal pure returns (bytes32) {
        uint256 n = h.length;
        while (n > 1) {
            uint256 k = 0;
            for (uint256 i = 0; i < n; i += 2) {
                h[k++] = (i + 1 < n) ? keccak256(abi.encodePacked(h[i], h[i + 1])) : h[i];
            }
            n = k;
        }
        return h[0];
    }

    function _anchor(bytes32[] memory leaves) internal {
        bytes32 root = _merkleRoot(leaves);
        rootBlock[root] = block.number;
        emit BatchAnchored(root, leaves.length);
    }
}

/// T0/T1: anchoring without on-chain authentication (aggregator is trusted).
contract AnchorOnly is Anchoring {
    /// T0: the aggregator posts only the root.
    function anchorRootOnly(bytes32 root, uint256 n) external {
        rootBlock[root] = block.number;
        emit BatchAnchored(root, n);
    }
    /// T1: the aggregator posts all leaves; the root is computed on-chain.
    function anchorLeaves(bytes32[] calldata h) external {
        _anchor(h);
    }
    /// per-record storage, no authentication
    function anchorEach(bytes32[] calldata h) external {
        for (uint256 i = 0; i < h.length; i++) recordBlock[h[i]] = block.number;
    }
}

/// ECDSA over secp256k1, verified with the ecrecover precompile (0x01).
contract K1Verifier is Anchoring {
    uint256 internal constant HALF_N = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    address public immutable kgc;
    mapping(address => bool) public registered;
    struct Msg { bytes32 ct; uint64 ts; bytes32 chk; bytes20 seed; uint8 v; bytes32 r; bytes32 s; }
    error BadSignature(uint256 i);

    constructor() { kgc = msg.sender; }
    function registerDevice(address dev) external { require(msg.sender == kgc); registered[dev] = true; }

    function _check(Msg calldata m, uint256 i) internal view returns (bytes32 leaf) {
        bytes32 h = keccak256(abi.encode(address(this), m.ct, m.ts, m.chk, m.seed));
        if (uint256(m.s) > HALF_N) revert BadSignature(i);
        address a = ecrecover(h, m.v, m.r, m.s);
        if (a == address(0) || !registered[a]) revert BadSignature(i);
        leaf = keccak256(abi.encode(a, m.ct, m.ts, m.chk, m.seed));
    }
    function submitOne(Msg calldata m) external { recordBlock[_check(m, 0)] = block.number; }
    function submitBatch(Msg[] calldata ms) external {
        bytes32[] memory leaves = new bytes32[](ms.length);
        for (uint256 i = 0; i < ms.length; i++) leaves[i] = _check(ms[i], i);
        _anchor(leaves);
    }
}

/// ECDSA over P-256 (secp256r1), verified with the EIP-7951 precompile (0x100).
contract R1Verifier is Anchoring {
    address public immutable kgc;
    mapping(uint32 => bytes32) public devCommit;     // keccak256(qx, qy)
    struct Dev { uint32 idx; bytes32 qx; bytes32 qy; }
    struct Msg { uint16 dev; bytes32 ct; uint64 ts; bytes32 chk; bytes20 seed; bytes32 r; bytes32 s; }
    error BadDevice(uint256 j);
    error BadSignature(uint256 i);

    constructor() { kgc = msg.sender; }
    function registerDevice(uint32 idx, bytes32 qx, bytes32 qy) external {
        require(msg.sender == kgc); devCommit[idx] = keccak256(abi.encode(qx, qy));
    }
    function _commit(Dev calldata d, uint256 j) internal view returns (bytes32 c) {
        c = devCommit[d.idx];
        if (c == bytes32(0) || c != keccak256(abi.encode(d.qx, d.qy))) revert BadDevice(j);
    }
    function _check(Dev calldata d, bytes32 c, Msg calldata m, uint256 i) internal view returns (bytes32) {
        bytes32 h = sha256(abi.encode(address(this), m.ct, m.ts, m.chk, m.seed));
        (bool ok, bytes memory out) = address(0x100).staticcall(abi.encode(h, m.r, m.s, d.qx, d.qy));
        if (!ok || out.length != 32 || uint256(bytes32(out)) != 1) revert BadSignature(i);
        return keccak256(abi.encode(c, m.ct, m.ts, m.chk, m.seed));
    }
    function submitOne(Dev calldata d, Msg calldata m) external {
        recordBlock[_check(d, _commit(d, 0), m, 0)] = block.number;
    }
    function submitBatch(Dev[] calldata ds, Msg[] calldata ms) external {
        bytes32[] memory cs = new bytes32[](ds.length);
        for (uint256 j = 0; j < ds.length; j++) cs[j] = _commit(ds[j], j);
        bytes32[] memory leaves = new bytes32[](ms.length);
        for (uint256 i = 0; i < ms.length; i++) leaves[i] = _check(ds[ms[i].dev], cs[ms[i].dev], ms[i], i);
        _anchor(leaves);
    }
}

/// BLS signatures on BLS12-381 (signatures in G1, public keys in G2), with per-device keys.
/// The aggregator sums the n signatures into one; the contract hashes every message to G1
/// (RFC 9380 hash_to_curve, SHA-256/SSWU, via MODEXP and MAP_FP_TO_G1) and checks
///   e(sigma, -P2) * prod_j e(sum_{i in j} H(m_i), pk_j) == 1      (m + 1 pairs).
contract BLSAggVerifier is Anchoring {
    bytes internal constant NEG_P2 = hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000d1b3cc2c7027888be51d9ef691d77bcb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa0000000000000000000000000000000013fa4d4a0ad8b1ce186ed5061789213d993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed";
    bytes internal constant DST = "MLAV-BENCH-BLS-SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    bytes internal constant P_FIELD = hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";
    address public immutable kgc;
    mapping(uint32 => bytes32) public devCommit;     // keccak256(pk), pk in G2 (256 bytes)
    struct Dev { uint32 idx; bytes32[8] pk; }
    struct Msg { uint16 dev; bytes32 ct; uint64 ts; bytes32 chk; bytes20 seed; }
    error BadDevice(uint256 j);
    error BadSignature();

    constructor() { kgc = msg.sender; }
    function registerDevice(uint32 idx, bytes32[8] calldata pk) external {
        require(msg.sender == kgc); devCommit[idx] = keccak256(abi.encode(pk));
    }

    // ---------------------------------------------------------- RFC 9380 hash_to_curve
    function _expand(bytes memory m) internal view returns (bytes memory u) {
        bytes memory dstPrime = abi.encodePacked(DST, uint8(DST.length));
        bytes32 b0 = sha256(abi.encodePacked(bytes32(0), bytes32(0), m, uint16(128), uint8(0), dstPrime));
        bytes32 bi = sha256(abi.encodePacked(b0, uint8(1), dstPrime));
        u = new bytes(128);
        assembly ("memory-safe") { mstore(add(u, 32), bi) }
        for (uint8 i = 2; i <= 4; i++) {
            bi = sha256(abi.encodePacked(b0 ^ bi, i, dstPrime));
            assembly ("memory-safe") { mstore(add(u, add(32, mul(sub(i, 1), 32))), bi) }
        }
    }
    /// reduce a 64-byte big-endian integer mod p with MODEXP (x^1 mod p); returns the
    /// 64-byte EIP-2537 field-element encoding (16 zero bytes || 48-byte value)
    function _modp(bytes memory u, uint256 off) internal view returns (bytes memory fe) {
        bytes memory input = abi.encodePacked(uint256(64), uint256(1), uint256(48), new bytes(64), uint8(1), P_FIELD);
        fe = new bytes(64);
        assembly ("memory-safe") {
            mcopy(add(input, 128), add(add(u, 32), off), 64)
            if iszero(staticcall(gas(), 0x05, add(input, 32), mload(input), add(fe, 48), 48)) { revert(0, 0) }
        }
    }
    function _map(bytes memory fe) internal view returns (bytes memory p) {
        p = new bytes(128);
        assembly ("memory-safe") {
            if iszero(staticcall(gas(), 0x10, add(fe, 32), 64, add(p, 32), 128)) { revert(0, 0) }
        }
    }
    function _add(bytes memory a, bytes memory b) internal view returns (bytes memory p) {
        bytes memory input = abi.encodePacked(a, b);
        p = new bytes(128);
        assembly ("memory-safe") {
            if iszero(staticcall(gas(), 0x0b, add(input, 32), 256, add(p, 32), 128)) { revert(0, 0) }
        }
    }
    function hashToG1(bytes memory m) public view returns (bytes memory) {
        bytes memory u = _expand(m);
        return _add(_map(_modp(u, 0)), _map(_modp(u, 64)));
    }

    // ---------------------------------------------------------- verification
    function _verify(Dev[] calldata ds, Msg[] calldata ms, bytes32[4] calldata sig) internal view returns (bytes32[] memory leaves) {
        uint256 m = ds.length;
        bytes32[] memory cs = new bytes32[](m);
        for (uint256 j = 0; j < m; j++) {
            cs[j] = devCommit[ds[j].idx];
            if (cs[j] == bytes32(0) || cs[j] != keccak256(abi.encode(ds[j].pk))) revert BadDevice(j);
        }
        bytes[] memory acc = new bytes[](m);
        leaves = new bytes32[](ms.length);
        for (uint256 i = 0; i < ms.length; i++) {
            Msg calldata mi = ms[i];
            bytes memory enc = abi.encode(cs[mi.dev], mi.ct, mi.ts, mi.chk, mi.seed);
            bytes memory hp = hashToG1(enc);
            acc[mi.dev] = acc[mi.dev].length == 0 ? hp : _add(acc[mi.dev], hp);
            leaves[i] = keccak256(enc);
        }
        bytes memory input = abi.encodePacked(sig, NEG_P2);
        for (uint256 j = 0; j < m; j++) input = abi.encodePacked(input, acc[j], ds[j].pk);
        uint256[1] memory res;
        assembly ("memory-safe") {
            if iszero(staticcall(gas(), 0x0f, add(input, 32), mload(input), res, 32)) { revert(0, 0) }
        }
        if (res[0] != 1) revert BadSignature();
    }
    function submitOne(Dev[] calldata ds, Msg[] calldata ms, bytes32[4] calldata sig) external {
        bytes32[] memory leaves = _verify(ds, ms, sig);
        recordBlock[leaves[0]] = block.number;
    }
    function submitBatch(Dev[] calldata ds, Msg[] calldata ms, bytes32[4] calldata aggSig) external {
        _anchor(_verify(ds, ms, aggSig));
    }
}
