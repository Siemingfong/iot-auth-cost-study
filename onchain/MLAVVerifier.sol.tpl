// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title MLAV-IBS on-chain verifier (EIP-2537, BLS12-381)
/// @notice Pseudonymous Cha-Cheon-style IBS. Signature sigma = (U, V) in G1^2,
///         verified as e(V, P2) * e(U + h*Q, -Ppub2) == 1 with h = H2(c, record, U),
///         where c = keccak256(Q) is the registered pseudonym commitment.
///         P2 and -Ppub2 are baked in at deployment (generated verifier).
contract MLAVVerifier {
    uint256 internal constant R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;
    bytes internal constant P2 = hex"{{P2}}";
    bytes internal constant NPPUB2 = hex"{{NPPUB2}}";

    struct Dev { uint32 idx; bytes32[4] q; }
    struct Msg { uint16 dev; bytes32 ct; uint64 ts; bytes32 chk; bytes20 seed; bytes32[4] u; bytes32[4] v; }

    address public immutable kgc;
    mapping(uint32 => bytes32) public devCommit;      // keccak256(Q) of each registered pseudonym
    mapping(bytes32 => uint256) public recordBlock;   // per-record anchoring (baseline)
    mapping(bytes32 => uint256) public rootBlock;     // Merkle-root anchoring (MLAV layer 1)

    event BatchAnchored(bytes32 indexed root, uint256 n);
    error BadDevice(uint256 i);
    error BadSignature();

    constructor() { kgc = msg.sender; }

    function registerDevice(uint32 idx, bytes32[4] calldata q) external {
        require(msg.sender == kgc, "only KGC");
        devCommit[idx] = keccak256(abi.encode(q));
    }

    // ------------------------------------------------------------------ helpers
    function _commit(Dev calldata d) internal view returns (bytes32 c) {
        c = devCommit[d.idx];
        if (c == bytes32(0) || c != keccak256(abi.encode(d.q))) revert BadDevice(d.idx);
    }

    function _h(bytes32 c, Msg calldata m) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(c, m.ct, m.ts, m.chk, m.seed, m.u))) % R;
    }

    function _recordHash(bytes32 c, Msg calldata m) internal pure returns (bytes32) {
        return keccak256(abi.encode(c, m.ct, m.ts, m.chk, m.seed));
    }

    function _put(bytes memory buf, uint256 off, bytes32[4] calldata p, uint256 s) internal pure {
        assembly ("memory-safe") {
            let d := add(add(buf, 32), off)
            calldatacopy(d, p, 128)
            mstore(add(d, 128), s)
        }
    }

    function _msm(bytes memory input) internal view returns (bytes memory out) {
        out = new bytes(128);
        assembly ("memory-safe") {
            if iszero(staticcall(gas(), 0x0c, add(input, 32), mload(input), add(out, 32), 128)) { revert(0, 0) }
        }
    }

    function _g1add(bytes memory a, bytes32[4] calldata b) internal view returns (bytes memory out) {
        bytes memory input = new bytes(256);
        out = new bytes(128);
        assembly ("memory-safe") {
            mcopy(add(input, 32), add(a, 32), 128)
            calldatacopy(add(input, 160), b, 128)
            if iszero(staticcall(gas(), 0x0b, add(input, 32), 256, add(out, 32), 128)) { revert(0, 0) }
        }
    }

    function _pairing2(bytes memory s, bytes memory t) internal view returns (bool ok) {
        bytes memory input = abi.encodePacked(s, P2, t, NPPUB2);
        uint256[1] memory res;
        assembly ("memory-safe") {
            if iszero(staticcall(gas(), 0x0f, add(input, 32), mload(input), res, 32)) { revert(0, 0) }
        }
        ok = res[0] == 1;
    }

    function _copy(bytes32[4] calldata p) internal pure returns (bytes memory out) {
        out = new bytes(128);
        assembly ("memory-safe") { calldatacopy(add(out, 32), p, 128) }
    }

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

    // ------------------------------------------------------------------ individual
    function submitIndividual(Dev calldata d, Msg calldata m) external {
        bytes32 c = _commit(d);
        bytes memory hq = new bytes(160);
        _put(hq, 0, d.q, _h(c, m));
        bytes memory t = _g1add(_msm(hq), m.u);              // U + h*Q
        if (!_pairing2(_copy(m.v), t)) revert BadSignature();
        recordBlock[_recordHash(c, m)] = block.number;
    }

    // ------------------------------------------------------------------ batches
    /// mode 0 = naive sum (INSECURE, comparison only), 1 = small-exponent test,
    /// 2 = pseudonym-grouped small-exponent test. A verified batch is anchored as one Merkle root.
    function submitBatch(Dev[] calldata devs, Msg[] calldata msgs, uint8 mode) external {
        uint256 m = devs.length;
        uint256 n = msgs.length;
        bytes32[] memory cs = new bytes32[](m);
        for (uint256 j = 0; j < m; j++) cs[j] = _commit(devs[j]);
        bytes32[] memory leaves = new bytes32[](n);
        bytes memory S;
        bytes memory T;
        if (mode == 0) (S, T) = _fillNaive(devs, msgs, cs, leaves);
        else if (mode == 1) (S, T) = _fillSET(devs, msgs, cs, leaves);
        else (S, T) = _fillGrouped(devs, msgs, cs, leaves);
        if (!_pairing2(S, _msm(T))) revert BadSignature();
        bytes32 root = _merkleRoot(leaves);
        rootBlock[root] = block.number;
        emit BatchAnchored(root, n);
    }

    function _fillNaive(Dev[] calldata devs, Msg[] calldata msgs, bytes32[] memory cs, bytes32[] memory leaves)
        internal view returns (bytes memory S, bytes memory T)
    {
        uint256 n = msgs.length;
        S = _copy(msgs[0].v);
        T = new bytes(320 * n);
        for (uint256 i = 0; i < n; i++) {
            Msg calldata mi = msgs[i];
            bytes32 c = cs[mi.dev];
            if (i > 0) S = _g1add(S, mi.v);
            _put(T, 160 * i, mi.u, 1);
            _put(T, 160 * (n + i), devs[mi.dev].q, _h(c, mi));
            leaves[i] = _recordHash(c, mi);
        }
    }

    function _fillSET(Dev[] calldata devs, Msg[] calldata msgs, bytes32[] memory cs, bytes32[] memory leaves)
        internal view returns (bytes memory S, bytes memory T)
    {
        uint256 n = msgs.length;
        bytes32 seed = keccak256(msg.data);              // Fiat-Shamir seed for the 128-bit deltas
        S = new bytes(160 * n);
        T = new bytes(320 * n);
        for (uint256 i = 0; i < n; i++) {
            Msg calldata mi = msgs[i];
            bytes32 c = cs[mi.dev];
            uint256 dlt = uint256(keccak256(abi.encode(seed, i))) >> 128;
            _put(S, 160 * i, mi.v, dlt);
            _put(T, 160 * i, mi.u, dlt);
            _put(T, 160 * (n + i), devs[mi.dev].q, mulmod(dlt, _h(c, mi), R));
            leaves[i] = _recordHash(c, mi);
        }
        S = _msm(S);
    }

    function _fillGrouped(Dev[] calldata devs, Msg[] calldata msgs, bytes32[] memory cs, bytes32[] memory leaves)
        internal view returns (bytes memory S, bytes memory T)
    {
        uint256 n = msgs.length;
        uint256 m = devs.length;
        bytes32 seed = keccak256(msg.data);
        S = new bytes(160 * n);
        T = new bytes(160 * (n + m));
        uint256[] memory acc = new uint256[](m);
        for (uint256 i = 0; i < n; i++) {
            Msg calldata mi = msgs[i];
            bytes32 c = cs[mi.dev];
            uint256 dlt = uint256(keccak256(abi.encode(seed, i))) >> 128;
            _put(S, 160 * i, mi.v, dlt);
            _put(T, 160 * i, mi.u, dlt);
            acc[mi.dev] = addmod(acc[mi.dev], mulmod(dlt, _h(c, mi), R), R);
            leaves[i] = _recordHash(c, mi);
        }
        for (uint256 j = 0; j < m; j++) _put(T, 160 * (n + j), devs[j].q, acc[j]);
        S = _msm(S);
    }

    // ------------------------------------------------------------------ anchoring only
    function anchorEach(bytes32[] calldata h) external {
        for (uint256 i = 0; i < h.length; i++) recordBlock[h[i]] = block.number;
    }

    function anchorRoot(bytes32[] calldata h) external {
        bytes32 root = _merkleRoot(h);
        rootBlock[root] = block.number;
        emit BatchAnchored(root, h.length);
    }
}
