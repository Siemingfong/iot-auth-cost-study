// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title MLAV-IBS on-chain verifier (EIP-2537, BLS12-381)
/// @notice Pseudonymous Cha-Cheon-style IBS. Signature sigma = (U, V) in G1^2,
///         verified as e(V, P2) * e(U + h*Q, -Ppub2) == 1 with h = H2(c, record, U),
///         where c = keccak256(Q) is the registered pseudonym commitment.
///         P2 and -Ppub2 are baked in at deployment (generated verifier).
contract MLAVVerifier {
    uint256 internal constant R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;
    bytes internal constant P2 = hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
    bytes internal constant NPPUB2 = hex"000000000000000000000000000000000c815b4866ee400c0c191e29c28b8e62ab01dc11eb0c1f3a7cb4ae33993e8f7f336ba660f78c65c5d7a47bb28e4ec89d00000000000000000000000000000000087fb5f8d71d2b89a600269ef18659cdc05a20cc418aafaf6307bf97053efa2bcb1e677e870930483ff7494cd366817900000000000000000000000000000000174d1adba8e08929878e308367cd020f30e206f66cf4d007bf729aab0aaab191742621ca77bb303a3dfda2b47daf560c000000000000000000000000000000000e9a1968440fb6e939d8e902454fac8db8963bd22e5c90bfae97014e8c6f438d593b85ff5afde05848887e3835008f25";

    struct Dev { uint32 idx; bytes32[4] q; }
    struct Msg { uint16 dev; bytes32 ct; uint64 ts; bytes32 chk; bytes20 seed; bytes32[4] u; bytes32[4] v; }

    address public immutable kgc;
    mapping(uint32 => bytes32) public devCommit;      // keccak256(Q) of each registered pseudonym
    mapping(bytes32 => uint256) public recordBlock;   // per-record anchoring (baseline)
    mapping(bytes32 => uint256) public rootBlock;     // Merkle-root anchoring (MLAV layer 1)
    /// last accepted timestamp per pseudonym; 1 after registration, 0 for unregistered ones
    mapping(uint32 => uint64) public lastTs;

    event BatchAnchored(bytes32 indexed root, uint256 n);
    error Stale(uint256 i);
    error BadDevice(uint256 i);
    error BadSignature();

    constructor() { kgc = msg.sender; }

    function registerDevice(uint32 idx, bytes32[4] calldata q) external {
        require(msg.sender == kgc, "only KGC");
        require(lastTs[idx] == 0, "registered");   // each pseudonym once: no key or timestamp reset
        devCommit[idx] = keccak256(abi.encode(q));
        lastTs[idx] = 1;
    }
    /// replay protection: a pseudonym's records must carry strictly increasing timestamps
    function _fresh(uint32 idx, uint64 ts, uint256 i) internal {
        uint64 last = lastTs[idx];
        if (last == 0 || ts <= last) revert Stale(i);
        lastTs[idx] = ts;
    }

    // ------------------------------------------------------------------ helpers
    function _commit(Dev calldata d) internal view returns (bytes32 c) {
        c = devCommit[d.idx];
        if (c == bytes32(0) || c != keccak256(abi.encode(d.q))) revert BadDevice(d.idx);
    }

    function _h(bytes32 c, Msg calldata m) internal view returns (uint256) {
        return uint256(keccak256(abi.encode(block.chainid, address(this), c, m.ct, m.ts, m.chk, m.seed, m.u))) % R;
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

    function _g1add(bytes memory a, bytes32[4] calldata b) internal view returns (bytes memory) {
        bytes memory input = new bytes(256);
        assembly ("memory-safe") {
            mcopy(add(input, 32), add(a, 32), 128)
            calldatacopy(add(input, 160), b, 128)
            if iszero(staticcall(gas(), 0x0b, add(input, 32), 256, add(a, 32), 128)) { revert(0, 0) }
        }
        return a;   // the sum is written into a, so no memory is allocated for it
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
                if (i + 1 < n) {
                    bytes32 a = h[i]; bytes32 b = h[i + 1]; bytes32 r;
                    // hash the pair in the scratch space instead of allocating memory for every node
                    assembly ("memory-safe") { mstore(0x00, a) mstore(0x20, b) r := keccak256(0x00, 0x40) }
                    h[k++] = r;
                } else {
                    h[k++] = h[i];
                }
            }
            n = k;
        }
        return h[0];
    }

    // ------------------------------------------------------------------ individual
    function submitIndividual(Dev calldata d, Msg calldata m) external {
        bytes32 c = _commit(d);
        _fresh(d.idx, m.ts, 0);
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
        for (uint256 j = 0; j < m; j++) {
            uint256 fmp; assembly ("memory-safe") { fmp := mload(0x40) }
            cs[j] = _commit(devs[j]);
            assembly ("memory-safe") { mstore(0x40, fmp) }
        }
        for (uint256 i = 0; i < n; i++) _fresh(devs[msgs[i].dev].idx, msgs[i].ts, i);
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
            uint256 fmp; assembly ("memory-safe") { fmp := mload(0x40) }
            Msg calldata mi = msgs[i];
            bytes32 c = cs[mi.dev];
            if (i > 0) _g1add(S, mi.v);
            _put(T, 160 * i, mi.u, 1);
            _put(T, 160 * (n + i), devs[mi.dev].q, _h(c, mi));
            leaves[i] = _recordHash(c, mi);
            assembly ("memory-safe") { mstore(0x40, fmp) }   // reuse the memory of this record's temporaries
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
            uint256 fmp; assembly ("memory-safe") { fmp := mload(0x40) }
            Msg calldata mi = msgs[i];
            bytes32 c = cs[mi.dev];
            uint256 dlt = uint256(keccak256(abi.encode(seed, i))) >> 128;
            _put(S, 160 * i, mi.v, dlt);
            _put(T, 160 * i, mi.u, dlt);
            _put(T, 160 * (n + i), devs[mi.dev].q, mulmod(dlt, _h(c, mi), R));
            leaves[i] = _recordHash(c, mi);
            assembly ("memory-safe") { mstore(0x40, fmp) }   // reuse the memory of this record's temporaries
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
            uint256 fmp; assembly ("memory-safe") { fmp := mload(0x40) }
            Msg calldata mi = msgs[i];
            bytes32 c = cs[mi.dev];
            uint256 dlt = uint256(keccak256(abi.encode(seed, i))) >> 128;
            _put(S, 160 * i, mi.v, dlt);
            _put(T, 160 * i, mi.u, dlt);
            acc[mi.dev] = addmod(acc[mi.dev], mulmod(dlt, _h(c, mi), R), R);
            leaves[i] = _recordHash(c, mi);
            assembly ("memory-safe") { mstore(0x40, fmp) }   // reuse the memory of this record's temporaries
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
