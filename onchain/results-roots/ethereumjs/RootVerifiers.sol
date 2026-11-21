// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Device-signed roots: a device signs one Merkle root over its own records. The verifiers below extend the
// per-record verifiers of Baselines.sol by inheritance, in a separate source file, so that the per-record
// contracts compile to exactly the bytecode measured in release v1.4.
import "Baselines.sol";

abstract contract RootHelpers is Anchoring {
    /// the tag keeps a signature on a root from being accepted as a signature on a single record, and vice versa
    bytes32 internal constant ROOT_TAG = keccak256("device-signed root");
    /// the root of a device's records, recomputed from the posted record hashes
    function _deviceRoot(bytes32[] calldata leaves) internal pure returns (bytes32) {
        bytes32[] memory h = leaves;   // calldata copied to memory, hashed in place
        return _merkleRoot(h);
    }
    /// anchors one batch root over the (device, root) pairs of a batch of device-signed roots
    function _anchorRoots(bytes32[] memory roots, uint256 n) internal {
        bytes32 root = _merkleRoot(roots);
        rootBlock[root] = block.number;
        emit BatchAnchored(root, n);
    }
}

contract K1RootVerifier is K1Verifier, RootHelpers {
    struct RootMsg { bytes32[] leaves; uint64 ts; uint8 v; bytes32 r; bytes32 s; }
    /// one signature per device over the root of its records
    function submitRoots(RootMsg[] calldata rs) external {
        bytes32[] memory roots = new bytes32[](rs.length);
        uint256 n;
        for (uint256 j = 0; j < rs.length; j++) {
            uint256 fmp; assembly ("memory-safe") { fmp := mload(0x40) }
            RootMsg calldata d = rs[j];
            bytes32 root = _deviceRoot(d.leaves);
            bytes32 h = keccak256(abi.encode(block.chainid, address(this), ROOT_TAG, root, d.ts));
            if (uint256(d.s) > HALF_N) revert BadSignature(j);
            address a = ecrecover(h, d.v, d.r, d.s);
            if (a == address(0)) revert BadSignature(j);
            _fresh(uint160(a), d.ts, j);
            roots[j] = keccak256(abi.encode(a, root));
            n += d.leaves.length;
            assembly ("memory-safe") { mstore(0x40, fmp) }
        }
        _anchorRoots(roots, n);
    }
}

contract R1RootVerifier is R1Verifier, RootHelpers {
    struct RootMsg { bytes32[] leaves; uint64 ts; bytes32 r; bytes32 s; }
    /// one signature per device over the root of its records; rs[j] belongs to device ds[j]
    function submitRoots(Dev[] calldata ds, RootMsg[] calldata rs) external {
        if (rs.length != ds.length) revert BadDevice(rs.length);
        bytes32[] memory roots = new bytes32[](rs.length);
        uint256 n;
        for (uint256 j = 0; j < rs.length; j++) {
            uint256 fmp; assembly ("memory-safe") { fmp := mload(0x40) }
            bytes32 c = _commit(ds[j], j);
            RootMsg calldata d = rs[j];
            bytes32 root = _deviceRoot(d.leaves);
            bytes32 h = sha256(abi.encode(block.chainid, address(this), ROOT_TAG, root, d.ts));
            (bool ok, bytes memory out) = address(0x100).staticcall(abi.encode(h, d.r, d.s, ds[j].qx, ds[j].qy));
            if (!ok || out.length != 32 || uint256(bytes32(out)) != 1) revert BadSignature(j);
            _fresh(ds[j].idx, d.ts, j);
            roots[j] = keccak256(abi.encode(c, root));
            n += d.leaves.length;
            assembly ("memory-safe") { mstore(0x40, fmp) }
        }
        _anchorRoots(roots, n);
    }
}

contract BLSRootVerifier is BLSAggVerifier, RootHelpers {
    struct RootMsg { bytes32[] leaves; uint64 ts; }
    /// each device signs the root of its records; one aggregate signature over all devices of the batch, checked
    /// with one pairing check of m + 1 pairs; rs[j] belongs to device ds[j]
    function submitRoots(Dev[] calldata ds, RootMsg[] calldata rs, bytes32[4] calldata aggSig) external {
        uint256 m = ds.length;
        if (rs.length != m) revert BadDevice(rs.length);
        bytes memory head = abi.encodePacked(aggSig, NEG_P2);
        uint256 hl = head.length;
        bytes memory input = new bytes(hl + 384 * m);
        assembly ("memory-safe") { mcopy(add(input, 32), add(head, 32), hl) }
        bytes32[] memory roots = new bytes32[](m);
        uint256 n;
        for (uint256 j = 0; j < m; j++) {
            uint256 fmp; assembly ("memory-safe") { fmp := mload(0x40) }
            bytes32 c = devCommit[ds[j].idx];
            if (c == bytes32(0) || c != keccak256(abi.encode(ds[j].pk))) revert BadDevice(j);
            RootMsg calldata d = rs[j];
            bytes32 root = _deviceRoot(d.leaves);
            bytes memory hp = hashToG1(abi.encode(block.chainid, address(this), ROOT_TAG, c, root, d.ts));
            _fresh(ds[j].idx, d.ts, j);
            uint256 o = hl + 384 * j;
            assembly ("memory-safe") { mcopy(add(add(input, 32), o), add(hp, 32), 128) }
            bytes32[8] calldata pk = ds[j].pk;
            assembly ("memory-safe") { calldatacopy(add(add(input, 32), add(o, 128)), pk, 256) }
            roots[j] = keccak256(abi.encode(c, root));
            n += d.leaves.length;
            assembly ("memory-safe") { mstore(0x40, fmp) }
        }
        uint256[1] memory res;
        assembly ("memory-safe") {
            if iszero(staticcall(gas(), 0x0f, add(input, 32), mload(input), res, 32)) { revert(0, 0) }
        }
        if (res[0] != 1) revert BadSignature();
        _anchorRoots(roots, n);
    }
}
