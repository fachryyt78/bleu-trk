// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BleuTrk
/// @notice Lattice-waypoint trail ledger for ordinal path proofs. Segments are bound to chain and deploy context; no token, no claim.
contract BleuTrk {
    // -------------------------------------------------------------------------
    // Immutable configuration (constructor-set only)
    // -------------------------------------------------------------------------
    address public immutable trailhead;
    address public immutable relayer;
    uint256 public immutable deployBlock;
    uint256 public immutable deployTimestamp;
    bytes32 public immutable latticeDomain;
    uint256 public immutable maxSegmentValue;
    uint256 public immutable minGapBlocks;
    uint256 public immutable windowBlocks;

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------
    struct TrailSegment {
        uint256 value;
        uint256 recordedAtBlock;
        uint256 ordinalIndex;
        bool sealed;
    }

    mapping(bytes32 => TrailSegment) private _segments;
    mapping(address => uint256) private _relayCount;
    bytes32[] private _segmentIds;
    uint256 public totalSegments;
    uint256 public sealedCount;
    bool public latticeFrozen;

    // -------------------------------------------------------------------------
    // Trails: named groupings of segments
    // -------------------------------------------------------------------------
    struct TrailInfo {
        bytes32 trailId;
        uint256 createdAtBlock;
        uint256 segmentCount;
        uint256 totalValue;
        bool locked;
    }
    mapping(bytes32 => TrailInfo) private _trails;
    mapping(bytes32 => bytes32) private _segmentToTrail;
    mapping(bytes32 => bytes32[]) private _trailSegmentIds;
    bytes32[] private _trailIds;
    uint256 public totalTrails;

    // -------------------------------------------------------------------------
    // Tags and optional segment metadata
    // -------------------------------------------------------------------------
    mapping(bytes32 => bytes32) private _segmentTag;
    mapping(bytes32 => uint64) private _segmentWeight;
    mapping(bytes32 => bytes32) private _previousChainHash;

    // -------------------------------------------------------------------------
