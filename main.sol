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
    // Epochs: periodic snapshots for fingerprinting
    // -------------------------------------------------------------------------
    struct EpochSnapshot {
        uint256 atBlock;
        uint256 atSegmentCount;
        bytes32 fingerprint;
        uint256 sealedAtEpoch;
    }
    mapping(uint256 => EpochSnapshot) private _epochs;
    uint256 public currentEpochIndex;
    uint256 public cumulativeValue;

    // -------------------------------------------------------------------------
    // Constants (distinct per-contract)
    // -------------------------------------------------------------------------
    uint256 public constant SEGMENT_CAP = 2097152;
    uint256 public constant RELAY_BATCH_LIMIT = 47;
    uint256 public constant FROST_DELAY_BLOCKS = 12;
    uint256 public constant EPOCH_EVERY_N_SEGMENTS = 64;
    uint256 public constant MAX_TRAIL_SEGMENTS = 512;
    uint256 public constant MAX_WEIGHT = 0xFFFFFFFFFFFFFFFF;
    uint256 public constant VIEW_BATCH_MAX = 128;

    // -------------------------------------------------------------------------
    // Errors (unique names and semantics)
    // -------------------------------------------------------------------------
    error BTrk_NotTrailhead();
    error BTrk_NotRelayer();
    error BTrk_SegmentAlreadyRecorded();
    error BTrk_ValueExceedsCap();
    error BTrk_GapTooShort();
    error BTrk_LatticeFrozen();
    error BTrk_ZeroSegmentId();
    error BTrk_AlreadySealed();
    error BTrk_SegmentNotFound();
    error BTrk_RelayBatchTooLarge();
    error BTrk_FrostDelayActive();
    error BTrk_ZeroAddress();
    error BTrk_TrailNotFound();
    error BTrk_TrailAlreadyExists();
    error BTrk_TrailLocked();
    error BTrk_SegmentNotInTrail();
    error BTrk_TrailSegmentLimit();
    error BTrk_WeightExceedsMax();
    error BTrk_InvalidOrdinalRange();
    error BTrk_ViewBatchTooLarge();
    error BTrk_InvalidEpochIndex();

    // -------------------------------------------------------------------------
    // Events (unique signatures)
    // -------------------------------------------------------------------------
    event SegmentRecorded(
        bytes32 indexed segmentId,
        uint256 value,
        uint256 ordinalIndex,
        uint256 atBlock
    );
    event SegmentSealed(bytes32 indexed segmentId, uint256 atBlock);
    event LatticeFrozen(uint256 atBlock);
