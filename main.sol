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
    event RelayerUsed(address indexed relayer, uint256 newCount);
    event TrailheadTransferred(address indexed previous, address indexed next);
    event TrailCreated(bytes32 indexed trailId, uint256 atBlock);
    event SegmentAttachedToTrail(bytes32 indexed segmentId, bytes32 indexed trailId);
    event TrailLocked(bytes32 indexed trailId, uint256 atBlock);
    event SegmentTagged(bytes32 indexed segmentId, bytes32 tag);
    event SegmentWeightSet(bytes32 indexed segmentId, uint64 weight);
    event EpochRecorded(uint256 indexed epochIndex, uint256 atSegmentCount, bytes32 fingerprint);
    event ChainHashUpdated(bytes32 indexed segmentId, bytes32 previousChainHash);

    // -------------------------------------------------------------------------
    // Constructor (no args; all populated)
    // -------------------------------------------------------------------------
    constructor() {
        trailhead = msg.sender;
        relayer = msg.sender;
        deployBlock = block.number;
        deployTimestamp = block.timestamp;
        latticeDomain = keccak256(
            abi.encodePacked(
                block.chainid,
                address(this),
                block.prevrandao,
                block.timestamp,
                "BleuTrk_Lattice_v1"
            )
        );
        maxSegmentValue = 1048576;
        minGapBlocks = 5;
        windowBlocks = 256;
    }

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------
    modifier onlyTrailhead() {
        if (msg.sender != trailhead) revert BTrk_NotTrailhead();
        _;
    }

    modifier onlyRelayer() {
        if (msg.sender != relayer) revert BTrk_NotRelayer();
        _;
    }

    modifier whenNotFrozen() {
        if (latticeFrozen) revert BTrk_LatticeFrozen();
        _;
    }

    // -------------------------------------------------------------------------
    // Trailhead: record a single segment
    // -------------------------------------------------------------------------
    function recordSegment(bytes32 segmentId, uint256 value) external onlyTrailhead whenNotFrozen {
        if (segmentId == bytes32(0)) revert BTrk_ZeroSegmentId();
        if (value > maxSegmentValue) revert BTrk_ValueExceedsCap();
        TrailSegment storage seg = _segments[segmentId];
        if (seg.recordedAtBlock != 0) revert BTrk_SegmentAlreadyRecorded();
        if (totalSegments > 0) {
            uint256 lastOrdinal = _segments[_segmentIds[totalSegments - 1]].ordinalIndex;
            if (block.number < deployBlock + minGapBlocks) revert BTrk_GapTooShort();
        }
        totalSegments += 1;
        seg.value = value;
        seg.recordedAtBlock = block.number;
        seg.ordinalIndex = totalSegments;
        _segmentIds.push(segmentId);
        cumulativeValue += value;
        _updateChainHash(segmentId, value, totalSegments);
        _maybeRecordEpoch(totalSegments, block.number);
        emit SegmentRecorded(segmentId, value, totalSegments, block.number);
    }

    // -------------------------------------------------------------------------
    // Trailhead: seal a segment (no further changes)
    // -------------------------------------------------------------------------
    function sealSegment(bytes32 segmentId) external onlyTrailhead whenNotFrozen {
        TrailSegment storage seg = _segments[segmentId];
        if (seg.recordedAtBlock == 0) revert BTrk_SegmentNotFound();
        if (seg.sealed) revert BTrk_AlreadySealed();
        seg.sealed = true;
        sealedCount += 1;
        emit SegmentSealed(segmentId, block.number);
    }

    // -------------------------------------------------------------------------
    // Trailhead: freeze entire lattice (irreversible)
    // -------------------------------------------------------------------------
    function freezeLattice() external onlyTrailhead whenNotFrozen {
        if (block.number < deployBlock + FROST_DELAY_BLOCKS) revert BTrk_FrostDelayActive();
        latticeFrozen = true;
        emit LatticeFrozen(block.number);
    }

    // -------------------------------------------------------------------------
    // Relayer: batch-record segments (within cap)
    // -------------------------------------------------------------------------
    function relaySegments(
        bytes32[] calldata segmentIds,
        uint256[] calldata values
    ) external onlyRelayer whenNotFrozen {
        if (segmentIds.length > RELAY_BATCH_LIMIT) revert BTrk_RelayBatchTooLarge();
        if (segmentIds.length != values.length) revert BTrk_RelayBatchTooLarge();
        for (uint256 i = 0; i < segmentIds.length; ) {
            bytes32 id = segmentIds[i];
            uint256 val = values[i];
            if (id == bytes32(0)) revert BTrk_ZeroSegmentId();
            if (val > maxSegmentValue) revert BTrk_ValueExceedsCap();
            TrailSegment storage seg = _segments[id];
            if (seg.recordedAtBlock != 0) revert BTrk_SegmentAlreadyRecorded();
            totalSegments += 1;
            seg.value = val;
            seg.recordedAtBlock = block.number;
            seg.ordinalIndex = totalSegments;
            _segmentIds.push(id);
            cumulativeValue += val;
            _updateChainHash(id, val, totalSegments);
            _maybeRecordEpoch(totalSegments, block.number);
            emit SegmentRecorded(id, val, totalSegments, block.number);
            unchecked {
                ++i;
            }
        }
        _relayCount[msg.sender] += segmentIds.length;
        emit RelayerUsed(msg.sender, _relayCount[msg.sender]);
    }

    // -------------------------------------------------------------------------
    // View: get segment by id
    // -------------------------------------------------------------------------
    function getSegment(bytes32 segmentId) external view returns (
        uint256 value,
        uint256 recordedAtBlock,
        uint256 ordinalIndex,
        bool sealed
    ) {
        TrailSegment storage seg = _segments[segmentId];
        if (seg.recordedAtBlock == 0) revert BTrk_SegmentNotFound();
        return (seg.value, seg.recordedAtBlock, seg.ordinalIndex, seg.sealed);
    }

    // -------------------------------------------------------------------------
    // View: segment id by ordinal index (1-based)
    // -------------------------------------------------------------------------
    function getSegmentIdByOrdinal(uint256 ordinalIndex) external view returns (bytes32) {
        if (ordinalIndex == 0 || ordinalIndex > totalSegments) revert BTrk_SegmentNotFound();
        return _segmentIds[ordinalIndex - 1];
    }

    // -------------------------------------------------------------------------
    // View: relay count for an address
    // -------------------------------------------------------------------------
    function getRelayCount(address account) external view returns (uint256) {
        return _relayCount[account];
    }

    // -------------------------------------------------------------------------
    // View: lattice fingerprint (hash of domain + totals)
    // -------------------------------------------------------------------------
    function latticeFingerprint() external view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                latticeDomain,
                totalSegments,
                sealedCount,
                deployBlock,
                deployTimestamp,
                latticeFrozen
            )
        );
    }

    // -------------------------------------------------------------------------
    // View: whether a segment is within the current window (last N blocks)
    // -------------------------------------------------------------------------
    function isInWindow(bytes32 segmentId) external view returns (bool) {
        TrailSegment storage seg = _segments[segmentId];
        if (seg.recordedAtBlock == 0) return false;
        return block.number <= seg.recordedAtBlock + windowBlocks;
    }

    // -------------------------------------------------------------------------
    // View: total segments (alias for clarity)
    // -------------------------------------------------------------------------
    function totalSegmentCount() external view returns (uint256) {
        return totalSegments;
    }

    // -------------------------------------------------------------------------
    // View: segment ids length for enumeration
    // -------------------------------------------------------------------------
    function segmentIdsLength() external view returns (uint256) {
        return _segmentIds.length;
    }

    // -------------------------------------------------------------------------
    // View: check existence without reverting
    // -------------------------------------------------------------------------
    function hasSegment(bytes32 segmentId) external view returns (bool) {
        return _segments[segmentId].recordedAtBlock != 0;
    }

    // -------------------------------------------------------------------------
    // View: config snapshot (no storage write)
    // -------------------------------------------------------------------------
    function getConfig() external view returns (
        address trailhead_,
        address relayer_,
        uint256 deployBlock_,
        uint256 maxSegmentValue_,
        uint256 minGapBlocks_,
        uint256 windowBlocks_,
        bool latticeFrozen_
    ) {
        return (
            trailhead,
            relayer,
            deployBlock,
            maxSegmentValue,
            minGapBlocks,
            windowBlocks,
            latticeFrozen
        );
    }

    // -------------------------------------------------------------------------
    // Trailhead: seal multiple segments in one call
    // -------------------------------------------------------------------------
    function sealSegments(bytes32[] calldata segmentIds) external onlyTrailhead whenNotFrozen {
        if (segmentIds.length > RELAY_BATCH_LIMIT) revert BTrk_RelayBatchTooLarge();
        for (uint256 i = 0; i < segmentIds.length; ) {
            bytes32 id = segmentIds[i];
            TrailSegment storage seg = _segments[id];
            if (seg.recordedAtBlock == 0) revert BTrk_SegmentNotFound();
            if (!seg.sealed) {
                seg.sealed = true;
                sealedCount += 1;
                emit SegmentSealed(id, block.number);
            }
            unchecked {
                ++i;
            }
        }
    }

    // -------------------------------------------------------------------------
    // View: count of unsealed segments
    // -------------------------------------------------------------------------
    function unsealedCount() external view returns (uint256) {
        return totalSegments - sealedCount;
    }

    // -------------------------------------------------------------------------
    // View: segment values in ordinal range [start, end] (1-based, inclusive)
    // -------------------------------------------------------------------------
    function getValuesInOrdinalRange(uint256 startOrdinal, uint256 endOrdinal)
        external
        view
        returns (uint256[] memory values)
    {
        if (startOrdinal == 0 || endOrdinal < startOrdinal || endOrdinal > totalSegments) {
            revert BTrk_SegmentNotFound();
        }
        uint256 len = endOrdinal - startOrdinal + 1;
        if (len > RELAY_BATCH_LIMIT) revert BTrk_RelayBatchTooLarge();
        values = new uint256[](len);
        for (uint256 i = 0; i < len; ) {
            values[i] = _segments[_segmentIds[startOrdinal + i - 1]].value;
            unchecked {
                ++i;
            }
        }
    }

    // -------------------------------------------------------------------------
    // View: block number of the most recently recorded segment
    // -------------------------------------------------------------------------
    function lastRecordedBlock() external view returns (uint256) {
        if (totalSegments == 0) return 0;
        return _segments[_segmentIds[totalSegments - 1]].recordedAtBlock;
    }

    // -------------------------------------------------------------------------
    // View: lattice domain (for external verification)
    // -------------------------------------------------------------------------
    function getLatticeDomain() external view returns (bytes32) {
        return latticeDomain;
    }

    // -------------------------------------------------------------------------
    // View: deploy context (chain and time)
    // -------------------------------------------------------------------------
    function getDeployContext() external view returns (uint256 blockNum, uint256 timestamp) {
        return (deployBlock, deployTimestamp);
    }

    // -------------------------------------------------------------------------
    // Trailhead: create a named trail
    // -------------------------------------------------------------------------
    function createTrail(bytes32 trailId) external onlyTrailhead whenNotFrozen {
        if (trailId == bytes32(0)) revert BTrk_ZeroSegmentId();
        if (_trails[trailId].createdAtBlock != 0) revert BTrk_TrailAlreadyExists();
        _trails[trailId] = TrailInfo({
            trailId: trailId,
            createdAtBlock: block.number,
            segmentCount: 0,
            totalValue: 0,
            locked: false
        });
        _trailIds.push(trailId);
        totalTrails += 1;
        emit TrailCreated(trailId, block.number);
    }

    // -------------------------------------------------------------------------
    // Trailhead: attach a segment to a trail (segment must exist, trail must not be locked)
    // -------------------------------------------------------------------------
    function attachSegmentToTrail(bytes32 segmentId, bytes32 trailId) external onlyTrailhead whenNotFrozen {
        if (_segments[segmentId].recordedAtBlock == 0) revert BTrk_SegmentNotFound();
        if (_trails[trailId].createdAtBlock == 0) revert BTrk_TrailNotFound();
        if (_trails[trailId].locked) revert BTrk_TrailLocked();
        if (_segmentToTrail[segmentId] != bytes32(0)) revert BTrk_SegmentAlreadyRecorded();
        TrailInfo storage tr = _trails[trailId];
        if (tr.segmentCount >= MAX_TRAIL_SEGMENTS) revert BTrk_TrailSegmentLimit();
        _segmentToTrail[segmentId] = trailId;
        tr.segmentCount += 1;
        tr.totalValue += _segments[segmentId].value;
        _trailSegmentIds[trailId].push(segmentId);
        emit SegmentAttachedToTrail(segmentId, trailId);
    }

    // -------------------------------------------------------------------------
    // Trailhead: lock a trail (no more segments can be attached)
    // -------------------------------------------------------------------------
    function lockTrail(bytes32 trailId) external onlyTrailhead whenNotFrozen {
        if (_trails[trailId].createdAtBlock == 0) revert BTrk_TrailNotFound();
        _trails[trailId].locked = true;
        emit TrailLocked(trailId, block.number);
    }

    // -------------------------------------------------------------------------
    // Trailhead: set optional tag for a segment
    // -------------------------------------------------------------------------
    function setSegmentTag(bytes32 segmentId, bytes32 tag) external onlyTrailhead whenNotFrozen {
        if (_segments[segmentId].recordedAtBlock == 0) revert BTrk_SegmentNotFound();
        _segmentTag[segmentId] = tag;
        emit SegmentTagged(segmentId, tag);
    }

    // -------------------------------------------------------------------------
    // Trailhead: set optional weight for a segment (for weighted proofs)
    // -------------------------------------------------------------------------
    function setSegmentWeight(bytes32 segmentId, uint64 weight) external onlyTrailhead whenNotFrozen {
        if (_segments[segmentId].recordedAtBlock == 0) revert BTrk_SegmentNotFound();
