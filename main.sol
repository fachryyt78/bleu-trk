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
        if (weight > MAX_WEIGHT) revert BTrk_WeightExceedsMax();
        _segmentWeight[segmentId] = weight;
        emit SegmentWeightSet(segmentId, weight);
    }

    // -------------------------------------------------------------------------
    // Trailhead: batch attach segments to a trail
    // -------------------------------------------------------------------------
    function attachSegmentsToTrail(bytes32[] calldata segmentIds, bytes32 trailId)
        external
        onlyTrailhead
        whenNotFrozen
    {
        if (segmentIds.length > RELAY_BATCH_LIMIT) revert BTrk_RelayBatchTooLarge();
        if (_trails[trailId].createdAtBlock == 0) revert BTrk_TrailNotFound();
        if (_trails[trailId].locked) revert BTrk_TrailLocked();
        TrailInfo storage tr = _trails[trailId];
        for (uint256 i = 0; i < segmentIds.length; ) {
            bytes32 sid = segmentIds[i];
            if (_segments[sid].recordedAtBlock == 0) revert BTrk_SegmentNotFound();
            if (_segmentToTrail[sid] != bytes32(0)) revert BTrk_SegmentAlreadyRecorded();
            if (tr.segmentCount >= MAX_TRAIL_SEGMENTS) revert BTrk_TrailSegmentLimit();
            _segmentToTrail[sid] = trailId;
            tr.segmentCount += 1;
            tr.totalValue += _segments[sid].value;
            _trailSegmentIds[trailId].push(sid);
            emit SegmentAttachedToTrail(sid, trailId);
            unchecked {
                ++i;
            }
        }
    }

    // -------------------------------------------------------------------------
    // Internal: append to hash chain (previous hash per segment)
    // -------------------------------------------------------------------------
    function _updateChainHash(bytes32 segmentId, uint256 value, uint256 ordinalIndex) private {
        bytes32 prev = totalSegments == 1 ? bytes32(0) : _previousChainHash[_segmentIds[totalSegments - 2]];
        bytes32 link = keccak256(abi.encodePacked(prev, segmentId, value, ordinalIndex, block.number));
        _previousChainHash[segmentId] = link;
        emit ChainHashUpdated(segmentId, link);
    }

    // -------------------------------------------------------------------------
    // Internal: record epoch snapshot every EPOCH_EVERY_N_SEGMENTS
    // -------------------------------------------------------------------------
    function _maybeRecordEpoch(uint256 segmentCount, uint256 atBlock) private {
        if (segmentCount % EPOCH_EVERY_N_SEGMENTS != 0) return;
        uint256 epochIdx = currentEpochIndex;
        bytes32 fp = keccak256(
            abi.encodePacked(
                latticeDomain,
                segmentCount,
                sealedCount,
                cumulativeValue,
                atBlock,
                epochIdx
            )
        );
        _epochs[epochIdx] = EpochSnapshot({
            atBlock: atBlock,
            atSegmentCount: segmentCount,
            fingerprint: fp,
            sealedAtEpoch: sealedCount
        });
        currentEpochIndex = epochIdx + 1;
        emit EpochRecorded(epochIdx, segmentCount, fp);
    }

    // -------------------------------------------------------------------------
    // View: get trail info
    // -------------------------------------------------------------------------
    function getTrail(bytes32 trailId) external view returns (
        uint256 createdAtBlock,
        uint256 segmentCount,
        uint256 totalValue,
        bool locked
    ) {
        TrailInfo storage tr = _trails[trailId];
        if (tr.createdAtBlock == 0) revert BTrk_TrailNotFound();
        return (tr.createdAtBlock, tr.segmentCount, tr.totalValue, tr.locked);
    }

    // -------------------------------------------------------------------------
    // View: trail id by index (0-based)
    // -------------------------------------------------------------------------
    function getTrailIdByIndex(uint256 index) external view returns (bytes32) {
        if (index >= totalTrails) revert BTrk_TrailNotFound();
        return _trailIds[index];
    }

    // -------------------------------------------------------------------------
    // View: segment ids in a trail (paginated)
    // -------------------------------------------------------------------------
    function getTrailSegmentIds(bytes32 trailId, uint256 offset, uint256 limit)
        external
        view
        returns (bytes32[] memory segmentIds)
    {
        if (_trails[trailId].createdAtBlock == 0) revert BTrk_TrailNotFound();
        bytes32[] storage arr = _trailSegmentIds[trailId];
        if (limit > VIEW_BATCH_MAX) revert BTrk_ViewBatchTooLarge();
        if (offset >= arr.length) return new bytes32[](0);
        uint256 end = offset + limit;
        if (end > arr.length) end = arr.length;
        uint256 len = end - offset;
        segmentIds = new bytes32[](len);
        for (uint256 i = 0; i < len; ) {
            segmentIds[i] = arr[offset + i];
            unchecked {
                ++i;
            }
        }
    }

    // -------------------------------------------------------------------------
    // View: trail id for a segment (or zero if none)
    // -------------------------------------------------------------------------
    function getTrailForSegment(bytes32 segmentId) external view returns (bytes32) {
        return _segmentToTrail[segmentId];
    }

    // -------------------------------------------------------------------------
    // View: tag for a segment
    // -------------------------------------------------------------------------
    function getSegmentTag(bytes32 segmentId) external view returns (bytes32) {
        return _segmentTag[segmentId];
    }

    // -------------------------------------------------------------------------
    // View: weight for a segment
    // -------------------------------------------------------------------------
    function getSegmentWeight(bytes32 segmentId) external view returns (uint64) {
        return _segmentWeight[segmentId];
    }

    // -------------------------------------------------------------------------
    // View: chain hash for a segment (for external verification)
    // -------------------------------------------------------------------------
    function getChainHash(bytes32 segmentId) external view returns (bytes32) {
        if (_segments[segmentId].recordedAtBlock == 0) revert BTrk_SegmentNotFound();
        return _previousChainHash[segmentId];
    }

    // -------------------------------------------------------------------------
    // View: cumulative chain hash up to and including ordinal (hash of last link)
    // -------------------------------------------------------------------------
    function getChainHashAtOrdinal(uint256 ordinalIndex) external view returns (bytes32) {
        if (ordinalIndex == 0 || ordinalIndex > totalSegments) revert BTrk_SegmentNotFound();
        return _previousChainHash[_segmentIds[ordinalIndex - 1]];
    }

    // -------------------------------------------------------------------------
    // View: epoch snapshot by index
    // -------------------------------------------------------------------------
    function getEpoch(uint256 epochIndex) external view returns (
        uint256 atBlock,
        uint256 atSegmentCount,
        bytes32 fingerprint,
        uint256 sealedAtEpoch
    ) {
        if (epochIndex >= currentEpochIndex) revert BTrk_InvalidEpochIndex();
        EpochSnapshot storage e = _epochs[epochIndex];
        return (e.atBlock, e.atSegmentCount, e.fingerprint, e.sealedAtEpoch);
    }

    // -------------------------------------------------------------------------
    // View: total cumulative value of all segments
    // -------------------------------------------------------------------------
    function getCumulativeValue() external view returns (uint256) {
        return cumulativeValue;
    }

    // -------------------------------------------------------------------------
    // View: full segment + tag + weight + trail + chain hash
    // -------------------------------------------------------------------------
    function getSegmentFull(bytes32 segmentId) external view returns (
        uint256 value,
        uint256 recordedAtBlock,
        uint256 ordinalIndex,
        bool sealed,
        bytes32 tag,
        uint64 weight,
        bytes32 trailId,
        bytes32 chainHash
    ) {
        TrailSegment storage seg = _segments[segmentId];
        if (seg.recordedAtBlock == 0) revert BTrk_SegmentNotFound();
        return (
            seg.value,
            seg.recordedAtBlock,
            seg.ordinalIndex,
            seg.sealed,
            _segmentTag[segmentId],
            _segmentWeight[segmentId],
            _segmentToTrail[segmentId],
            _previousChainHash[segmentId]
        );
    }

    // -------------------------------------------------------------------------
    // View: batch get segments (ids => value, block, ordinal, sealed)
    // -------------------------------------------------------------------------
    function getSegmentBatch(bytes32[] calldata segmentIds) external view returns (
        uint256[] memory values,
        uint256[] memory recordedAtBlocks,
        uint256[] memory ordinalIndices,
        bool[] memory sealedFlags
    ) {
        if (segmentIds.length > VIEW_BATCH_MAX) revert BTrk_ViewBatchTooLarge();
        values = new uint256[](segmentIds.length);
        recordedAtBlocks = new uint256[](segmentIds.length);
        ordinalIndices = new uint256[](segmentIds.length);
        sealedFlags = new bool[](segmentIds.length);
        for (uint256 i = 0; i < segmentIds.length; ) {
            TrailSegment storage seg = _segments[segmentIds[i]];
            values[i] = seg.value;
            recordedAtBlocks[i] = seg.recordedAtBlock;
            ordinalIndices[i] = seg.ordinalIndex;
            sealedFlags[i] = seg.sealed;
            unchecked {
                ++i;
            }
        }
    }

    // -------------------------------------------------------------------------
    // View: segment ids in ordinal range [start, end] (1-based inclusive)
    // -------------------------------------------------------------------------
    function getSegmentIdsInOrdinalRange(uint256 startOrdinal, uint256 endOrdinal)
        external
        view
        returns (bytes32[] memory ids)
    {
        if (startOrdinal == 0 || endOrdinal < startOrdinal || endOrdinal > totalSegments) {
            revert BTrk_InvalidOrdinalRange();
        }
        uint256 len = endOrdinal - startOrdinal + 1;
        if (len > VIEW_BATCH_MAX) revert BTrk_ViewBatchTooLarge();
        ids = new bytes32[](len);
        for (uint256 i = 0; i < len; ) {
            ids[i] = _segmentIds[startOrdinal + i - 1];
            unchecked {
                ++i;
            }
        }
    }

    // -------------------------------------------------------------------------
    // View: segments recorded in block range [fromBlock, toBlock] (inclusive)
    // -------------------------------------------------------------------------
    function getSegmentIdsInBlockRange(uint256 fromBlock, uint256 toBlock)
        external
        view
        returns (bytes32[] memory ids)
    {
        if (fromBlock > toBlock) return new bytes32[](0);
        uint256 cap = totalSegments < VIEW_BATCH_MAX ? totalSegments : VIEW_BATCH_MAX;
        bytes32[] memory temp = new bytes32[](cap);
        uint256 count = 0;
        for (uint256 i = 0; i < totalSegments && count < cap; ) {
            TrailSegment storage seg = _segments[_segmentIds[i]];
            if (seg.recordedAtBlock >= fromBlock && seg.recordedAtBlock <= toBlock) {
                temp[count] = _segmentIds[i];
                count += 1;
            }
            unchecked {
                ++i;
            }
        }
        ids = new bytes32[](count);
        for (uint256 j = 0; j < count; ) {
            ids[j] = temp[j];
            unchecked {
                ++j;
            }
        }
    }

    // -------------------------------------------------------------------------
    // View: first ordinal index whose segment was recorded at or after block
    // -------------------------------------------------------------------------
    function firstOrdinalAtOrAfterBlock(uint256 atOrAfterBlock) external view returns (uint256) {
        for (uint256 i = 0; i < totalSegments; ) {
            if (_segments[_segmentIds[i]].recordedAtBlock >= atOrAfterBlock) {
                return i + 1;
            }
            unchecked {
                ++i;
            }
        }
        return 0;
    }

    // -------------------------------------------------------------------------
    // View: last ordinal index whose segment was recorded at or before block
    // -------------------------------------------------------------------------
    function lastOrdinalAtOrBeforeBlock(uint256 atOrBeforeBlock) external view returns (uint256) {
        for (uint256 i = totalSegments; i > 0; ) {
            unchecked {
                --i;
            }
            if (_segments[_segmentIds[i]].recordedAtBlock <= atOrBeforeBlock) {
                return i + 1;
            }
        }
        return 0;
    }

    // -------------------------------------------------------------------------
    // View: sum of segment values in ordinal range (gas-capped by VIEW_BATCH_MAX)
    // -------------------------------------------------------------------------
    function sumValuesInOrdinalRange(uint256 startOrdinal, uint256 endOrdinal)
        external
        view
        returns (uint256 sum)
    {
        if (startOrdinal == 0 || endOrdinal < startOrdinal || endOrdinal > totalSegments) {
            revert BTrk_InvalidOrdinalRange();
        }
        uint256 len = endOrdinal - startOrdinal + 1;
        if (len > VIEW_BATCH_MAX) revert BTrk_ViewBatchTooLarge();
        for (uint256 i = 0; i < len; ) {
            sum += _segments[_segmentIds[startOrdinal + i - 1]].value;
            unchecked {
                ++i;
            }
        }
    }

    // -------------------------------------------------------------------------
    // View: weighted sum (value * weight) in ordinal range; weight 0 treated as 1
    // -------------------------------------------------------------------------
    function weightedSumInOrdinalRange(uint256 startOrdinal, uint256 endOrdinal)
        external
        view
        returns (uint256 weightedSum)
    {
        if (startOrdinal == 0 || endOrdinal < startOrdinal || endOrdinal > totalSegments) {
            revert BTrk_InvalidOrdinalRange();
        }
        uint256 len = endOrdinal - startOrdinal + 1;
        if (len > VIEW_BATCH_MAX) revert BTrk_ViewBatchTooLarge();
        for (uint256 i = 0; i < len; ) {
            bytes32 id = _segmentIds[startOrdinal + i - 1];
            uint64 w = _segmentWeight[id];
            uint256 v = _segments[id].value;
            weightedSum += v * (w == 0 ? 1 : uint256(w));
            unchecked {
                ++i;
            }
        }
    }

    // -------------------------------------------------------------------------
    // View: whether trail exists
    // -------------------------------------------------------------------------
    function hasTrail(bytes32 trailId) external view returns (bool) {
        return _trails[trailId].createdAtBlock != 0;
    }

    // -------------------------------------------------------------------------
    // View: trail count
    // -------------------------------------------------------------------------
    function trailCount() external view returns (uint256) {
        return totalTrails;
    }

    // -------------------------------------------------------------------------
    // View: all trail ids (paginated)
    // -------------------------------------------------------------------------
    function getTrailIds(uint256 offset, uint256 limit) external view returns (bytes32[] memory trailIds) {
        if (limit > VIEW_BATCH_MAX) revert BTrk_ViewBatchTooLarge();
        if (offset >= totalTrails) return new bytes32[](0);
        uint256 end = offset + limit;
        if (end > totalTrails) end = totalTrails;
        uint256 len = end - offset;
        trailIds = new bytes32[](len);
        for (uint256 i = 0; i < len; ) {
            trailIds[i] = _trailIds[offset + i];
            unchecked {
                ++i;
            }
        }
    }

    // -------------------------------------------------------------------------
    // View: lattice fingerprint at a specific epoch (if exists)
    // -------------------------------------------------------------------------
    function latticeFingerprintAtEpoch(uint256 epochIndex) external view returns (bytes32) {
        if (epochIndex >= currentEpochIndex) revert BTrk_InvalidEpochIndex();
        return _epochs[epochIndex].fingerprint;
    }

    // -------------------------------------------------------------------------
    // View: block number at which epoch was recorded
    // -------------------------------------------------------------------------
    function getEpochBlock(uint256 epochIndex) external view returns (uint256) {
        if (epochIndex >= currentEpochIndex) revert BTrk_InvalidEpochIndex();
        return _epochs[epochIndex].atBlock;
    }

    // -------------------------------------------------------------------------
    // View: segment count at epoch
    // -------------------------------------------------------------------------
    function getEpochSegmentCount(uint256 epochIndex) external view returns (uint256) {
        if (epochIndex >= currentEpochIndex) revert BTrk_InvalidEpochIndex();
        return _epochs[epochIndex].atSegmentCount;
    }

    // -------------------------------------------------------------------------
    // View: verify chain link for a segment (recompute and compare)
    // -------------------------------------------------------------------------
    function verifyChainLink(bytes32 segmentId) external view returns (bool valid) {
        TrailSegment storage seg = _segments[segmentId];
        if (seg.recordedAtBlock == 0) return false;
        bytes32 prev = seg.ordinalIndex == 1 ? bytes32(0) : _previousChainHash[_segmentIds[seg.ordinalIndex - 2]];
        bytes32 expected = keccak256(
            abi.encodePacked(prev, segmentId, seg.value, seg.ordinalIndex, seg.recordedAtBlock)
        );
        return _previousChainHash[segmentId] == expected;
    }

    // -------------------------------------------------------------------------
    // View: config extended (includes epoch and trail constants)
    // -------------------------------------------------------------------------
    function getConfigExtended() external view returns (
        address trailhead_,
        address relayer_,
        uint256 deployBlock_,
        uint256 maxSegmentValue_,
        uint256 minGapBlocks_,
        uint256 windowBlocks_,
        bool latticeFrozen_,
        uint256 currentEpochIndex_,
        uint256 totalTrails_,
        uint256 cumulativeValue_
    ) {
        return (
            trailhead,
            relayer,
            deployBlock,
            maxSegmentValue,
            minGapBlocks,
            windowBlocks,
            latticeFrozen,
            currentEpochIndex,
            totalTrails,
            cumulativeValue
        );
    }

    // -------------------------------------------------------------------------
    // View: segment stats in ordinal range (count, sum, min, max)
    // -------------------------------------------------------------------------
    function getStatsInOrdinalRange(uint256 startOrdinal, uint256 endOrdinal) external view returns (
        uint256 count,
        uint256 sum,
        uint256 minVal,
        uint256 maxVal
    ) {
        if (startOrdinal == 0 || endOrdinal < startOrdinal || endOrdinal > totalSegments) {
            revert BTrk_InvalidOrdinalRange();
        }
        uint256 len = endOrdinal - startOrdinal + 1;
        if (len > VIEW_BATCH_MAX) revert BTrk_ViewBatchTooLarge();
        count = len;
        minVal = type(uint256).max;
        for (uint256 i = 0; i < len; ) {
            uint256 v = _segments[_segmentIds[startOrdinal + i - 1]].value;
            sum += v;
            if (v < minVal) minVal = v;
            if (v > maxVal) maxVal = v;
            unchecked {
                ++i;
            }
        }
        if (minVal == type(uint256).max) minVal = 0;
    }

    // -------------------------------------------------------------------------
    // View: segments by tag (returns ids that have the given tag; paginated scan)
    // -------------------------------------------------------------------------
    function getSegmentIdsByTag(bytes32 tag, uint256 maxResults) external view returns (bytes32[] memory ids) {
        if (maxResults > VIEW_BATCH_MAX) revert BTrk_ViewBatchTooLarge();
        bytes32[] memory temp = new bytes32[](maxResults);
        uint256 count = 0;
        for (uint256 i = 0; i < totalSegments && count < maxResults; ) {
            bytes32 id = _segmentIds[i];
            if (_segmentTag[id] == tag) {
                temp[count] = id;
                count += 1;
            }
            unchecked {
                ++i;
            }
        }
        ids = new bytes32[](count);
        for (uint256 j = 0; j < count; ) {
            ids[j] = temp[j];
            unchecked {
                ++j;
            }
        }
    }

    // -------------------------------------------------------------------------
    // View: proof payload for segment (for off-chain verification)
    // -------------------------------------------------------------------------
    function getProofPayload(bytes32 segmentId) external view returns (
        bytes32 segmentId_,
        uint256 value,
        uint256 ordinalIndex,
        uint256 recordedAtBlock,
        bytes32 chainHash,
        bytes32 latticeDomain_
    ) {
        TrailSegment storage seg = _segments[segmentId];
        if (seg.recordedAtBlock == 0) revert BTrk_SegmentNotFound();
        return (
            segmentId,
            seg.value,
            seg.ordinalIndex,
            seg.recordedAtBlock,
            _previousChainHash[segmentId],
            latticeDomain
        );
    }

    // -------------------------------------------------------------------------
    // View: batch proof payloads for ordinal range
    // -------------------------------------------------------------------------
    function getProofPayloadsInOrdinalRange(uint256 startOrdinal, uint256 endOrdinal) external view returns (
        bytes32[] memory segmentIds_,
        uint256[] memory values,
        uint256[] memory ordinalIndices,
        uint256[] memory recordedAtBlocks,
        bytes32[] memory chainHashes
    ) {
        if (startOrdinal == 0 || endOrdinal < startOrdinal || endOrdinal > totalSegments) {
            revert BTrk_InvalidOrdinalRange();
        }
        uint256 len = endOrdinal - startOrdinal + 1;
        if (len > VIEW_BATCH_MAX) revert BTrk_ViewBatchTooLarge();
        segmentIds_ = new bytes32[](len);
        values = new uint256[](len);
        ordinalIndices = new uint256[](len);
        recordedAtBlocks = new uint256[](len);
        chainHashes = new bytes32[](len);
        for (uint256 i = 0; i < len; ) {
            bytes32 id = _segmentIds[startOrdinal + i - 1];
            TrailSegment storage seg = _segments[id];
            segmentIds_[i] = id;
            values[i] = seg.value;
            ordinalIndices[i] = seg.ordinalIndex;
            recordedAtBlocks[i] = seg.recordedAtBlock;
            chainHashes[i] = _previousChainHash[id];
            unchecked {
                ++i;
            }
        }
    }

    // -------------------------------------------------------------------------
    // View: lattice summary (single struct for dashboards)
    // -------------------------------------------------------------------------
    struct LatticeSummary {
        bytes32 domain;
        uint256 totalSegments;
        uint256 sealedCount;
        uint256 cumulativeValue;
        uint256 totalTrails;
        uint256 currentEpochIndex;
        uint256 deployBlock;
        uint256 lastRecordedBlock_;
        bool frozen;
    }

    function getLatticeSummary() external view returns (LatticeSummary memory s) {
        s.domain = latticeDomain;
        s.totalSegments = totalSegments;
        s.sealedCount = sealedCount;
        s.cumulativeValue = cumulativeValue;
        s.totalTrails = totalTrails;
        s.currentEpochIndex = currentEpochIndex;
        s.deployBlock = deployBlock;
        s.lastRecordedBlock_ = totalSegments == 0 ? 0 : _segments[_segmentIds[totalSegments - 1]].recordedAtBlock;
        s.frozen = latticeFrozen;
    }

    // -------------------------------------------------------------------------
    // View: last N segment ids by ordinal (most recent first)
    // -------------------------------------------------------------------------
    function getRecentSegmentIds(uint256 n) external view returns (bytes32[] memory ids) {
        if (n > VIEW_BATCH_MAX) revert BTrk_ViewBatchTooLarge();
        if (n == 0 || totalSegments == 0) return new bytes32[](0);
        uint256 start = totalSegments >= n ? totalSegments - n : 0;
        uint256 len = totalSegments - start;
        ids = new bytes32[](len);
        for (uint256 i = 0; i < len; ) {
            ids[i] = _segmentIds[start + i];
            unchecked {
                ++i;
            }
        }
    }

    // -------------------------------------------------------------------------
    // View: trail fingerprint (hash of trail id + segment count + total value + locked)
    // -------------------------------------------------------------------------
    function getTrailFingerprint(bytes32 trailId) external view returns (bytes32) {
        TrailInfo storage tr = _trails[trailId];
        if (tr.createdAtBlock == 0) revert BTrk_TrailNotFound();
        return keccak256(
            abi.encodePacked(
                trailId,
                tr.segmentCount,
                tr.totalValue,
                tr.locked,
                tr.createdAtBlock
            )
        );
    }

    // -------------------------------------------------------------------------
    // View: count of segments recorded in block range [fromBlock, toBlock]
    // -------------------------------------------------------------------------
    function segmentCountInBlockRange(uint256 fromBlock, uint256 toBlock) external view returns (uint256 count) {
        if (fromBlock > toBlock) return 0;
        for (uint256 i = 0; i < totalSegments; ) {
            uint256 b = _segments[_segmentIds[i]].recordedAtBlock;
            if (b >= fromBlock && b <= toBlock) count += 1;
            unchecked {
                ++i;
            }
        }
    }

    // -------------------------------------------------------------------------
    // View: batch check segment existence (returns same-length bool array)
    // -------------------------------------------------------------------------
    function hasSegments(bytes32[] calldata segmentIds) external view returns (bool[] memory exists) {
        if (segmentIds.length > VIEW_BATCH_MAX) revert BTrk_ViewBatchTooLarge();
        exists = new bool[](segmentIds.length);
        for (uint256 i = 0; i < segmentIds.length; ) {
            exists[i] = _segments[segmentIds[i]].recordedAtBlock != 0;
            unchecked {
                ++i;
            }
        }
    }

    // -------------------------------------------------------------------------
    // View: full segment data for ordinal range (value, block, ordinal, sealed, tag, weight, trail, chainHash)
    // -------------------------------------------------------------------------
    function getFullSegmentsInOrdinalRange(uint256 startOrdinal, uint256 endOrdinal) external view returns (
        bytes32[] memory segmentIds_,
        uint256[] memory values,
        uint256[] memory recordedAtBlocks,
        uint256[] memory ordinalIndices,
        bool[] memory sealedFlags,
        bytes32[] memory tags,
        uint64[] memory weights,
        bytes32[] memory trailIds,
        bytes32[] memory chainHashes
    ) {
        if (startOrdinal == 0 || endOrdinal < startOrdinal || endOrdinal > totalSegments) {
            revert BTrk_InvalidOrdinalRange();
        }
        uint256 len = endOrdinal - startOrdinal + 1;
        if (len > VIEW_BATCH_MAX) revert BTrk_ViewBatchTooLarge();
        segmentIds_ = new bytes32[](len);
        values = new uint256[](len);
        recordedAtBlocks = new uint256[](len);
        ordinalIndices = new uint256[](len);
        sealedFlags = new bool[](len);
        tags = new bytes32[](len);
        weights = new uint64[](len);
        trailIds = new bytes32[](len);
        chainHashes = new bytes32[](len);
        for (uint256 i = 0; i < len; ) {
            bytes32 id = _segmentIds[startOrdinal + i - 1];
            TrailSegment storage seg = _segments[id];
            segmentIds_[i] = id;
            values[i] = seg.value;
            recordedAtBlocks[i] = seg.recordedAtBlock;
            ordinalIndices[i] = seg.ordinalIndex;
            sealedFlags[i] = seg.sealed;
            tags[i] = _segmentTag[id];
            weights[i] = _segmentWeight[id];
            trailIds[i] = _segmentToTrail[id];
            chainHashes[i] = _previousChainHash[id];
            unchecked {
                ++i;
            }
        }
    }

    // -------------------------------------------------------------------------
    // View: average value in ordinal range (sum / count; 0 if empty range)
    // -------------------------------------------------------------------------
    function averageValueInOrdinalRange(uint256 startOrdinal, uint256 endOrdinal) external view returns (uint256 avg) {
        if (startOrdinal == 0 || endOrdinal < startOrdinal || endOrdinal > totalSegments) {
            revert BTrk_InvalidOrdinalRange();
        }
        uint256 len = endOrdinal - startOrdinal + 1;
        if (len > VIEW_BATCH_MAX) revert BTrk_ViewBatchTooLarge();
        uint256 sum = 0;
