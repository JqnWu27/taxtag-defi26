// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// TaxTag agency contract (SPEC.md sections 2, 3 and 5).
//
// Root-only design: writers supply authenticated SMT paths, the
// contract verifies them against its stored roots and recomputes the new
// root along the path.
//
// Trees (circomlib-compatible compressed sparse Merkle trees: leaf hash
// P(key, value, 1), node P(left, right), empty subtree 0, key bits LSB first):
//   AT   anchor table          key P(3,tag)     -> P(2,S)   written by a TA, once
//   TRL  revocation list       key P(3,tag)     -> 1        written by a TA
//   UNL  used nullifiers       key NF           -> 1        batched from the log by anyone
//   PSL  position status list  key position_id  -> pentry   written by the venue, once
// RCL: depth-32 incremental append-only Merkle tree, node P(left, right),
//   empty leaf 0, leaf formed exactly as SPEC section 2:
//     meta = P(7, NF, cid, block, idx)
//     body = P(op, asset_in, amount_in, asset_out, amount_out)
//     tail = P(10, value, position_id, time, 0)
//     leaf = P(meta, body, tail)
//
// Root rule: a recording proof may cite ANY earlier RCL root and ANY earlier
// AT root (every root is kept in knownRCL / knownAT). The TRL root is always
// the current one. Nullifier freshness is checked against used[nf], so two
// recordings built against the same roots both land.

interface IPoseidon2 { function poseidon(uint256[2] calldata) external pure returns (uint256); }
interface IPoseidon3 { function poseidon(uint256[3] calldata) external pure returns (uint256); }
interface IPoseidon5 { function poseidon(uint256[5] calldata) external pure returns (uint256); }
interface IRecVerifier {
    function verifyProof(uint256[2] calldata a, uint256[2][2] calldata b,
        uint256[2] calldata c, uint256[8] calldata input) external view returns (bool);
}
interface IPriceFeed { function price() external view returns (uint256); }

contract AgencyContract {
    uint256 public constant RCL_DEPTH = 32;
    uint256 internal constant U64 = 1 << 64;
    // BN254 scalar field modulus: every SMT key and value must be below it
    uint256 internal constant SNARK_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // operation codes (SPEC section 2)
    uint256 internal constant OP_SWAP = 1;
    uint256 internal constant OP_PLEDGE = 2;
    uint256 internal constant OP_BORROW = 3;
    uint256 internal constant OP_REPAY = 4;
    uint256 internal constant OP_CLAIM = 5;
    // PSL entry kinds (SPEC sections 2 and 5)
    uint256 internal constant KIND_LIQUIDATION = 1;
    uint256 internal constant KIND_WITHDRAWAL = 2;

    struct SmtPath { uint256[] sibs; uint256 oldKey; uint256 oldValue; bool isOld0; }

    IPoseidon2 immutable P2;
    IPoseidon3 immutable P3;
    IPoseidon5 immutable P5;
    IRecVerifier public immutable verifier;
    uint256 public immutable keysetDigest;
    address public immutable admin;            // demo set-up owner (registries, asset table)

    mapping(address => bool) public isAgency;  // recognized TAs
    mapping(address => bool) public isEntry;   // registered entry contracts
    mapping(address => bool) public isVenue;   // covered venues

    // asset table: token -> (asset id 1..65535, price feed)
    struct Asset { uint16 id; address feed; }
    mapping(address => Asset) public assetOf;
    mapping(uint256 => address) public tokenOfAsset;

    uint256 public rootAT;
    uint256 public rootTRL;
    uint256 public rootUNL;
    uint256 public rootPSL;
    mapping(uint256 => bool) public knownAT;     // every AT root ever published
    mapping(uint256 => bool) public knownRCL;    // every RCL root ever published
    mapping(uint256 => uint256) public anchorAt; // convenience mirror of AT leaves

    // nullifiers: mapping for freshness, append log for the UNL batches
    mapping(uint256 => bool) public used;
    uint256[] public nfLog;
    uint256 public unlCovered;                   // log entries already in the UNL

    // RCL incremental tree
    uint256 public rootRCL;
    uint256 public nextLeafIndex;
    uint256[RCL_DEPTH] zeros;
    uint256[RCL_DEPTH] filled;

    // chain position: idx is the per-block sequence number of entries this
    // contract writes (records and PSL entries share it), because the EVM
    // does not expose the transaction index
    uint128 lastBlock;
    uint128 idxInBlock;

    // positions: opened by a pledge record, closed by a PSL entry
    struct Position { address venue; bool closed; }
    mapping(uint256 => Position) public positions;

    struct Snapshot { uint256 rcl; uint256 unl; uint256 at; uint256 psl; }
    mapping(uint32 => Snapshot) public snapshots;

    event AnchorWritten(uint256 indexed tagHash, uint256 anchor, uint256 newRootAT);
    event TagRevoked(uint256 indexed tagHash, uint256 newRootTRL);
    event EntryRegistered(address indexed entry);
    event VenueRegistered(address indexed venue);
    event AssetRegistered(address indexed token, uint256 assetId, address feed);
    // every leaf field, so a ledger can be rebuilt from (tag, S) alone
    event Recorded(uint256 indexed leafIndex, uint256 leaf, uint256 nf,
                   uint256 cid, uint256 blockNo, uint256 idx, uint256 time,
                   uint256 op, uint256 assetIn, uint256 amountIn,
                   uint256 assetOut, uint256 amountOut,
                   uint256 value, uint256 positionId, uint256 newRootRCL);
    event PassiveRecorded(uint256 indexed positionId, uint256 kind,
                   uint256 cid, uint256 blockNo, uint256 idx, uint256 time,
                   uint256 assetA, uint256 amountA, uint256 assetB, uint256 amountB,
                   uint256 value, uint256 entry, uint256 newRootPSL);
    event NullifiersInserted(uint256 fromIndex, uint256 count, uint256 newRootUNL);
    event SnapshotPinned(uint32 indexed period, uint256 rcl, uint256 unl,
                   uint256 at, uint256 psl, uint256 blockNo, uint256 time,
                   uint256 leafCount, uint256 nfCount);

    constructor(address _verifier, address _p2, address _p3, address _p5,
                uint256 _keysetDigest, address[] memory agencies) {
        verifier = IRecVerifier(_verifier);
        P2 = IPoseidon2(_p2); P3 = IPoseidon3(_p3); P5 = IPoseidon5(_p5);
        keysetDigest = _keysetDigest;
        admin = msg.sender;
        for (uint256 i = 0; i < agencies.length; i++) isAgency[agencies[i]] = true;
        // RCL zero subtrees; the empty root is a known root, so a first
        // record (whose proof leaves root_rcl unconstrained) can cite it
        uint256 z = 0;
        for (uint256 i = 0; i < RCL_DEPTH; i++) { zeros[i] = z; z = _h2(z, z); }
        rootRCL = z;
        knownRCL[z] = true;
    }

    modifier onlyAdmin() { require(msg.sender == admin, "not the owner"); _; }

    // ---- demo set-up: registries and asset table ---------------------------
    function registerEntry(address a) external onlyAdmin {
        isEntry[a] = true;
        emit EntryRegistered(a);
    }
    function registerVenue(address a) external onlyAdmin {
        isVenue[a] = true;
        emit VenueRegistered(a);
    }
    function registerAsset(address token, uint256 assetId, address feed) external onlyAdmin {
        require(token != address(0) && feed != address(0), "zero address");
        require(assetId >= 1 && assetId <= 65535, "asset id out of range");
        require(assetOf[token].id == 0, "token already registered");
        require(tokenOfAsset[assetId] == address(0), "asset id taken");
        assetOf[token] = Asset(uint16(assetId), feed);
        tokenOfAsset[assetId] = token;
        emit AssetRegistered(token, assetId, feed);
    }

    // ---- Poseidon helpers -------------------------------------------------
    function _h2(uint256 a, uint256 b) internal view returns (uint256) {
        return P2.poseidon([a, b]);
    }
    function _h1(uint256 key, uint256 value) internal view returns (uint256) {
        return P3.poseidon([key, value, 1]);   // circomlib SMT leaf hash
    }

    // ---- compressed-SMT verify + insert (circomlibjs-compatible) ----
    function _bit(uint256 key, uint256 i) internal pure returns (bool) {
        return (key >> i) & 1 == 1;
    }

    function _foldUp(uint256 leaf, uint256 key, uint256[] calldata sibs)
        internal view returns (uint256 cur)
    {
        cur = leaf;
        for (uint256 k = sibs.length; k > 0; k--) {
            uint256 i = k - 1;
            cur = _bit(key, i) ? _h2(sibs[i], cur) : _h2(cur, sibs[i]);
        }
    }

    function _smtInsert(uint256 root, uint256 key, uint256 value,
        uint256[] calldata sibs, uint256 oldKey, uint256 oldValue, bool isOld0)
        internal view returns (uint256)
    {
        // 0) canonical inputs only. The Poseidon contracts reduce their
        //    inputs mod the field, so oldKey and oldKey + p hash to the same
        //    leaf while having different bits; the push-down below is driven
        //    by those bits, so a non-canonical oldKey would let a caller of
        //    insertNullifiers place the old leaf off its own path and make a
        //    consumed nullifier provably "absent".
        //    isOld0 is a Solidity bool: the ABI decoder rejects anything but
        //    0 or 1.
        require(key < SNARK_FIELD && value < SNARK_FIELD, "key or value not a field element");
        if (isOld0) {
            require(oldKey == 0 && oldValue == 0, "old leaf given for an empty slot");
        } else {
            require(oldKey < SNARK_FIELD && oldValue < SNARK_FIELD, "old leaf not canonical");
            require(oldKey != key, "occupied");
        }

        // 1) exclusion proof against the given root
        uint256 oldLeaf = isOld0 ? 0 : _h1(oldKey, oldValue);
        require(_foldUp(oldLeaf, key, sibs) == root, "bad exclusion proof");

        // 2) recompute the root with the new leaf inserted
        uint256 newLeaf = _h1(key, value);
        uint256 cur;
        uint256 L = sibs.length;
        if (isOld0) {
            cur = newLeaf;
        } else {
            // push the colliding old leaf down to the first divergent bit
            uint256 j = L;
            while (_bit(key, j) == _bit(oldKey, j)) { j++; }
            cur = _bit(key, j) ? _h2(oldLeaf, newLeaf) : _h2(newLeaf, oldLeaf);
            for (uint256 k = j; k > L; k--) {
                cur = _bit(key, k - 1) ? _h2(0, cur) : _h2(cur, 0);
            }
        }
        return _foldUp(cur, key, sibs);
    }

    // ---- agency (TA) functions, with the root history ---
    function writeAnchor(uint256 tagHash, uint256 anchor,
        uint256[] calldata sibs, uint256 oldKey, uint256 oldValue, bool isOld0)
        external
    {
        require(isAgency[msg.sender], "not a recognized TA");
        require(anchor != 0, "empty anchor");
        require(anchorAt[tagHash] == 0, "occupied");        // write-once
        uint256 r = _smtInsert(rootAT, tagHash, anchor, sibs, oldKey, oldValue, isOld0);
        rootAT = r;
        knownAT[r] = true;
        anchorAt[tagHash] = anchor;
        emit AnchorWritten(tagHash, anchor, r);
    }

    function revokeTag(uint256 tagHash,
        uint256[] calldata sibs, uint256 oldKey, uint256 oldValue, bool isOld0)
        external
    {
        require(isAgency[msg.sender], "not a recognized TA");
        uint256 r = _smtInsert(rootTRL, tagHash, 1, sibs, oldKey, oldValue, isOld0);
        rootTRL = r;
        emit TagRevoked(tagHash, r);
    }

    // ---- shared helpers for record / recordPassive -------------------------
    function _asset(address token) internal view returns (uint256 id, address feed) {
        if (token == address(0)) return (0, address(0));
        Asset memory a = assetOf[token];
        require(a.id != 0, "asset not covered");
        return (a.id, a.feed);
    }

    function _nextIdx() internal returns (uint256 idx) {
        if (block.number != lastBlock) {
            lastBlock = uint128(block.number);
            idxInBlock = 0;
        }
        idx = idxInBlock++;
    }

    function _appendRCL(uint256 leaf) internal returns (uint256 leafIndex, uint256 root) {
        leafIndex = nextLeafIndex++;
        require(leafIndex < (1 << RCL_DEPTH), "RCL full");
        uint256 cur = leaf;
        uint256 pos = leafIndex;
        // Only the lowest level at which this path is a left child roots a
        // subtree that is now complete; that node is the one later appends
        // read as their left sibling, so it is the only one stored (one
        // storage write per append).
        bool stored = false;
        for (uint256 lvl = 0; lvl < RCL_DEPTH; lvl++) {
            if (pos & 1 == 0) {
                if (!stored) { filled[lvl] = cur; stored = true; }
                cur = _h2(cur, zeros[lvl]);
            } else {
                cur = _h2(filled[lvl], cur);
            }
            pos >>= 1;
        }
        root = cur;
        rootRCL = cur;
        knownRCL[cur] = true;
    }

    // which fields each operation uses (SPEC section 2 table); unused = 0
    function _checkShape(uint256 op, uint256 aIn, uint256 amountIn,
        uint256 aOut, uint256 amountOut, uint256 positionId) internal pure
    {
        bool hasIn = aIn != 0 && amountIn != 0;
        bool noIn = aIn == 0 && amountIn == 0;
        bool hasOut = aOut != 0 && amountOut != 0;
        bool noOut = aOut == 0 && amountOut == 0;
        if (op == OP_SWAP) {
            require(hasIn && hasOut && positionId == 0, "bad swap fields");
        } else if (op == OP_PLEDGE) {
            require(hasIn && (hasOut || noOut) && positionId != 0, "bad pledge fields");
        } else if (op == OP_BORROW) {
            require(noIn && hasOut && positionId != 0, "bad borrow fields");
        } else if (op == OP_REPAY) {
            require(hasIn && noOut && positionId != 0, "bad repay fields");
        } else if (op == OP_CLAIM) {
            require(noIn && hasOut && positionId == 0, "bad claim fields");
        } else {
            revert("unknown operation");
        }
    }

    // ---- recording ----------------------------------------------------------
    // Called by the entry contract (pool, router, aggregator, wrapper) or the
    // covered venue inside its executing transaction, so the append and the
    // nullifier consumption are atomic with the transfer. `owner` is the
    // address the entry contract reports as the owner of the moved assets.
    // `proof` is the Groth16 proof (a, b, c) flattened as snarkjs prints it
    // for Solidity: [a0, a1, b00, b01, b10, b11, c0, c1].
    function record(
        uint256 nf, address owner, uint256[8] calldata proof,
        uint256 rootRCL_, uint256 rootAT_,
        uint256 op, address tokenIn, uint256 amountIn,
        address tokenOut, uint256 amountOut, uint256 positionId
    ) external returns (uint256 leafIndex) {
        require(isEntry[msg.sender] || isVenue[msg.sender],
                "not an entry contract or covered venue");
        require(knownRCL[rootRCL_], "unknown RCL root");
        require(knownAT[rootAT_], "unknown AT root");
        require(!used[nf], "nullifier used");

        // Groth16 verification; public-input order matches c_rec.circom
        {
            uint256[8] memory pub = [nf, rootRCL_, rootAT_, rootTRL,
                keysetDigest, block.chainid,
                uint256(uint160(address(this))), uint256(uint160(owner))];
            require(verifier.verifyProof([proof[0], proof[1]],
                [[proof[2], proof[3]], [proof[4], proof[5]]],
                [proof[6], proof[7]], pub), "invalid proof");
        }

        // consume the nullifier: mark used, append to the log
        used[nf] = true;
        nfLog.push(nf);

        // every field below is written by the contract
        (uint256 aIn, address feedIn) = _asset(tokenIn);
        (uint256 aOut, address feedOut) = _asset(tokenOut);
        _checkShape(op, aIn, amountIn, aOut, amountOut, positionId);
        require(amountIn < U64 && amountOut < U64 && positionId < U64, "field out of range");
        uint256 value = amountOut != 0
            ? amountOut * IPriceFeed(feedOut).price()
            : amountIn * IPriceFeed(feedIn).price();
        require(value < U64, "value out of range");

        if (op == OP_PLEDGE) {
            require(positions[positionId].venue == address(0), "position id taken");
            positions[positionId] = Position(msg.sender, false);
        } else if (op == OP_BORROW || op == OP_REPAY) {
            Position memory p = positions[positionId];
            require(p.venue == msg.sender && !p.closed, "not an open position of the caller");
        }

        uint256 leaf;
        uint256 idx = _nextIdx();
        {
            uint256 meta = P5.poseidon([7, nf, block.chainid, block.number, idx]);
            uint256 body = P5.poseidon([op, aIn, amountIn, aOut, amountOut]);
            uint256 tail = P5.poseidon([10, value, positionId, block.timestamp, 0]);
            leaf = P3.poseidon([meta, body, tail]);
        }
        uint256 newRoot;
        (leafIndex, newRoot) = _appendRCL(leaf);

        emit Recorded(leafIndex, leaf, nf, block.chainid, block.number, idx,
                      block.timestamp, op, aIn, amountIn, aOut, amountOut,
                      value, positionId, newRoot);
    }

    // ---- nullifier batches --------------------------------------------------
    // Anyone. Inserts the next paths.length logged nullifiers into the UNL in
    // log order, each with a non-membership path against the running root.
    function insertNullifiers(uint256 fromIndex, SmtPath[] calldata paths) external {
        require(fromIndex == unlCovered, "batch does not start at the covered index");
        uint256 n = paths.length;
        require(fromIndex + n <= nfLog.length, "batch runs past the log");
        uint256 root = rootUNL;
        for (uint256 k = 0; k < n; k++) {
            root = _smtInsert(root, nfLog[fromIndex + k], 1, paths[k].sibs,
                              paths[k].oldKey, paths[k].oldValue, paths[k].isOld0);
        }
        rootUNL = root;
        unlCovered = fromIndex + n;
        emit NullifiersInserted(fromIndex, n, root);
    }

    // ---- passive events (SPEC section 5) -------------------------------------
    // Covered venue only, no taxpayer proof. kind 1 liquidation:
    //   (tokenA, amountA) = collateral seized, (tokenB, amountB) = debt covered.
    // kind 2 withdrawal:
    //   (tokenA, amountA) = collateral returned, (tokenB, amountB) = interest.
    // value = oracle value of (tokenB, amountB). Write-once at key positionId.
    function recordPassive(uint256 positionId, uint256 kind,
        address tokenA, uint256 amountA, address tokenB, uint256 amountB,
        uint256[] calldata sibs, uint256 oldKey, uint256 oldValue, bool isOld0)
        external
    {
        require(isVenue[msg.sender], "not a covered venue");
        require(kind == KIND_LIQUIDATION || kind == KIND_WITHDRAWAL, "unknown kind");
        {
            Position memory p = positions[positionId];
            require(p.venue == msg.sender, "not a position of the caller");
            require(!p.closed, "position already closed");
            positions[positionId].closed = true;
        }
        (uint256 a, ) = _asset(tokenA);
        (uint256 b, address feedB) = _asset(tokenB);
        require(a != 0 && amountA != 0, "collateral missing");
        require((b != 0 && amountB != 0) || (b == 0 && amountB == 0), "bad second leg");
        if (kind == KIND_LIQUIDATION) require(amountB != 0, "no debt covered");
        require(amountA < U64 && amountB < U64, "field out of range");
        uint256 value = amountB != 0 ? amountB * IPriceFeed(feedB).price() : 0;
        require(value < U64, "value out of range");

        uint256 idx = _nextIdx();
        uint256 pentry;
        {
            uint256 pmeta = P5.poseidon([11, kind, block.chainid, block.number, idx]);
            uint256 pbody = P5.poseidon([a, amountA, b, amountB, value]);
            pentry = P3.poseidon([pmeta, pbody, block.timestamp]);
        }
        uint256 r = _smtInsert(rootPSL, positionId, pentry, sibs, oldKey, oldValue, isOld0);
        rootPSL = r;

        emit PassiveRecorded(positionId, kind, block.chainid, block.number, idx,
                             block.timestamp, a, amountA, b, amountB, value, pentry, r);
    }

    // ---- reads / snapshot ----------------------------------------------------
    function currentRoots() external view
        returns (uint256 rcl, uint256 unl, uint256 at, uint256 trl, uint256 psl)
    { return (rootRCL, rootUNL, rootAT, rootTRL, rootPSL); }

    function nfLogLength() external view returns (uint256) { return nfLog.length; }

    // Anyone. Pins (rootRCL, rootUNL, rootAT, rootPSL) for the period, once,
    // and only when the UNL batches cover the whole nullifier log.
    function pinSnapshot(uint32 period) external {
        require(unlCovered == nfLog.length, "UNL batches do not cover the log");
        require(snapshots[period].rcl == 0, "period already pinned");
        snapshots[period] = Snapshot(rootRCL, rootUNL, rootAT, rootPSL);
        emit SnapshotPinned(period, rootRCL, rootUNL, rootAT, rootPSL,
                            block.number, block.timestamp, nextLeafIndex, nfLog.length);
    }
}
