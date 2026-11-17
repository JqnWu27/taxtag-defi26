// TaxTag filing side, JS reference: Poseidon layouts of SPEC.md
// section 2 and the authenticated structures.
//
//   RCL   positional append-only Merkle tree, depth 32, empty leaf 0
//   UNL / PSL / AT   circomlib sparse Merkle trees (circomlibjs SMT)
//   asset tree       positional, depth 16, index = asset id, leaf P(q, avg),
//                    every leaf starts as P(0, 0)
//   ledger tree      positional, depth 4, leaf P(id_tax, n_chain0, n_chain1),
//                    empty slot P(0, 0, 0)
//   open-position tree  positional, depth 16, leaf P(P(cid, position_id),
//                    mark), empty slot P(0, 0)
const { buildPoseidon, newMemEmptyTrie } = require("circomlibjs");

const DR = 32;        // RCL depth
const DA = 16;        // asset tree and open-position tree depth
const DL = 4;         // ledger tree depth (16 tag slots)
const DP = 32;        // PSL SMT levels opened in the step circuit
const MIN_STEPS = 64; // padding floor
const TWO64 = 1n << 64n;

const OP = { SWAP: 1n, PLEDGE: 2n, BORROW: 3n, REPAY: 4n, CLAIM: 5n };
const PKIND = { LIQUIDATION: 1n, WITHDRAWAL: 2n };
const KIND = { PAD: 0n, RECORD: 1n, PSL: 2n, OPEN: 3n };

let poseidon = null;
let F = null;

async function init() {
  if (!poseidon) {
    poseidon = await buildPoseidon();
    F = poseidon.F;
  }
  return module.exports;
}

function P(arr) {
  return F.toObject(poseidon(arr.map((x) => F.e(x))));
}

// ---- SPEC section 2 formats ------------------------------------------------
const fmt = {
  idTax: (tag, S) => P([1n, tag, S]),
  anchor: (S) => P([2n, S]),
  atIndex: (tag) => P([3n, tag]),
  nullifier: (idTax, cid, acaddr, i) => P([8n, idTax, cid, acaddr, i]),
  leafMeta: (nf, cid, block, idx) => P([7n, nf, cid, block, idx]),
  leafBody: (op, assetIn, amountIn, assetOut, amountOut) =>
    P([op, assetIn, amountIn, assetOut, amountOut]),
  leafTail: (value, positionId, time) => P([10n, value, positionId, time, 0n]),
  recordLeaf: (meta, body, tail) => P([meta, body, tail]),
  pslMeta: (kind, cid, block, idx) => P([11n, kind, cid, block, idx]),
  pslBody: (assetA, amountA, assetB, amountB, value) =>
    P([assetA, amountA, assetB, amountB, value]),
  pslEntry: (pmeta, pbody, time) => P([pmeta, pbody, time]),
  blindY: (S, y) => P([13n, S, y]),
  closingCommitment: (stateDigest, blind) => P([stateDigest, blind]),
  // filing-side layouts
  closingDigest: (rootAssets, rootLedger, rootOpen, nOpen) =>
    P([12n, rootAssets, rootLedger, rootOpen, nOpen]),
  assetLeaf: (q, avg) => P([q, avg]),
  ledgerLeaf: (idTax, n0, n1) => P([idTax, n0, n1]),
  openKey: (cid, positionId) => P([cid, positionId]),
  openLeaf: (key, mark) => P([key, mark]),
  pins: (p) => P(p),
  stateDigest: (s) => P(s),
  stateBlind: (S, y) => P([14n, S, y]),
};

function recordLeafOf(r) {
  return fmt.recordLeaf(
    fmt.leafMeta(r.nf, r.cid, r.block, r.idx),
    fmt.leafBody(r.op, r.assetIn, r.amountIn, r.assetOut, r.amountOut),
    fmt.leafTail(r.value, r.positionId, r.time));
}

function pslEntryOf(e) {
  return fmt.pslEntry(
    fmt.pslMeta(e.kind, e.cid, e.block, e.idx),
    fmt.pslBody(e.assetA, e.amountA, e.assetB, e.amountB, e.value),
    e.time);
}

// ---- positional Merkle tree, sparse storage ---------------------------------
class PosTree {
  constructor(depth, zeroLeaf = 0n) {
    this.depth = depth;
    this.zeros = [zeroLeaf];
    for (let k = 0; k < depth; k++) this.zeros.push(P([this.zeros[k], this.zeros[k]]));
    this.levels = [];
    for (let k = 0; k <= depth; k++) this.levels.push(new Map());
    this.size = 0;                   // next append index
  }
  clone() {
    const t = Object.create(PosTree.prototype);
    t.depth = this.depth;
    t.zeros = this.zeros;
    t.levels = this.levels.map((m) => new Map(m));
    t.size = this.size;
    return t;
  }
  node(level, index) {
    const v = this.levels[level].get(index);
    return v === undefined ? this.zeros[level] : v;
  }
  get(index) { return this.node(0, index); }
  set(index, leaf) {
    let cur = leaf;
    let p = index;
    this.levels[0].set(p, cur);
    for (let k = 0; k < this.depth; k++) {
      const sib = this.node(k, p ^ 1);
      cur = (p & 1) ? P([sib, cur]) : P([cur, sib]);
      p = Math.floor(p / 2);
      this.levels[k + 1].set(p, cur);
    }
    if (index >= this.size) this.size = index + 1;
  }
  append(leaf) {
    const index = this.size;
    this.set(index, leaf);
    return index;
  }
  root() { return this.node(this.depth, 0); }
  // siblings bottom-up
  path(index) {
    const sibs = [];
    let p = index;
    for (let k = 0; k < this.depth; k++) {
      sibs.push(this.node(k, p ^ 1));
      p = Math.floor(p / 2);
    }
    return sibs;
  }
  static rootFrom(leaf, index, sibs) {
    let cur = leaf;
    let p = index;
    for (let k = 0; k < sibs.length; k++) {
      cur = (p & 1) ? P([sibs[k], cur]) : P([cur, sibs[k]]);
      p = Math.floor(p / 2);
    }
    return cur;
  }
}

// bit-reversal of a leaf index over `bits` bits (DualPath reads the RCL path
// top-down)
function bitReverse(index, bits) {
  let r = 0n;
  let v = BigInt(index);
  for (let k = 0; k < bits; k++) {
    r = (r << 1n) | (v & 1n);
    v >>= 1n;
  }
  return r;
}

// ---- circomlib sparse Merkle tree with an insert log ------------------------
class Smt {
  static async create() {
    const s = new Smt();
    s.tree = await newMemEmptyTrie();
    s.log = [];
    return s;
  }
  async insert(key, value) {
    await this.tree.insert(F.e(key), F.e(value));
    this.log.push([key, value]);
  }
  get root() { return F.toObject(this.tree.root); }
  async clone() {
    const s = await Smt.create();
    for (const [k, v] of this.log) await s.insert(k, v);
    return s;
  }
  // proof for `key`, siblings zero padded to `depth`
  async proof(key, depth) {
    const res = await this.tree.find(F.e(key));
    if (res.siblings.length >= depth) {
      throw new Error(`SMT proof needs ${res.siblings.length + 1} levels, circuit has ${depth}`);
    }
    const siblings = res.siblings.map((s) => F.toObject(s));
    while (siblings.length < depth) siblings.push(0n);
    if (res.found) {
      return { found: true, value: F.toObject(res.foundValue), siblings,
               oldKey: 0n, oldValue: 0n, isOld0: 0n };
    }
    return {
      found: false, siblings,
      oldKey: res.isOld0 ? 0n : F.toObject(res.notFoundKey),
      oldValue: res.isOld0 ? 0n : F.toObject(res.notFoundValue),
      isOld0: res.isOld0 ? 1n : 0n,
    };
  }
}

function nextPow2(n) {
  let p = 1;
  while (p < n) p *= 2;
  return p;
}

module.exports = {
  init, P, fmt, recordLeafOf, pslEntryOf, PosTree, Smt, bitReverse, nextPow2,
  DR, DA, DL, DP, MIN_STEPS, TWO64, OP, PKIND, KIND,
  get F() { return F; },
};
