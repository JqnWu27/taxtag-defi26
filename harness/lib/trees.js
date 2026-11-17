// Independent JavaScript mirrors of the agency contract's trees.
//   Smt  circomlibjs sparse Merkle tree (AT, TRL, UNL, PSL)
//   Rcl  depth-32 positional append-only Merkle tree, recomputed from the
//        full leaf list on every query (deliberately NOT the contract's
//        filled-subtree algorithm, so the two implementations are independent)
const { newMemEmptyTrie } = require("circomlibjs");

class Smt {
  static async create(F) {
    const s = new Smt();
    s.F = F;
    s.trie = await newMemEmptyTrie();
    s.leaves = [];          // [key, value] in insertion order
    return s;
  }
  root() { return this.F.toObject(this.trie.root); }
  async insert(key, value) {
    await this.trie.insert(this.F.e(key), this.F.e(value));
    this.leaves.push([BigInt(key), BigInt(value)]);
  }
  async has(key) { return (await this.trie.find(this.F.e(key))).found; }
  // siblings of an existing key (inclusion), unpadded
  async inclusion(key) {
    const res = await this.trie.find(this.F.e(key));
    if (!res.found) throw new Error("key not in tree");
    return {
      siblings: res.siblings.map((s) => this.F.toObject(s)),
      value: this.F.toObject(res.foundValue),
    };
  }
  // non-membership data for an absent key, in the shape the contract's
  // _smtInsert and circomlib's SMTVerifier(fnc = 1) take
  async exclusion(key) {
    const res = await this.trie.find(this.F.e(key));
    if (res.found) throw new Error("key already present");
    return {
      siblings: res.siblings.map((s) => this.F.toObject(s)),
      oldKey: res.isOld0 ? 0n : this.F.toObject(res.notFoundKey),
      oldValue: res.isOld0 ? 0n : this.F.toObject(res.notFoundValue),
      isOld0: !!res.isOld0,
    };
  }
}

const pad = (arr, n) => {
  const out = arr.slice();
  if (out.length > n) throw new Error(`path longer than depth ${n}`);
  while (out.length < n) out.push(0n);
  return out;
};

class Rcl {
  constructor(H, depth) {
    this.H = H;
    this.depth = depth;
    this.leaves = [];
    this.zeros = [0n];
    for (let k = 0; k < depth; k++) this.zeros.push(H.node(this.zeros[k], this.zeros[k]));
  }
  append(leaf) { this.leaves.push(BigInt(leaf)); return this.leaves.length - 1; }
  // root over the first n leaves (default: all); also returns the path of
  // leaf `index` when asked
  _walk(n, index) {
    let cur = this.leaves.slice(0, n);
    let idx = index;
    const siblings = [];
    for (let lvl = 0; lvl < this.depth; lvl++) {
      if (index !== undefined) {
        const sib = idx ^ 1;
        siblings.push(sib < cur.length ? cur[sib] : this.zeros[lvl]);
        idx >>= 1;
      }
      const next = [];
      for (let j = 0; j < cur.length; j += 2) {
        const l = cur[j];
        const r = j + 1 < cur.length ? cur[j + 1] : this.zeros[lvl];
        next.push(this.H.node(l, r));
      }
      cur = next;
    }
    const root = cur.length ? cur[0] : this.zeros[this.depth];
    return { root, siblings };
  }
  root(n = this.leaves.length) {
    // leaves are append-only, so the root of the first n leaves never changes
    if (!this._roots) this._roots = new Map();
    if (!this._roots.has(n)) this._roots.set(n, this._walk(n).root);
    return this._roots.get(n);
  }
  path(index, n = this.leaves.length) {
    if (index >= n) throw new Error("leaf not in the tree at this size");
    return this._walk(n, index);
  }
}

module.exports = { Smt, Rcl, pad };
