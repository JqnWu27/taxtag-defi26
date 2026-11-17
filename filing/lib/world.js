// Synthetic chains for the filing side: a stand-in for the agency contract
// that follows SPEC.md sections 2, 3 and 5 (leaf formats, RCL append,
// nullifier consumption, PSL write-once entries, snapshot pinning). It lets
// the filing artifact generate ledgers with all Merkle paths without the
// recording side's contract. Simplification: a consumed nullifier enters
// the UNL SMT at once (the contract batches the log; the pinned root is the
// same once the batches cover the log).
const core = require("./core");
const { fmt, PosTree, Smt, recordLeafOf, pslEntryOf, DR } = core;

class Chain {
  static async create({ cid, acaddr, startBlock = 1000n, firstPositionId = 1n }) {
    const c = new Chain();
    c.cid = BigInt(cid);
    c.acaddr = BigInt(acaddr);
    c.rcl = new PosTree(DR, 0n);
    c.unl = await Smt.create();
    await c.unl.insert(1n, 1n);            // sentinel
    c.at = await Smt.create();
    c.psl = await Smt.create();
    c.block = BigInt(startBlock);
    c.lastTime = -1n;
    c.idxInBlock = 0n;
    c.nextPositionId = BigInt(firstPositionId);
    c.pslEntries = new Map();              // position id -> entry fields
    c.noiseSeed = 1n;
    return c;
  }

  // one block per distinct timestamp; one index counter per block shared by
  // record and recordPassive, so (time, cid, block, idx) is unique
  _coords(time) {
    time = BigInt(time);
    if (time < this.lastTime) throw new Error("chain time must not decrease");
    if (time !== this.lastTime) {
      this.block += 1n;
      this.idxInBlock = 0n;
      this.lastTime = time;
    }
    const idx = this.idxInBlock;
    this.idxInBlock += 1n;
    return { time, block: this.block, idx };
  }

  async writeAnchor(tag, S) {
    await this.at.insert(fmt.atIndex(tag), fmt.anchor(S));
  }

  newPositionId() {
    const id = this.nextPositionId;
    this.nextPositionId += 1n;
    return id;
  }

  // the contract side of `record`: every field of the leaf is written here
  async record({ nf, op, assetIn = 0n, amountIn = 0n, assetOut = 0n, amountOut = 0n,
                 value, positionId = 0n, time }) {
    const co = this._coords(time);
    const r = {
      nf, cid: this.cid, block: co.block, idx: co.idx, time: co.time,
      op: BigInt(op), assetIn: BigInt(assetIn), amountIn: BigInt(amountIn),
      assetOut: BigInt(assetOut), amountOut: BigInt(amountOut),
      value: BigInt(value), positionId: BigInt(positionId),
    };
    r.leaf = recordLeafOf(r);
    r.leafIndex = this.rcl.append(r.leaf);
    await this.unl.insert(nf, 1n);
    return r;
  }

  // the contract side of `recordPassive`: write-once PSL entry
  async recordPassive({ positionId, kind, assetA = 0n, amountA = 0n, assetB = 0n,
                        amountB = 0n, value = 0n, time }) {
    positionId = BigInt(positionId);
    if (this.pslEntries.has(positionId)) throw new Error("PSL entry is write-once");
    const co = this._coords(time);
    const e = {
      positionId, kind: BigInt(kind), cid: this.cid, block: co.block, idx: co.idx,
      time: co.time, assetA: BigInt(assetA), amountA: BigInt(amountA),
      assetB: BigInt(assetB), amountB: BigInt(amountB), value: BigInt(value),
    };
    e.entry = pslEntryOf(e);
    await this.psl.insert(positionId, e.entry);
    this.pslEntries.set(positionId, e);
    return e;
  }

  // records, nullifiers and positions of other users
  async noise(n, time) {
    for (let k = 0; k < n; k++) {
      this.noiseSeed += 1n;
      const s = this.noiseSeed;
      const co = this._coords(time);
      this.rcl.append(core.P([777n, this.cid, s, co.block, co.idx]));
      await this.unl.insert(core.P([778n, this.cid, s]), 1n);
    }
  }

  async noisePassive(time) {
    const id = this.newPositionId();
    await this.recordPassive({ positionId: id, kind: 2n, assetA: 2n, amountA: 1n,
                               assetB: 1n, amountB: 3n, value: 3n, time });
    return id;
  }

  // snapshot at the period boundary: frozen copies of the four structures
  async snapshot() {
    return {
      cid: this.cid, acaddr: this.acaddr,
      rcl: this.rcl.clone(), unl: await this.unl.clone(),
      at: await this.at.clone(), psl: await this.psl.clone(),
      pslEntries: new Map(this.pslEntries),
      rootRCL: this.rcl.root(), rootUNL: this.unl.root,
      rootAT: this.at.root, rootPSL: this.psl.root,
    };
  }
}

// The taxpayer's local view: tags, secrets, counters and copied records.
class Taxpayer {
  constructor(tags) {
    this.tags = tags.map((t) => ({
      tag: BigInt(t.tag), S: BigInt(t.S), idTax: fmt.idTax(BigInt(t.tag), BigInt(t.S)),
    }));
    this.counters = this.tags.map(() => [0n, 0n]);
    this.records = [];                     // own records, in recording order
  }
  addTag(t) {
    this.tags.push({ tag: BigInt(t.tag), S: BigInt(t.S),
                     idTax: fmt.idTax(BigInt(t.tag), BigInt(t.S)) });
    this.counters.push([0n, 0n]);
    return this.tags.length - 1;
  }
  async register(chains, slot) {
    for (const c of chains) await c.writeAnchor(this.tags[slot].tag, this.tags[slot].S);
  }
  // record one covered transaction under tag `slot` on chain slot `ch`
  async record(chains, slot, ch, fields) {
    const chain = chains[ch];
    const i = this.counters[slot][ch] + 1n;
    const nf = fmt.nullifier(this.tags[slot].idTax, chain.cid, chain.acaddr, i);
    const f = { ...fields };
    if (BigInt(f.op) === core.OP.PLEDGE && f.positionId === undefined) {
      f.positionId = chain.newPositionId();
    }
    const r = await chain.record({ nf, ...f });
    this.counters[slot][ch] = i;
    const own = { ...r, slot, ch, i };
    this.records.push(own);
    return own;
  }
}

module.exports = { Chain, Taxpayer };
