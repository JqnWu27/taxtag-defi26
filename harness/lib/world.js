// One in-process chain with the TaxTag contracts deployed, plus the
// independent JavaScript mirrors every contract root is checked against.
//
// A World owns: a ganache provider (deterministic accounts and block
// timestamps), the agency contract, the demo contracts, the mirrors
// (lib/trees.js) and the per-tag local ledgers. Every state-changing helper
// asserts contract state against the mirror after the transaction.
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const solc = require("solc");
// ganache prints a multi-line notice at load time when its optional native
// WebSocket binary does not match the Node version ("This version of uWS is
// not compatible ... Falling back to a NodeJS implementation"). The
// in-process provider used here has no socket at all, so the notice is
// noise; it is dropped for the duration of this one require call only.
const ganache = (() => {
  const write = process.stderr.write;
  process.stderr.write = () => true;
  try { return require("ganache"); } finally { process.stderr.write = write; }
})();
const { ethers } = require("ethers");
const snarkjs = require("snarkjs");
const { poseidonContract } = require("circomlibjs");
const { init, PARAMS, OP, KIND } = require("./hashes");
const { Smt, Rcl, pad } = require("./trees");

const ROOT = path.resolve(__dirname, "..", "..");
const OUT = path.join(ROOT, "out", "rec");
const WASM = path.join(OUT, "c_rec_js", "c_rec.wasm");
const ZKEY = path.join(OUT, "c_rec.zkey");
const VKEY = path.join(OUT, "c_rec.vkey.json");
const MNEMONIC = "test test test test test test test test test test test junk";
const ROLES = ["admin", "ta", "alice", "bob", "carol", "dave", "liquidator", "mallory"];

const S = (x) => BigInt(x).toString();
const assertEq = (label, a, b) => {
  if (BigInt(a) !== BigInt(b)) throw new Error(`${label}: ${a} != ${b}`);
};

// ---- contract compilation (cached on the source hash) ----------------------
const CONTRACT_FILES = [
  "AgencyContract.sol",
  "demo/Interfaces.sol", "demo/MockToken.sol", "demo/MockPriceFeed.sol",
  "demo/CoveredPool.sol", "demo/PlainPool.sol", "demo/Aggregator.sol",
  "demo/PoolWrapper.sol", "demo/LendingVenue.sol",
  "test/TestHelpers.sol",
];

function compileContracts() {
  const srcDir = path.join(ROOT, "contracts");
  const sources = {};
  for (const f of CONTRACT_FILES) {
    sources[f] = { content: fs.readFileSync(path.join(srcDir, f), "utf8") };
  }
  sources["Verifier_c_rec.sol"] = {
    content: fs.readFileSync(path.join(OUT, "Verifier_c_rec.sol"), "utf8"),
  };
  const settings = {
    evmVersion: "paris",
    viaIR: true,
    optimizer: { enabled: true, runs: 200 },
    outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } },
  };
  const key = crypto.createHash("sha256")
    .update(JSON.stringify({ sources, settings, v: solc.version() })).digest("hex");
  const cacheFile = path.join(OUT, "contracts.cache.json");
  if (fs.existsSync(cacheFile)) {
    const c = JSON.parse(fs.readFileSync(cacheFile, "utf8"));
    if (c.key === key) return c.artifacts;
  }
  const out = JSON.parse(solc.compile(JSON.stringify({ language: "Solidity", sources, settings })));
  const fatal = (out.errors || []).filter((e) => e.severity === "error");
  if (fatal.length) {
    throw new Error("solc: " + fatal.map((e) => e.formattedMessage).join("\n"));
  }
  const artifacts = {};
  for (const file of Object.keys(out.contracts)) {
    for (const name of Object.keys(out.contracts[file])) {
      artifacts[name] = {
        abi: out.contracts[file][name].abi,
        bytecode: "0x" + out.contracts[file][name].evm.bytecode.object,
      };
    }
  }
  fs.writeFileSync(cacheFile, JSON.stringify({ key, solc: solc.version(), artifacts }));
  return artifacts;
}

// Groth16 proof -> the 8 words record() takes (snarkjs Solidity ordering)
function proofToWords(proof) {
  return [
    proof.pi_a[0], proof.pi_a[1],
    proof.pi_b[0][1], proof.pi_b[0][0],
    proof.pi_b[1][1], proof.pi_b[1][0],
    proof.pi_c[0], proof.pi_c[1],
  ];
}

class World {
  // opts: chainId, genesis (ISO date), ethPrice, stubVerifier (gas sweep only)
  static async create(opts = {}) {
    const w = new World();
    w.c = await init();
    w.H = w.c.H;
    w.F = w.c.F;
    w.chainId = opts.chainId ?? 1337;
    w.cid = BigInt(w.chainId);
    w.blockSeconds = 12;
    w.quiet = !!opts.quiet;
    w.gas = [];
    w.proveMs = [];

    w.ganache = ganache.provider({
      logging: { quiet: true },
      chain: { chainId: w.chainId, time: new Date(opts.genesis ?? "2026-01-05T00:00:00Z") },
      wallet: { mnemonic: MNEMONIC, totalAccounts: ROLES.length },
      miner: { timestampIncrement: w.blockSeconds, blockGasLimit: opts.blockGasLimit ?? 30000000 },
    });
    // cacheTimeout -1: ethers otherwise caches the block number for 250 ms,
    // and a receipt of a block newer than the cached number makes wait()
    // fall back to polling (4 s by default) for every quick transaction
    w.provider = new ethers.BrowserProvider(w.ganache, undefined,
      { cacheTimeout: -1, pollingInterval: 25 });
    w.signers = {};
    w.addr = {};
    for (let k = 0; k < ROLES.length; k++) {
      w.signers[ROLES[k]] = await w.provider.getSigner(k);
      w.addr[ROLES[k]] = await w.signers[ROLES[k]].getAddress();
    }
    const net = await w.provider.getNetwork();
    assertEq("chain id", net.chainId, w.cid);

    // ---- deploy ----
    w.art = compileContracts();
    const admin = w.signers.admin;
    const deployRaw = async (nIn) => {
      const abi = poseidonContract.generateABI(nIn);
      let code = poseidonContract.createCode(nIn);
      if (!code.startsWith("0x")) code = "0x" + code;
      const f = new ethers.ContractFactory(abi, code, admin);
      const c = await f.deploy(); await c.waitForDeployment(); return c;
    };
    w.p2 = await deployRaw(2); w.p3 = await deployRaw(3); w.p5 = await deployRaw(5);
    w.verifier = await w.deploy(opts.stubVerifier ? "StubVerifier" : "Groth16Verifier");
    w.agency = await w.deploy("AgencyContract", [
      await w.verifier.getAddress(), await w.p2.getAddress(),
      await w.p3.getAddress(), await w.p5.getAddress(),
      w.c.keysetDigest, [w.addr.ta],
    ]);
    w.acaddrHex = await w.agency.getAddress();
    w.acaddr = BigInt(w.acaddrHex);
    w.probe = await w.deploy("GasProbe");

    // tokens, feeds, asset table. Token units: USDC 1 unit = 1 USDC,
    // ETH 1 unit = 0.01 ETH. Feeds quote USD per token unit.
    w.ethPrice = BigInt(opts.ethPrice ?? 30);
    w.usdc = await w.deploy("MockToken", ["USD Coin (mock)", "USDC", 0]);
    w.eth = await w.deploy("MockToken", ["Ether (mock)", "ETH", 2]);
    w.feedUsdc = await w.deploy("MockPriceFeed", [1]);
    w.feedEth = await w.deploy("MockPriceFeed", [w.ethPrice]);
    w.USDC = await w.usdc.getAddress();
    w.ETH = await w.eth.getAddress();
    w.assets = [
      { asset_id: 1, symbol: "USDC", token: w.USDC, decimals: 0, unit: "1 USDC" },
      { asset_id: 2, symbol: "ETH", token: w.ETH, decimals: 2, unit: "0.01 ETH" },
    ];
    w.assetId = { [w.USDC]: 1n, [w.ETH]: 2n, [ethers.ZeroAddress]: 0n };
    await (await w.agency.registerAsset(w.USDC, 1, await w.feedUsdc.getAddress())).wait();
    await (await w.agency.registerAsset(w.ETH, 2, await w.feedEth.getAddress())).wait();

    // venues and entry contracts
    w.poolA = await w.deploy("CoveredPool", [w.acaddrHex, w.ETH, w.USDC, w.ethPrice, 1]);
    w.poolB = await w.deploy("CoveredPool", [w.acaddrHex, w.ETH, w.USDC, w.ethPrice, 1]);
    w.aggregator = await w.deploy("Aggregator", [w.acaddrHex]);
    w.lending = await w.deploy("LendingVenue", [w.acaddrHex, 1001, w.USDC]);
    w.plainPool = await w.deploy("PlainPool", [w.ETH, w.USDC, w.ethPrice, 1]);
    w.wrapper = await w.deploy("PoolWrapper", [w.acaddrHex, await w.plainPool.getAddress()]);
    w.contracts = {
      poolA: await w.poolA.getAddress(), poolB: await w.poolB.getAddress(),
      aggregator: await w.aggregator.getAddress(), lending: await w.lending.getAddress(),
      plainPool: await w.plainPool.getAddress(), wrapper: await w.wrapper.getAddress(),
    };
    await (await w.agency.registerVenue(w.contracts.poolA)).wait();
    await (await w.agency.registerVenue(w.contracts.poolB)).wait();
    await (await w.agency.registerVenue(w.contracts.lending)).wait();
    await (await w.agency.registerEntry(w.contracts.aggregator)).wait();
    await (await w.agency.registerEntry(w.contracts.wrapper)).wait();
    // liquidity for the mocks
    for (const a of [w.contracts.poolA, w.contracts.poolB, w.contracts.lending, w.contracts.plainPool]) {
      await (await w.usdc.mint(a, 1000000000)).wait();
      await (await w.eth.mint(a, 10000000)).wait();
    }

    // ---- mirrors ----
    w.m = {
      at: await Smt.create(w.F), trl: await Smt.create(w.F),
      unl: await Smt.create(w.F), psl: await Smt.create(w.F),
      rcl: new Rcl(w.H, PARAMS.DR),
      nfLog: [], unlCovered: 0,
      records: [], passive: [], snapshots: [],
    };
    w.ledgers = new Map();     // tag name -> records of that tag on this chain
    w.tags = new Map();
    await w.checkRoots("after deployment");
    return w;
  }

  log(...a) { if (!this.quiet) console.log(...a); }

  async deploy(name, args = [], signer = this.signers.admin) {
    const a = this.art[name];
    if (!a) throw new Error("no artifact " + name);
    const f = new ethers.ContractFactory(a.abi, a.bytecode, signer);
    const c = await f.deploy(...args);
    await c.waitForDeployment();
    return c;
  }

  // ---- time -----------------------------------------------------------------
  // The next block gets exactly this timestamp; later blocks +12 s each.
  async warp(iso) {
    const t = Math.floor(new Date(iso).getTime() / 1000);
    const latest = await this.provider.getBlock("latest");
    if (t <= latest.timestamp) throw new Error(`warp into the past: ${iso}`);
    await this.provider.send("evm_setTime", [(t - this.blockSeconds) * 1000]);
  }

  // ---- transactions ---------------------------------------------------------
  async tx(label, txPromise) {
    const tx = await txPromise;
    const rcpt = await tx.wait();
    if (label) {
      this.gas.push({ label, gas: Number(rcpt.gasUsed) });
      this.log(`  [gas] ${label}: ${rcpt.gasUsed}`);
    }
    return rcpt;
  }

  events(rcpt, name) {
    const out = [];
    for (const l of rcpt.logs) {
      if (l.address.toLowerCase() !== this.acaddrHex.toLowerCase()) continue;
      const p = this.agency.interface.parseLog(l);
      if (p && p.name === name) out.push(p.args);
    }
    return out;
  }

  async stateDigest() {
    const r = await this.agency.currentRoots();     // (rcl, unl, at, trl, psl)
    return [r[0], r[1], r[2], r[3], r[4],
      await this.agency.nextLeafIndex(), await this.agency.nfLogLength(),
      await this.agency.unlCovered()].map(S).join(",");
  }

  // Every contract root against the mirror.
  async checkRoots(where) {
    // (rcl, unl, at, trl, psl); read by position because ethers results are
    // array-like and "at" would resolve to Array.prototype.at
    const r = await this.agency.currentRoots();
    const m = this.m;
    assertEq(`${where}: RCL root`, r[0], m.rcl.root());
    assertEq(`${where}: UNL root`, r[1], m.unl.root());
    assertEq(`${where}: AT root`, r[2], m.at.root());
    assertEq(`${where}: TRL root`, r[3], m.trl.root());
    assertEq(`${where}: PSL root`, r[4], m.psl.root());
    assertEq(`${where}: leaf count`, await this.agency.nextLeafIndex(), m.rcl.leaves.length);
    assertEq(`${where}: nullifier log length`, await this.agency.nfLogLength(), m.nfLog.length);
    assertEq(`${where}: UNL coverage`, await this.agency.unlCovered(), m.unlCovered);
  }

  // A call that must revert: checks the reason on a static call, then sends
  // the transaction for real and checks it is mined as failed and that no
  // agency state changed.
  async expectRevert(label, contract, method, args, reason, signer) {
    const c = signer ? contract.connect(signer) : contract;
    let got = null;
    try { await c[method].staticCall(...args); }
    catch (e) { got = String(e.reason ?? e.shortMessage ?? e.message); }
    if (got === null) throw new Error(`${label}: expected a revert, the call succeeded`);
    if (reason && !got.includes(reason)) {
      throw new Error(`${label}: reverted with "${got}", expected "${reason}"`);
    }
    const before = await this.stateDigest();
    let minedFailed = false;
    try {
      const tx = await c[method](...args, { gasLimit: 6000000 });
      const r = await tx.wait();
      minedFailed = r.status === 0;
    } catch (e) {
      minedFailed = !!(e.receipt && e.receipt.status === 0) ||
        /revert|CALL_EXCEPTION/i.test(String(e.code) + String(e.message));
    }
    if (!minedFailed) throw new Error(`${label}: the transaction did not fail on chain`);
    if (before !== (await this.stateDigest())) throw new Error(`${label}: state changed`);
    this.log(`  PASS  ${label}  (reverts: "${got}")`);
    return got;
  }

  // ---- tags -------------------------------------------------------------------
  // Pure data of one tag: test secrets and everything derived from them.
  makeTag(name, tag, sec, taIndex) {
    const H = this.H;
    const t = {
      name, tag: BigInt(tag), S: BigInt(sec), taIndex,
      idTax: H.idTax(tag, sec), anchor: H.anchor(sec), atKey: H.atIndex(tag),
      sig: this.c.signTag(taIndex, tag),
    };
    return t;
  }

  ledgerOf(t) {
    if (!this.ledgers.has(t.name)) { this.ledgers.set(t.name, []); this.tags.set(t.name, t); }
    return this.ledgers.get(t.name);
  }

  // The TA writes an AT entry (key -> value) with a path from the mirror.
  async writeAnchorRaw(key, value, label = "writeAnchor") {
    const ex = await this.m.at.exclusion(key);
    const rcpt = await this.tx(`${label} (AT holds ${this.m.at.leaves.length})`,
      this.agency.connect(this.signers.ta)
        .writeAnchor(key, value, ex.siblings, ex.oldKey, ex.oldValue, ex.isOld0));
    await this.m.at.insert(key, value);
    assertEq("AT root after writeAnchor", await this.agency.rootAT(), this.m.at.root());
    if (!(await this.agency.knownAT(this.m.at.root()))) throw new Error("AT root not kept");
    return rcpt;
  }

  async issueTag(t) {
    this.ledgerOf(t);
    const rcpt = await this.writeAnchorRaw(t.atKey, t.anchor);
    assertEq("anchorAt", await this.agency.anchorAt(t.atKey), t.anchor);
    return rcpt;
  }

  async revoke(key, label = "revokeTag") {
    const ex = await this.m.trl.exclusion(key);
    const rcpt = await this.tx(`${label} (TRL holds ${this.m.trl.leaves.length})`,
      this.agency.connect(this.signers.ta)
        .revokeTag(key, ex.siblings, ex.oldKey, ex.oldValue, ex.isOld0));
    await this.m.trl.insert(key, 1n);
    assertEq("TRL root after revokeTag", await this.agency.rootTRL(), this.m.trl.root());
    return rcpt;
  }

  // ---- recording proofs -------------------------------------------------------
  // Circuit input for record i of tag t, with `owner` as the reported owner
  // address, against the CURRENT mirrored roots. Overrides (for the negative
  // tests): i, prev (a record object to use as predecessor), rclSize (cite
  // the RCL root as of that many leaves), rootRCL / prevPath (free values),
  // trl (stale exclusion data { root, ex }), at ({ root, siblings } of a
  // tree other than the mirrored AT).
  async makeInput(t, owner, o = {}) {
    const H = this.H, m = this.m;
    const ledger = this.ledgerOf(t);
    const i = BigInt(o.i ?? ledger.length + 1);
    const nf = H.nullifier(t.idTax, this.cid, this.acaddr, i);
    const rclSize = o.rclSize ?? m.rcl.leaves.length;
    let rootRCL = m.rcl.root(rclSize);
    const at = o.at ?? await m.at.inclusion(t.atKey);
    const rootAT = o.at ? BigInt(o.at.root) : m.at.root();
    const trlRoot = o.trl ? o.trl.root : m.trl.root();
    const trlEx = o.trl ? o.trl.ex : await m.trl.exclusion(t.atKey);
    let prev = { block: 0n, idx: 0n, body: 0n, tail: 0n, pos: 0n,
                 siblings: new Array(PARAMS.DR).fill(0n) };
    if (i > 1n) {
      const p = o.prev ?? ledger[Number(i) - 2];
      if (!p) throw new Error(`no record ${i - 1n} in the local ledger of ${t.name}`);
      const mp = o.prevPath ?? m.rcl.path(p.leaf_index, rclSize).siblings;
      prev = { block: p.block, idx: p.idx, body: p.body, tail: p.tail,
               pos: BigInt(p.leaf_index), siblings: mp };
    }
    if (o.rootRCL !== undefined) rootRCL = BigInt(o.rootRCL);
    const input = {
      nf: S(nf), root_rcl: S(rootRCL), root_at: S(rootAT), root_trl: S(trlRoot),
      keyset_digest: S(this.c.keysetDigest), cid: S(this.cid),
      acaddr: S(this.acaddr), owner: S(BigInt(owner)),
      tag: S(t.tag), S: S(t.S), i: S(i),
      R8x: S(t.sig.R8x), R8y: S(t.sig.R8y), Sig: S(t.sig.S),
      pubx: this.c.pubx.map(S), puby: this.c.puby.map(S), key_index: String(t.taIndex),
      at_siblings: pad(at.siblings, PARAMS.D).map(S),
      trl_siblings: pad(trlEx.siblings, PARAMS.D).map(S),
      trl_oldKey: S(trlEx.oldKey), trl_oldValue: S(trlEx.oldValue),
      // a bigint is passed through unchanged (forged-flag negative test)
      trl_isOld0: typeof trlEx.isOld0 === "bigint" ? S(trlEx.isOld0) : (trlEx.isOld0 ? "1" : "0"),
      block_prev: S(prev.block), idx_prev: S(prev.idx),
      body_prev: S(prev.body), tail_prev: S(prev.tail),
      leaf_pos: S(prev.pos), rcl_siblings: prev.siblings.map(S),
    };
    return { input, i, nf, rootRCL, rootAT };
  }

  // Real Groth16 proof. Returns the RecArgs tuple the entry contracts take.
  // The prover is retried only when the machine runs out of memory (other
  // heavy jobs share this laptop); an unsatisfied constraint is never retried.
  async prove(made) {
    let proof, publicSignals, t0;
    for (let attempt = 1; ; attempt++) {
      t0 = Date.now();
      try {
        ({ proof, publicSignals } = await snarkjs.groth16.fullProve(made.input, WASM, ZKEY));
        break;
      } catch (e) {
        const msg = String(e && e.message);
        const oom = (e && e.name === "DataCloneError") || e instanceof RangeError ||
          /out of memory|could not allocate|allocation failed/i.test(msg);
        if (!oom || attempt >= 6) throw e;
        console.log(`  [prover] out of memory (attempt ${attempt}), waiting to retry: ${msg.split("\n")[0]}`);
        if (globalThis.curve_bn128) {
          try { await globalThis.curve_bn128.terminate(); } catch (_) { /* ignore */ }
          globalThis.curve_bn128 = null;
        }
        await new Promise((r) => setTimeout(r, 20000 * attempt));
      }
    }
    const ms = Date.now() - t0;
    this.proveMs.push(ms);
    return {
      ...made, proof, publicSignals, ms,
      words: proofToWords(proof),
      rec: [made.nf, proofToWords(proof), made.rootRCL, made.rootAT],
    };
  }

  // Off-chain Groth16 verification with the exported verification key.
  async verifyOffchain(pr) {
    if (!this._vkey) this._vkey = JSON.parse(fs.readFileSync(VKEY, "utf8"));
    return snarkjs.groth16.verify(this._vkey, pr.publicSignals, pr.proof);
  }

  async buildRec(t, owner, o = {}) {
    return this.prove(await this.makeInput(t, owner, o));
  }

  // ---- absorbing a record: independent recomputation of the leaf --------------
  // `expect` holds what the scenario says the contract must have written:
  // op, asset_in, amount_in, asset_out, amount_out, value, position_id, idx.
  // opts.partial: more records of the same block are still to be absorbed,
  // so the comparison with the contract's CURRENT state is left to the caller
  // (the per-record checks against the event still run).
  async absorbRecord(rcpt, t, pr, expect, label, opts = {}) {
    const H = this.H, m = this.m;
    const evs = this.events(rcpt, "Recorded");
    if (evs.length !== 1) throw new Error(`${label}: expected exactly 1 record, got ${evs.length}`);
    const ev = evs[0];
    const blk = await this.provider.getBlock(rcpt.blockNumber);
    const f = {
      nf: pr.nf, cid: this.cid, block: BigInt(rcpt.blockNumber),
      idx: BigInt(expect.idx ?? 0), time: BigInt(blk.timestamp),
      op: BigInt(expect.op),
      asset_in: BigInt(expect.asset_in), amount_in: BigInt(expect.amount_in),
      asset_out: BigInt(expect.asset_out), amount_out: BigInt(expect.amount_out),
      value: BigInt(expect.value), position_id: BigInt(expect.position_id ?? 0),
    };
    const h = H.recordLeaf(f);
    const onChain = {
      nf: ev.nf, cid: ev.cid, block: ev.blockNo, idx: ev.idx, time: ev.time, op: ev.op,
      asset_in: ev.assetIn, amount_in: ev.amountIn, asset_out: ev.assetOut,
      amount_out: ev.amountOut, value: ev.value, position_id: ev.positionId,
    };
    for (const k of Object.keys(f)) assertEq(`${label}: leaf field ${k}`, onChain[k], f[k]);
    assertEq(`${label}: leaf`, ev.leaf, h.leaf);
    const leafIndex = m.rcl.append(h.leaf);
    assertEq(`${label}: leaf index`, ev.leafIndex, leafIndex);
    assertEq(`${label}: RCL root (event)`, ev.newRootRCL, m.rcl.root());
    m.nfLog.push(pr.nf);
    if (!(await this.agency.used(pr.nf))) throw new Error(`${label}: nullifier not marked used`);
    if (!(await this.agency.knownRCL(m.rcl.root()))) throw new Error(`${label}: RCL root not kept`);
    assertEq(`${label}: nfLog entry`, await this.agency.nfLog(m.nfLog.length - 1), pr.nf);
    if (!opts.partial) await this.checkRoots(label);
    const rec = { ...f, ...h, leaf_index: leafIndex, i: pr.i, tag: t.name, label,
                  owner: rcpt.from, tx: rcpt.hash, cited_root_rcl: pr.rootRCL,
                  gas: Number(rcpt.gasUsed) };
    m.records.push(rec);
    this.ledgerOf(t).push(rec);
    this.log(`  ok  ${label}: record ${pr.i} of ${t.name} -> leaf ${leafIndex}` +
      ` (block ${f.block}, idx ${f.idx}, time ${f.time}); roots match the mirror`);
    return rec;
  }

  async absorbPassive(rcpt, expect, label, opts = {}) {
    const H = this.H, m = this.m;
    const evs = this.events(rcpt, "PassiveRecorded");
    if (evs.length !== 1) throw new Error(`${label}: expected 1 PSL entry, got ${evs.length}`);
    const ev = evs[0];
    const blk = await this.provider.getBlock(rcpt.blockNumber);
    const f = {
      position_id: BigInt(expect.position_id), kind: BigInt(expect.kind),
      cid: this.cid, block: BigInt(rcpt.blockNumber), idx: BigInt(expect.idx ?? 0),
      time: BigInt(blk.timestamp),
      asset_a: BigInt(expect.asset_a), amount_a: BigInt(expect.amount_a),
      asset_b: BigInt(expect.asset_b), amount_b: BigInt(expect.amount_b),
      value: BigInt(expect.value),
    };
    const h = H.passiveEntry(f);
    const onChain = {
      position_id: ev.positionId, kind: ev.kind, cid: ev.cid, block: ev.blockNo,
      idx: ev.idx, time: ev.time, asset_a: ev.assetA, amount_a: ev.amountA,
      asset_b: ev.assetB, amount_b: ev.amountB, value: ev.value,
    };
    for (const k of Object.keys(f)) assertEq(`${label}: PSL field ${k}`, onChain[k], f[k]);
    assertEq(`${label}: PSL entry`, ev.entry, h.pentry);
    await m.psl.insert(f.position_id, h.pentry);
    assertEq(`${label}: PSL root (event)`, ev.newRootPSL, m.psl.root());
    if (!opts.partial) await this.checkRoots(label);
    const e = { ...f, ...h, label, tx: rcpt.hash, gas: Number(rcpt.gasUsed) };
    m.passive.push(e);
    this.log(`  ok  ${label}: PSL entry kind ${f.kind} at position ${f.position_id}` +
      ` (block ${f.block}, idx ${f.idx}, time ${f.time}); roots match the mirror`);
    return e;
  }

  async pslPath(positionId) {
    const ex = await this.m.psl.exclusion(BigInt(positionId));
    return [ex.siblings, ex.oldKey, ex.oldValue, ex.isOld0];
  }

  // ---- covered actions (each: prove, send, absorb) ----------------------------
  async approveAll(role) {
    const s = this.signers[role];
    for (const spender of Object.values(this.contracts)) {
      await (await this.usdc.connect(s).approve(spender, ethers.MaxUint256)).wait();
      await (await this.eth.connect(s).approve(spender, ethers.MaxUint256)).wait();
    }
  }

  async setEthPrice(p) {
    this.ethPrice = BigInt(p);
    await (await this.feedEth.setPrice(p)).wait();
    await (await this.poolA.setPrice(p, 1)).wait();
    await (await this.poolB.setPrice(p, 1)).wait();
    await (await this.plainPool.setPrice(p, 1)).wait();
  }

  price(token) { return token === this.ETH ? this.ethPrice : 1n; }

  // reward claim through the lending venue (op 5); the venue admin must
  // have set the claimable balance beforehand (lending.setClaimable)
  async claim(t, role, amount, label) {
    const pr = await this.buildRec(t, this.addr[role]);
    const rcpt = await this.tx(label && `${label} [tx: lending.claimReward]`,
      this.lending.connect(this.signers[role]).claimReward(amount, pr.rec));
    return this.absorbRecord(rcpt, t, pr, {
      op: OP.CLAIM, asset_in: 0, amount_in: 0, asset_out: 1, amount_out: amount,
      value: BigInt(amount) * 1n,
    }, label);
  }

  // direct swap on a covered pool: the pool is the entry contract (op 1)
  async swapDirect(t, role, pool, tokenIn, amountIn, expect, label) {
    const pr = await this.buildRec(t, this.addr[role]);
    const rcpt = await this.tx(label && `${label} [tx: pool.swap, direct]`,
      pool.connect(this.signers[role]).swap(tokenIn, amountIn, 0, this.addr[role], pr.rec));
    return this.absorbRecord(rcpt, t, pr, { op: OP.SWAP, position_id: 0, ...expect }, label);
  }

  // aggregator split over several covered pools: ONE record, net amounts
  async swapSplit(t, role, tokenIn, tokenOut, legs, expect, label) {
    const pr = await this.buildRec(t, this.addr[role]);
    const rcpt = await this.tx(label && `${label} [tx: aggregator.swapSplit, ${legs.length} pools]`,
      this.aggregator.connect(this.signers[role]).swapSplit(tokenIn, tokenOut,
        legs.map((l) => l[0]), legs.map((l) => l[1]), 0, pr.rec));
    return this.absorbRecord(rcpt, t, pr, { op: OP.SWAP, position_id: 0, ...expect }, label);
  }

  // swap through the wrapper in front of the unregistered pool (op 1)
  async swapWrapped(t, role, tokenIn, amountIn, expect, label) {
    const pr = await this.buildRec(t, this.addr[role]);
    const rcpt = await this.tx(label && `${label} [tx: wrapper.swap]`,
      this.wrapper.connect(this.signers[role]).swap(tokenIn, amountIn, 0, pr.rec));
    return this.absorbRecord(rcpt, t, pr, { op: OP.SWAP, position_id: 0, ...expect }, label);
  }

  // pledge with an optional loan in the same call: ONE pledge record (op 2)
  async pledge(t, role, collToken, collAmount, loanToken, loanAmount, label) {
    const positionId = await this.lending.nextPositionId();
    const pr = await this.buildRec(t, this.addr[role]);
    const rcpt = await this.tx(label && `${label} [tx: lending.pledge]`,
      this.lending.connect(this.signers[role])
        .pledge(collToken, collAmount, loanToken ?? ethers.ZeroAddress, loanAmount ?? 0, pr.rec));
    const loan = BigInt(loanAmount ?? 0);
    const rec = await this.absorbRecord(rcpt, t, pr, {
      op: OP.PLEDGE, asset_in: this.assetId[collToken], amount_in: collAmount,
      asset_out: loan ? this.assetId[loanToken] : 0, amount_out: loan,
      value: loan ? loan * this.price(loanToken) : BigInt(collAmount) * this.price(collToken),
      position_id: positionId,
    }, label);
    return { rec, positionId };
  }

  async borrow(t, role, positionId, loanToken, amount, label) {
    const pr = await this.buildRec(t, this.addr[role]);
    const rcpt = await this.tx(label && `${label} [tx: lending.borrow]`,
      this.lending.connect(this.signers[role]).borrow(positionId, loanToken, amount, pr.rec));
    return this.absorbRecord(rcpt, t, pr, {
      op: OP.BORROW, asset_in: 0, amount_in: 0, asset_out: this.assetId[loanToken],
      amount_out: amount, value: BigInt(amount) * this.price(loanToken), position_id: positionId,
    }, label);
  }

  async repay(t, role, positionId, debtToken, amount, label) {
    const pr = await this.buildRec(t, this.addr[role]);
    const rcpt = await this.tx(label && `${label} [tx: lending.repay]`,
      this.lending.connect(this.signers[role]).repay(positionId, amount, pr.rec));
    return this.absorbRecord(rcpt, t, pr, {
      op: OP.REPAY, asset_in: this.assetId[debtToken], amount_in: amount, asset_out: 0,
      amount_out: 0, value: BigInt(amount) * this.price(debtToken), position_id: positionId,
    }, label);
  }

  // ---- passive events: no proof --------------------------------------------------
  async withdraw(role, positionId, expect, label) {
    const rcpt = await this.tx(label && `${label} [tx: lending.withdraw -> recordPassive]`,
      this.lending.connect(this.signers[role]).withdraw(positionId, await this.pslPath(positionId)));
    return this.absorbPassive(rcpt, { position_id: positionId, kind: KIND.WITHDRAWAL, ...expect }, label);
  }

  async liquidate(role, positionId, expect, label) {
    const rcpt = await this.tx(label && `${label} [tx: lending.liquidate -> recordPassive]`,
      this.lending.connect(this.signers[role]).liquidate(positionId, await this.pslPath(positionId)));
    return this.absorbPassive(rcpt, { position_id: positionId, kind: KIND.LIQUIDATION, ...expect }, label);
  }

  // ---- several transactions in ONE block ---------------------------------------------
  // calls: [{ role, contract, method, args }]. Stops the miner, queues every
  // transaction, mines one block, restarts the miner. Returns the receipts in
  // their order inside the block.
  async sameBlock(calls) {
    await this.provider.send("miner_stop", []);
    const hashes = [];
    try {
      for (const c of calls) {
        const txr = await c.contract[c.method].populateTransaction(...c.args);
        hashes.push(await this.provider.send("eth_sendTransaction",
          [{ from: this.addr[c.role], to: txr.to, data: txr.data, gas: "0x3d0900" }]));
      }
      await this.provider.send("evm_mine", []);
    } finally {
      await this.provider.send("miner_start", []);
    }
    const rcpts = [];
    for (const h of hashes) rcpts.push(await this.provider.getTransactionReceipt(h));
    rcpts.sort((a, b) => a.index - b.index);
    return rcpts;
  }

  // ---- UNL batches and snapshots ---------------------------------------------------
  // Anyone inserts the next `count` logged nullifiers (default: all pending).
  async insertNullifiers(count, label = "insertNullifiers", role = "mallory") {
    const m = this.m;
    const from = m.unlCovered;
    const n = count ?? (m.nfLog.length - from);
    const paths = [];
    for (let k = 0; k < n; k++) {
      const nf = m.nfLog[from + k];
      const ex = await m.unl.exclusion(nf);          // against the running root
      paths.push([ex.siblings, ex.oldKey, ex.oldValue, ex.isOld0]);
      await m.unl.insert(nf, 1n);
    }
    const rcpt = await this.tx(`${label} (${n} nullifiers, UNL held ${from})`,
      this.agency.connect(this.signers[role]).insertNullifiers(from, paths));
    m.unlCovered = from + n;
    await this.checkRoots(label);
    this.log(`  ok  ${label}: ${n} nullifiers batched into the UNL, root matches the mirror`);
    return { rcpt, n, from, perNullifier: Math.round(Number(rcpt.gasUsed) / Math.max(n, 1)) };
  }

  async pinSnapshot(period, label = "pinSnapshot", role = "mallory") {
    const m = this.m;
    const rcpt = await this.tx(label, this.agency.connect(this.signers[role]).pinSnapshot(period));
    const s = await this.agency.snapshots(period);
    assertEq("snapshot RCL", s[0], m.rcl.root());   // (rcl, unl, at, psl)
    assertEq("snapshot UNL", s[1], m.unl.root());
    assertEq("snapshot AT", s[2], m.at.root());
    assertEq("snapshot PSL", s[3], m.psl.root());
    const blk = await this.provider.getBlock(rcpt.blockNumber);
    const snap = {
      period, root_rcl: m.rcl.root(), root_unl: m.unl.root(),
      root_at: m.at.root(), root_psl: m.psl.root(),
      block: BigInt(rcpt.blockNumber), time: BigInt(blk.timestamp),
      leaf_count: m.rcl.leaves.length, nf_count: m.nfLog.length,
      at_count: m.at.leaves.length, psl_count: m.psl.leaves.length,
      trl_count: m.trl.leaves.length,
    };
    m.snapshots.push(snap);
    this.log(`  ok  ${label}: period ${period} pinned at block ${snap.block};` +
      ` four roots match the mirror (${snap.leaf_count} leaves, ${snap.nf_count} nullifiers)`);
    return snap;
  }

  // ---- ledger rebuild from chain data and (tag, S) alone -----------------------------
  // Reads every Recorded event, walks NF_1, NF_2, ... of the tag and returns
  // the records found. Used to check the fixtures against the chain.
  async rebuildLedger(t) {
    const logs = await this.agency.queryFilter(this.agency.filters.Recorded(), 0, "latest");
    const byNf = new Map();
    for (const l of logs) byNf.set(BigInt(l.args.nf), l.args);
    const out = [];
    for (let i = 1n; ; i++) {
      const ev = byNf.get(this.H.nullifier(t.idTax, this.cid, this.acaddr, i));
      if (!ev) break;
      out.push({ i, leaf_index: Number(ev.leafIndex), leaf: BigInt(ev.leaf) });
    }
    return out;
  }

  async balances(role) {
    return {
      usdc: await this.usdc.balanceOf(this.addr[role]),
      eth: await this.eth.balanceOf(this.addr[role]),
    };
  }
}

module.exports = { World, compileContracts, proofToWords, assertEq, S,
                   ROOT, OUT, WASM, ZKEY, VKEY, PARAMS, OP, KIND };
