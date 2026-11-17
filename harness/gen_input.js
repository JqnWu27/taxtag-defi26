// Generates valid witness inputs for the recording circuit c_rec without
// any chain: the trees are built in JavaScript (circomlibjs SMTs for the AT
// and TRL, lib/trees.js for the RCL). Used by bench_rec.sh for the timing
// and memory measurements. The chain-backed generator used by the scenario
// scripts is World.makeInput in lib/world.js; both produce the same shape.
//
//   out/rec/input_c_rec_first.json   record 1 (predecessor check off)
//   out/rec/input_c_rec_next.json    record 5 of the worked example
//                                    (predecessor = the leaf of record 4)
//
// Usage: node harness/gen_input.js [D]      D = SMT depth, default 64
const fs = require("fs");
const path = require("path");
const { init, PARAMS, OP } = require("./lib/hashes");
const { Smt, Rcl, pad } = require("./lib/trees");

const D = Number(process.argv[2] || PARAMS.D);
const OUT = path.resolve(__dirname, "..", "out", "rec");
const S = (x) => BigInt(x).toString();

async function main() {
  const c = await init();
  const H = c.H;

  // ---- Alice (test secrets) ----
  const tag = 7311111111111111n, sec = 9244444444444444n, TA_INDEX = 5;
  const cid = 1337n;
  const acaddr = 0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9n;   // any address
  const owner = 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BCn;
  const idTax = H.idTax(tag, sec);
  const atKey = H.atIndex(tag);
  const sig = c.signTag(TA_INDEX, tag);

  // ---- trees ----
  const at = await Smt.create(c.F);
  await at.insert(H.atIndex(5555n), H.anchor(6666n));       // another registration
  await at.insert(atKey, H.anchor(sec));
  const trl = await Smt.create(c.F);
  await trl.insert(H.atIndex(999999n), 1n);                  // an unrelated revoked tag
  const atInc = await at.inclusion(atKey);
  const trlEx = await trl.exclusion(atKey);

  // RCL: Alice's records 1..4 (claims of 1500 USDC) with a foreign leaf between
  const rcl = new Rcl(H, PARAMS.DR);
  const ledger = [];
  for (let i = 1n; i <= 4n; i++) {
    const f = { nf: H.nullifier(idTax, cid, acaddr, i), cid, block: 60n + i, idx: 0n,
                time: 1772445600n + i * 86400n, op: OP.CLAIM, asset_in: 0n, amount_in: 0n,
                asset_out: 1n, amount_out: 1500n, value: 1500n, position_id: 0n };
    const h = H.recordLeaf(f);
    if (i === 2n) rcl.append(H.P([424242n, 1n]));            // somebody else's leaf
    ledger.push({ ...f, ...h, leaf_index: rcl.append(h.leaf) });
  }

  const common = {
    root_at: S(at.root()), root_trl: S(trl.root()),
    keyset_digest: S(c.keysetDigest), cid: S(cid), acaddr: S(acaddr), owner: S(owner),
    tag: S(tag), S: S(sec),
    R8x: S(sig.R8x), R8y: S(sig.R8y), Sig: S(sig.S),
    pubx: c.pubx.map(S), puby: c.puby.map(S), key_index: String(TA_INDEX),
    at_siblings: pad(atInc.siblings, D).map(S),
    trl_siblings: pad(trlEx.siblings, D).map(S),
    trl_oldKey: S(trlEx.oldKey), trl_oldValue: S(trlEx.oldValue),
    trl_isOld0: trlEx.isOld0 ? "1" : "0",
  };

  // record 1: no predecessor, root_rcl unconstrained (the empty root here)
  const first = {
    nf: S(H.nullifier(idTax, cid, acaddr, 1n)), root_rcl: S(rcl.root(0)), ...common, i: "1",
    block_prev: "0", idx_prev: "0", body_prev: "0", tail_prev: "0", leaf_pos: "0",
    rcl_siblings: new Array(PARAMS.DR).fill("0"),
  };
  // record 5: predecessor is the leaf of record 4
  const p = ledger[3];
  const next = {
    nf: S(H.nullifier(idTax, cid, acaddr, 5n)), root_rcl: S(rcl.root()), ...common, i: "5",
    block_prev: S(p.block), idx_prev: S(p.idx), body_prev: S(p.body), tail_prev: S(p.tail),
    leaf_pos: String(p.leaf_index), rcl_siblings: rcl.path(p.leaf_index).siblings.map(S),
  };

  fs.mkdirSync(OUT, { recursive: true });
  const sfx = D === PARAMS.D ? "" : `_d${D}`;
  fs.writeFileSync(path.join(OUT, `input_c_rec_first${sfx}.json`), JSON.stringify(first));
  fs.writeFileSync(path.join(OUT, `input_c_rec_next${sfx}.json`), JSON.stringify(next));
  console.log(`inputs written (D = ${D}): out/rec/input_c_rec_first${sfx}.json, out/rec/input_c_rec_next${sfx}.json`);
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
