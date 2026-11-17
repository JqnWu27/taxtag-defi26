// TaxTag hash conventions (SPEC.md section 2), in JavaScript.
// Independent of the contract and the circuit: circomlibjs Poseidon over
// BN254. Every function takes and returns BigInt.
const { buildPoseidon, buildEddsa } = require("circomlibjs");

const PARAMS = { D: 64, DR: 32, NKEYS: 16 };
const OP = { SWAP: 1n, PLEDGE: 2n, BORROW: 3n, REPAY: 4n, CLAIM: 5n };
const KIND = { LIQUIDATION: 1n, WITHDRAWAL: 2n };

let ctx = null;

async function init() {
  if (ctx) return ctx;
  const poseidon = await buildPoseidon();
  const eddsa = await buildEddsa();
  const F = poseidon.F;
  const P = (arr) => F.toObject(poseidon(arr.map((x) => F.e(BigInt(x)))));

  const H = {
    P,
    idTax: (tag, S) => P([1n, tag, S]),
    anchor: (S) => P([2n, S]),
    atIndex: (tag) => P([3n, tag]),                 // AT and TRL index
    credMsg: (tag) => P([9n, tag]),
    nullifier: (idTax, cid, acaddr, i) => P([8n, idTax, cid, acaddr, i]),
    leafMeta: (nf, cid, block, idx) => P([7n, nf, cid, block, idx]),
    leafBody: (op, assetIn, amountIn, assetOut, amountOut) =>
      P([op, assetIn, amountIn, assetOut, amountOut]),
    leafTail: (value, positionId, time) => P([10n, value, positionId, time, 0n]),
    leaf: (meta, body, tail) => P([meta, body, tail]),
    pslMeta: (kind, cid, block, idx) => P([11n, kind, cid, block, idx]),
    pslBody: (assetA, amountA, assetB, amountB, value) =>
      P([assetA, amountA, assetB, amountB, value]),
    pslEntry: (pmeta, pbody, time) => P([pmeta, pbody, time]),
    smtLeaf: (key, value) => P([key, value, 1n]),   // circomlib SMT leaf hash
    node: (l, r) => P([l, r]),
  };

  // full leaf from its plain fields
  H.recordLeaf = (r) => {
    const meta = H.leafMeta(r.nf, r.cid, r.block, r.idx);
    const body = H.leafBody(r.op, r.asset_in, r.amount_in, r.asset_out, r.amount_out);
    const tail = H.leafTail(r.value, r.position_id, r.time);
    return { meta, body, tail, leaf: H.leaf(meta, body, tail) };
  };
  H.passiveEntry = (e) => {
    const pmeta = H.pslMeta(e.kind, e.cid, e.block, e.idx);
    const pbody = H.pslBody(e.asset_a, e.amount_a, e.asset_b, e.amount_b, e.value);
    return { pmeta, pbody, pentry: H.pslEntry(pmeta, pbody, e.time) };
  };

  // ---- recognized TA key set (16 deterministic test keys) ----
  const prvKeys = [], pubx = [], puby = [];
  for (let j = 0; j < PARAMS.NKEYS; j++) {
    const prv = Buffer.from(String(j + 1).padStart(2, "0").repeat(32), "hex");
    const pub = eddsa.prv2pub(prv);
    prvKeys.push(prv);
    pubx.push(F.toObject(pub[0]));
    puby.push(F.toObject(pub[1]));
  }
  const keysetDigest = P([P(pubx), P(puby)]);

  // TA number taIndex signs the credential message of a tag
  const signTag = (taIndex, tag) => {
    const sig = eddsa.signPoseidon(prvKeys[taIndex], F.e(H.credMsg(tag)));
    return { R8x: F.toObject(sig.R8[0]), R8y: F.toObject(sig.R8[1]), S: sig.S };
  };

  ctx = { poseidon, eddsa, F, P, H, pubx, puby, keysetDigest, signTag };
  return ctx;
}

module.exports = { init, PARAMS, OP, KIND };
