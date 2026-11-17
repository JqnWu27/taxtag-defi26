// Regression test for the isOld0 soundness gap:
// circomlib's SMTVerifier does not force its exclusion flag isOld0 to
// be 0 or 1. With a free flag x, the level that should hold "the other
// leaf" evaluates to old1leaf * (1 - x), so a prover picks any (oldKey,
// oldValue) and solves
//     x = 1 - leaf(key, 1) / leaf(oldKey, oldValue)
// to make the exclusion proof of a key that IS in the tree verify. A REVOKED
// tag could then prove non-revocation. The fix is one constraint in
// circuits/rec/taxtag_rec_common.circom:  trl_isOld0 * (trl_isOld0 - 1) === 0
//
// This script builds exactly that forged witness for a revoked tag (no
// chain needed) and runs it through
//   (a) the current build out/rec/            -> must be REJECTED
//   (b) the pre-fix build out/rec/prefix_isold0/, if it was kept
//                                              -> is ACCEPTED (a full proof verifies)
//
// Usage: node harness/test_isold0.js
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const { init, PARAMS } = require("./lib/hashes");
const { Smt, pad } = require("./lib/trees");

const OUT = path.resolve(__dirname, "..", "out", "rec");
const S = (x) => BigInt(x).toString();

async function forgedInput() {
  const c = await init();
  const H = c.H, F = c.F;
  const tag = 4433333333333333n, sec = 6611111111111111n, TA = 0;     // "Carol"
  const cid = 1337n, acaddr = 0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9n;
  const owner = 0x90F79bf6EB2c4f870365E785982E1f101E93b906n;
  const key = H.atIndex(tag);
  const sig = c.signTag(TA, tag);

  const at = await Smt.create(F);
  await at.insert(H.atIndex(5555n), H.anchor(6666n));
  await at.insert(key, H.anchor(sec));
  const trl = await Smt.create(F);
  await trl.insert(H.atIndex(999999n), 1n);
  await trl.insert(key, 1n);                       // the tag IS revoked
  const inc = await trl.inclusion(key);            // the real path of the revocation leaf

  // the forgery: any other "old leaf", and the flag that scales it into the real one
  const oldKey = 123456789n, oldValue = 1n;
  const real = H.smtLeaf(key, 1n), fake = H.smtLeaf(oldKey, oldValue);
  const x = F.toObject(F.sub(F.one, F.div(F.e(real), F.e(fake))));

  const input = {
    nf: S(H.nullifier(H.idTax(tag, sec), cid, acaddr, 1n)),
    root_rcl: "0", root_at: S(at.root()), root_trl: S(trl.root()),
    keyset_digest: S(c.keysetDigest), cid: S(cid), acaddr: S(acaddr), owner: S(owner),
    tag: S(tag), S: S(sec), i: "1",
    R8x: S(sig.R8x), R8y: S(sig.R8y), Sig: S(sig.S),
    pubx: c.pubx.map(S), puby: c.puby.map(S), key_index: String(TA),
    at_siblings: pad((await at.inclusion(key)).siblings, PARAMS.D).map(S),
    trl_siblings: pad(inc.siblings, PARAMS.D).map(S),
    trl_oldKey: S(oldKey), trl_oldValue: S(oldValue), trl_isOld0: S(x),
    block_prev: "0", idx_prev: "0", body_prev: "0", tail_prev: "0", leaf_pos: "0",
    rcl_siblings: new Array(PARAMS.DR).fill("0"),
  };
  return { input, x };
}

async function tryBuild(dir, input) {
  const wasm = path.join(dir, "c_rec_js", "c_rec.wasm");
  const zkey = path.join(dir, "c_rec.zkey");
  const vkey = JSON.parse(fs.readFileSync(path.join(dir, "c_rec.vkey.json"), "utf8"));
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, zkey);
    const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
    return { accepted: ok, detail: ok ? "witness generated, Groth16 proof VERIFIES" : "proof does not verify" };
  } catch (e) {
    return { accepted: false, detail: String(e.message).split("\n")[0] };
  }
}

async function main() {
  const { input, x } = await forgedInput();
  console.log("forged non-revocation witness for a REVOKED tag, trl_isOld0 =");
  console.log("  " + x + "  (not 0, not 1)");
  let good = true;

  const pre = path.join(OUT, "prefix_isold0");
  if (fs.existsSync(path.join(pre, "c_rec.zkey"))) {
    const r = await tryBuild(pre, input);
    console.log(`${r.accepted ? "PASS" : "FAIL"}  pre-fix circuit accepts the forgery (the gap is real)  -- ${r.detail}`);
    good = good && r.accepted;
  } else {
    console.log("note  pre-fix build not present (out/rec/prefix_isold0), skipping the reproduction");
  }
  const r = await tryBuild(OUT, input);
  console.log(`${!r.accepted ? "PASS" : "FAIL"}  current circuit rejects the forgery  -- ${r.detail}`);
  good = good && !r.accepted;

  // control: the same witness with the honest flag value is rejected too (the tag is revoked)
  for (const flag of ["0", "1"]) {
    const rc = await tryBuild(OUT, { ...input, trl_isOld0: flag });
    console.log(`${!rc.accepted ? "PASS" : "FAIL"}  current circuit rejects the revoked tag with isOld0 = ${flag}  -- ${rc.detail}`);
    good = good && !rc.accepted;
  }
  console.log(good ? "\n== isOld0 regression: all checks passed ==" : "\n== isOld0 regression: FAILED ==");
  process.exit(good ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
