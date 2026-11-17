// Unit tests of the path gadgets, and a proof of concept for the isOld0
// finding: circomlib's SMTVerifier does not force isOld0 to be boolean, so a
// caller that wires it as a free private input accepts a FORGED exclusion
// proof for a key that is in the tree. The filing circuits use
// SMTVerifierB / DualPath, which force isOld0 boolean.
//
//  1 plain SMTVerifier(32): honest inclusion and exclusion accepted
//  2 plain SMTVerifier(32): forged exclusion of a PRESENT key accepted (the hole)
//  3 SMTVerifierB(32): the same forged input rejected, honest ones accepted
//  4 DualPath(32, 32): SMT inclusion, SMT exclusion (incl. the empty tree),
//    positional RCL inclusion accepted; wrong leaf, wrong root, the forged
//    exclusion and an exclusion of a present key rejected
// Usage: node test_smt_isold0.js
const fs = require("fs");
const path = require("path");
const core = require("./lib/core");
const { shortErr } = require("./lib/wtns");

const BUILD = path.join(__dirname, "build", "test");
async function calc(name) {
  const dir = path.join(BUILD, `${name}_js`);
  return require(path.join(dir, "witness_calculator.js"))(fs.readFileSync(path.join(dir, `${name}.wasm`)));
}
let failures = 0;
async function expect(label, wc, input, shouldPass) {
  let passed = true, why = "";
  try { await wc.calculateWitness(input, 0); } catch (e) { passed = false; why = shortErr(e); }
  const ok = passed === shouldPass;
  if (!ok) failures++;
  console.log(`  ${ok ? "ok  " : "FAIL"} ${label}: ${passed ? "accepted" : "rejected (" + why + ")"}`);
}

async function main() {
  await core.init();
  const { P, Smt, PosTree, bitReverse, F } = core;
  const S = (x) => (Array.isArray(x) ? x.map(S) : x.toString());
  const smt = await Smt.create();
  for (const [k, v] of [[5n, 55n], [9n, 99n], [12n, 77n], [1000001n, 3n]]) await smt.insert(k, v);
  const root = smt.root;
  const inc = await smt.proof(9n, 32);
  const exc = await smt.proof(13n, 32);

  const smtIn = (o) => ({ enabled: "1", root: S(root), siblings: S(o.siblings), oldKey: S(o.oldKey),
    oldValue: S(o.oldValue), isOld0: S(o.isOld0), key: S(o.key), value: S(o.value), fnc: S(o.fnc) });
  const honestInc = smtIn({ ...inc, key: 9n, value: 99n, fnc: 0n });
  const honestExc = smtIn({ ...exc, key: 13n, value: 0n, fnc: 1n });

  // forged exclusion of key 9 (present): scale an arbitrary "old leaf" hash
  // with a non-boolean isOld0 so that old1leaf * (1 - isOld0) equals the hash
  // of the leaf that really sits on key 9's path
  const realLeaf = P([9n, 99n, 1n]);
  const fakeOldKey = 123456789n, fakeOldValue = 1n;
  const h = P([fakeOldKey, fakeOldValue, 1n]);
  const t = F.toObject(F.sub(F.e(1n), F.div(F.e(realLeaf), F.e(h))));
  const forged = smtIn({ siblings: inc.siblings, oldKey: fakeOldKey, oldValue: fakeOldValue,
                         isOld0: t, key: 9n, value: 0n, fnc: 1n });

  console.log("== circomlib SMTVerifier(32), all inputs private");
  const plain = await calc("smt_plain");
  await expect("honest inclusion of key 9", plain, honestInc, true);
  await expect("honest exclusion of key 13", plain, honestExc, true);
  await expect("FORGED exclusion of key 9, which is in the tree (non-boolean isOld0)", plain, forged, true);

  console.log("== SMTVerifierB(32) (isOld0 forced boolean)");
  const bool = await calc("smt_bool");
  await expect("honest inclusion of key 9", bool, honestInc, true);
  await expect("honest exclusion of key 13", bool, honestExc, true);
  await expect("forged exclusion of key 9", bool, forged, false);

  console.log("== DualPath(32, 32)");
  const dp = await calc("dualpath");
  const dpIn = (o) => ({ smt_en: S(o.smt_en), rcl_en: S(o.rcl_en), fnc: S(o.fnc), root: S(o.root),
    siblings: S(o.siblings), oldKey: S(o.oldKey || 0n), oldValue: S(o.oldValue || 0n),
    isOld0: S(o.isOld0 || 0n), key: S(o.key), leaf: S(o.leaf) });
  await expect("SMT inclusion (9 -> 99)", dp, dpIn({ smt_en: 1n, rcl_en: 0n, fnc: 0n, root, siblings: inc.siblings, key: 9n, leaf: 99n }), true);
  await expect("SMT inclusion with a wrong value", dp, dpIn({ smt_en: 1n, rcl_en: 0n, fnc: 0n, root, siblings: inc.siblings, key: 9n, leaf: 98n }), false);
  await expect("SMT exclusion of key 13", dp, dpIn({ smt_en: 1n, rcl_en: 0n, fnc: 1n, root, ...exc, key: 13n, leaf: 0n }), true);
  await expect("SMT exclusion of key 9, which is present", dp, dpIn({ smt_en: 1n, rcl_en: 0n, fnc: 1n, root, siblings: inc.siblings, oldKey: 9n, oldValue: 99n, isOld0: 0n, key: 9n, leaf: 0n }), false);
  await expect("forged exclusion of key 9 (non-boolean isOld0)", dp, dpIn({ smt_en: 1n, rcl_en: 0n, fnc: 1n, root, siblings: inc.siblings, oldKey: fakeOldKey, oldValue: fakeOldValue, isOld0: t, key: 9n, leaf: 0n }), false);
  const empty = await Smt.create();
  const exE = await empty.proof(42n, 32);
  await expect("SMT exclusion in the empty tree (root 0)", dp, dpIn({ smt_en: 1n, rcl_en: 0n, fnc: 1n, root: empty.root, ...exE, key: 42n, leaf: 0n }), true);
  // positional RCL inclusion, read top-down
  const rcl = new PosTree(32, 0n);
  for (let k = 0; k < 37; k++) rcl.append(P([900n, BigInt(k)]));
  for (const idx of [0, 21, 36]) {
    const up = rcl.path(idx);
    const sib = []; for (let j = 0; j < 32; j++) sib.push(up[31 - j]);
    const base = { smt_en: 0n, rcl_en: 1n, fnc: 0n, root: rcl.root(), siblings: sib, key: bitReverse(idx, 32), leaf: rcl.get(idx) };
    await expect(`RCL inclusion of leaf ${idx}`, dp, dpIn(base), true);
    if (idx === 21) {
      await expect("RCL inclusion with a wrong leaf", dp, dpIn({ ...base, leaf: rcl.get(idx) + 1n }), false);
      await expect("RCL inclusion at a wrong index", dp, dpIn({ ...base, key: bitReverse(22, 32) }), false);
      await expect("RCL inclusion under a wrong root", dp, dpIn({ ...base, root: rcl.root() + 1n }), false);
    }
  }
  await expect("both modes off: nothing checked", dp, dpIn({ smt_en: 0n, rcl_en: 0n, fnc: 0n, root: 7n, siblings: new Array(32).fill(0n), key: 0n, leaf: 0n }), true);
  console.log(failures === 0 ? "path gadget tests: ALL OK" : `path gadget tests: ${failures} FAILED`);
  process.exitCode = failures === 0 ? 0 : 1;
}
main().catch((e) => { console.error(e); process.exitCode = 1; });
