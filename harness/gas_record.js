// Gas of the agency contract's functions, measured with REAL Groth16 proofs
// (SPEC.md section 9, recording part).
//
// record() and recordPassive() are called directly by an externally owned
// address registered as a venue, so the figure
// is the agency contract's own cost: no pool or lending logic, no token
// transfer. The whole-transaction gas of the demo venues is printed by the
// scenario scripts.
//
// Also measured: the Groth16 verification share (inside a contract call and
// as a stand-alone call), one on-chain Poseidon call per arity,
// writeAnchor and revokeTag over 64 writes each, insertNullifiers and
// pinSnapshot. Every root is checked against the JavaScript mirror.
//
// Usage: node harness/gas_record.js         (writes out/rec/gas_record.json)
const fs = require("fs");
const path = require("path");
const { ethers } = require("ethers");
const { run, tagOf, World, OP } = require("./lib/scenario");
const { OUT } = require("./lib/world");

run("gas measurement with real proofs", async (rep) => {
  const w = await World.create({});
  const H = w.H;
  const alice = tagOf(w, "alice");
  await w.warp("2027-01-10T09:00:00Z");
  const res = { record: [], writeAnchor: [], revokeTag: [], recordPassive: [],
                insertNullifiers: [], pinSnapshot: [], poseidon: {}, verify: {} };

  // ---- writeAnchor: Alice's tag first (empty AT), then 64 more ----
  // `siblings` is the length of the authenticated path the call carries
  let rc = await w.issueTag(alice);
  res.writeAnchor.push({ held: 0, siblings: 0, gas: Number(rc.gasUsed) });
  w.quiet = true;
  for (let k = 1; k <= 64; k++) {
    const key = H.atIndex(100000n + BigInt(k));
    const siblings = (await w.m.at.exclusion(key)).siblings.length;
    rc = await w.writeAnchorRaw(key, H.anchor(200000n + BigInt(k)));
    res.writeAnchor.push({ held: k, siblings, gas: Number(rc.gasUsed) });
  }
  for (let k = 0; k < 64; k++) {
    const key = H.atIndex(300000n + BigInt(k));
    const siblings = (await w.m.trl.exclusion(key)).siblings.length;
    rc = await w.revoke(key);
    res.revokeTag.push({ held: k, siblings, gas: Number(rc.gasUsed) });
  }
  w.quiet = false;
  const mm = (a) => [Math.min(...a.map((x) => x.gas)), Math.max(...a.map((x) => x.gas))];
  const median = (a) => { const v = a.map((x) => x.gas).sort((x, y) => x - y); return v[Math.floor(v.length / 2)]; };
  const fit = (pts) => {      // least squares gas = a + b * siblings
    const n = pts.length, sx = pts.reduce((t, q) => t + q.siblings, 0), sy = pts.reduce((t, q) => t + q.gas, 0);
    const sxx = pts.reduce((t, q) => t + q.siblings * q.siblings, 0), sxy = pts.reduce((t, q) => t + q.siblings * q.gas, 0);
    const b = (n * sxy - sx * sy) / (n * sxx - sx * sx);
    return { a: Math.round((sy - b * sx) / n), b: Math.round(b) };
  };
  res.fit_writeAnchor = fit(res.writeAnchor);
  res.fit_revokeTag = fit(res.revokeTag);
  rep.ok("65 anchors written, AT root equals the mirror after each", w.m.at.leaves.length === 65,
    `gas ${mm(res.writeAnchor).join(" .. ")}`);
  rep.ok("64 tags revoked, TRL root equals the mirror after each", w.m.trl.leaves.length === 64,
    `gas ${mm(res.revokeTag).join(" .. ")}`);

  // ---- record(): nine direct calls with real proofs ----
  await (await w.agency.registerVenue(w.addr.dave)).wait();      // a bare venue
  const A = w.addr.alice, Z = ethers.ZeroAddress, U = w.USDC, E = w.ETH;
  let last = null;
  const direct = async (label, op, tin, ain, tout, aout, pid, value) => {
    const pr = await w.buildRec(alice, A);
    const r = await w.tx(null, w.agency.connect(w.signers.dave)
      .record(pr.nf, A, pr.words, pr.rootRCL, pr.rootAT, op, tin, ain, tout, aout, pid));
    const rec = await w.absorbRecord(r, alice, pr, {
      op, asset_in: w.assetId[tin], amount_in: ain, asset_out: w.assetId[tout],
      amount_out: aout, value, position_id: pid }, label);
    res.record.push({ label, leaf_index: rec.leaf_index, i: Number(pr.i), gas: Number(r.gasUsed) });
    console.log(`  [gas] record(): ${r.gasUsed}  ${label}`);
    last = pr;
  };
  await w.warp("2027-02-01T10:00:00Z");
  await direct("claim, the first leaf of the tree (i = 1)", OP.CLAIM, Z, 0, U, 1500, 0, 1500);
  await direct("swap USDC for ETH", OP.SWAP, U, 600, E, 20, 0, 600);
  await direct("swap ETH for USDC", OP.SWAP, E, 10, U, 300, 0, 300);
  await direct("pledge with a loan (opens position 7001)", OP.PLEDGE, E, 10, U, 200, 7001, 200);
  await direct("borrow", OP.BORROW, Z, 0, U, 20, 7001, 20);
  await direct("repay", OP.REPAY, U, 220, Z, 0, 7001, 220);
  await direct("pledge without a loan (opens position 7002)", OP.PLEDGE, E, 5, Z, 0, 7002, 150);
  await direct("swap, leaf 7 (first write of level 3 of the frontier)", OP.SWAP, U, 300, E, 10, 0, 300);
  await direct("swap, leaf 8", OP.SWAP, U, 300, E, 10, 0, 300);
  const steady = res.record.slice(1);
  rep.ok("nine direct record() calls with real proofs accepted, every root equal to the mirror",
    res.record.length === 9, `first leaf ${res.record[0].gas}, then ${mm(steady).join(" .. ")}`);

  // ---- Groth16 verification share ----
  const wd = last.words;
  const pa = [wd[0], wd[1]], pb = [[wd[2], wd[3]], [wd[4], wd[5]]], pc = [wd[6], wd[7]];
  const vaddr = await w.verifier.getAddress();
  const pv = await w.probe.verifyGas(vaddr, pa, pb, pc, last.publicSignals);
  const standalone = await w.verifier.verifyProof.estimateGas(pa, pb, pc, last.publicSignals);
  res.verify = { in_call: Number(pv[1]), standalone_estimate: Number(standalone) };
  rep.ok("verifier accepts the proof inside the probe call", pv[0] === true,
    `in-call ${pv[1]} gas, stand-alone call ${standalone} gas`);

  // ---- one Poseidon call per arity, cold and warm ----
  for (const [n, c] of [[2, w.p2], [3, w.p3], [5, w.p5]]) {
    const data = c.interface.encodeFunctionData(`poseidon(uint256[${n}])`,
      [Array.from({ length: n }, (_, k) => BigInt(k + 1) * 1234567n)]);
    const g = await w.probe.callGas2(await c.getAddress(), data);
    res.poseidon[`P${n}`] = { cold: Number(g[1]), warm: Number(g[2]) };
  }
  console.log("  on-chain Poseidon, gas per call (cold / warm): " +
    Object.entries(res.poseidon).map(([k, v]) => `${k} ${v.cold} / ${v.warm}`).join(", "));
  rep.ok("Poseidon contracts answer the probe", res.poseidon.P2.warm > 0);

  // ---- recordPassive, direct from the bare venue ----
  const passive = async (label, pid, kind, ta, aa, tb, ab, value) => {
    const r = await w.tx(null, w.agency.connect(w.signers.dave)
      .recordPassive(pid, kind, ta, aa, tb, ab, ...(await w.pslPath(pid))));
    const held = w.m.psl.leaves.length;
    await w.absorbPassive(r, { position_id: pid, kind, asset_a: w.assetId[ta], amount_a: aa,
      asset_b: w.assetId[tb], amount_b: ab, value }, label);
    res.recordPassive.push({ label, held, gas: Number(r.gasUsed) });
    console.log(`  [gas] recordPassive(): ${r.gasUsed}  ${label}`);
  };
  await w.warp("2027-06-01T10:00:00Z");
  await passive("withdrawal with interest, PSL empty", 7001, 2, E, 10, E, 1, 30);
  await passive("liquidation, PSL holds 1", 7002, 1, E, 5, U, 100, 100);
  rep.ok("two PSL entries written, PSL root equals the mirror", w.m.psl.leaves.length === 2);

  // ---- insertNullifiers and pinSnapshot ----
  await w.warp("2027-12-31T23:58:00Z");
  for (const n of [1, 2, 6]) {
    const held = w.m.unlCovered;
    const r = await w.insertNullifiers(n, "insertNullifiers");
    res.insertNullifiers.push({ batch: n, held, gas: Number(r.rcpt.gasUsed), per_nullifier: r.perNullifier });
  }
  rc = await w.tx("pinSnapshot (four non-zero roots)", w.agency.connect(w.signers.mallory).pinSnapshot(2027));
  res.pinSnapshot.push({ psl_empty: false, gas: Number(rc.gasUsed) });
  rep.ok("UNL batches of 1, 2 and 6 nullifiers cover the log; snapshot pinned",
    w.m.unlCovered === 9);

  res.prove_ms_in_process = w.proveMs;
  fs.writeFileSync(path.join(OUT, "gas_record.json"), JSON.stringify(res, null, 1));

  console.log("\n==== gas table (real proofs) ====");
  console.log(`writeAnchor            ${mm(res.writeAnchor).join(" .. ")}   (AT holding 0 .. 64 entries; empty tree ${res.writeAnchor[0].gas}, median ${median(res.writeAnchor)}; fit ${res.fit_writeAnchor.a} + ${res.fit_writeAnchor.b} * path length)`);
  console.log(`revokeTag              ${mm(res.revokeTag).join(" .. ")}   (TRL holding 0 .. 63 entries; empty tree ${res.revokeTag[0].gas}, median ${median(res.revokeTag)}; fit ${res.fit_revokeTag.a} + ${res.fit_revokeTag.b} * path length)`);
  for (const r of res.record) console.log(`record                 ${r.gas}   leaf ${r.leaf_index}: ${r.label}`);
  console.log(`record, range          ${mm(steady).join(" .. ")}   (first leaf of the contract: ${res.record[0].gas})`);
  console.log(`  proof verification   ${res.verify.in_call}   (inside the call; stand-alone call ${res.verify.standalone_estimate})`);
  for (const r of res.recordPassive) console.log(`recordPassive          ${r.gas}   ${r.label}`);
  for (const r of res.insertNullifiers) console.log(`insertNullifiers       ${r.gas}   batch of ${r.batch}, UNL held ${r.held}: ${r.per_nullifier} per nullifier`);
  console.log(`pinSnapshot            ${res.pinSnapshot[0].gas}   (four non-zero roots)`);
  console.log(`results written: ${path.join(OUT, "gas_record.json")}`);
});
