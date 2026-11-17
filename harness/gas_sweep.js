// Gas as a function of tree occupancy, for the functions whose cost depends
// on how much the agency contract already holds:
//   insertNullifiers  per nullifier, UNL holding 0 .. N-1 nullifiers
//   recordPassive     PSL holding 0 .. N/8-1 entries
//   record            leaf index 0 .. N-1 (the part that is not verification)
//   pinSnapshot
//
// The nullifier log is filled through record() of a SEPARATE agency contract
// instance deployed with an always-true verifier stub
// (contracts/test/TestHelpers.sol), because N real proofs would take
// N * 3 s. insertNullifiers, recordPassive and pinSnapshot never call the
// verifier, so their figures are exact. The record() figures here exclude
// proof verification; gas_record.js has the real ones.
// Every root is still checked against the JavaScript mirror.
//
// Usage: node harness/gas_sweep.js [N]      N records, default 1024
//        (writes out/rec/gas_sweep.json)
const fs = require("fs");
const path = require("path");
const { ethers } = require("ethers");
const { run, World, OP } = require("./lib/scenario");
const { OUT, assertEq } = require("./lib/world");

const N = Number(process.argv[2] || 1024);

run(`gas sweep over tree occupancy (stub verifier, ${N} records)`, async (rep) => {
  const w = await World.create({ stubVerifier: true, quiet: true });
  const H = w.H, m = w.m;
  await w.writeAnchorRaw(H.atIndex(1n), H.anchor(2n));          // one known AT root
  await (await w.agency.registerVenue(w.addr.dave)).wait();
  const venue = w.agency.connect(w.signers.dave);
  const A = w.addr.alice, Z = ethers.ZeroAddress;
  const zeros8 = new Array(8).fill(0n);
  // an explicit gas limit skips eth_estimateGas, which would execute every
  // transaction several more times; gasUsed in the receipt is unaffected
  const GAS = { gasLimit: 4000000 };
  const emptyRoot = m.rcl.root(0), rootAT = m.at.root();
  const res = { n: N, record: [], insertSingle: [], insertBatch: [], recordPassive: [], pinSnapshot: null };

  // ---- N records: every 8th is a pledge (opens a position), the rest swaps ----
  const positions = [];
  const t0 = Date.now();
  for (let k = 0; k < N; k++) {
    const nf = H.P([777n, BigInt(k)]);
    const pledge = k % 8 === 3;
    const pid = pledge ? BigInt(9000 + k) : 0n;
    const tx = pledge
      ? await venue.record(nf, A, zeros8, emptyRoot, rootAT, 2, w.ETH, 10, Z, 0, pid, GAS)
      : await venue.record(nf, A, zeros8, emptyRoot, rootAT, 1, w.USDC, 300, w.ETH, 10, 0, GAS);
    const rc = await tx.wait();
    const ev = w.events(rc, "Recorded")[0];
    // independent recomputation of the leaf from the fields the contract reports
    const f = { nf, cid: w.cid, block: BigInt(rc.blockNumber), idx: 0n, time: ev.time,
                op: pledge ? OP.PLEDGE : OP.SWAP, asset_in: pledge ? 2n : 1n,
                amount_in: pledge ? 10n : 300n, asset_out: pledge ? 0n : 2n,
                amount_out: pledge ? 0n : 10n, value: 300n, position_id: pid };
    const leaf = H.recordLeaf(f).leaf;
    assertEq(`record ${k}: leaf`, ev.leaf, leaf);
    m.rcl.append(leaf);
    assertEq(`record ${k}: RCL root`, ev.newRootRCL, m.rcl.root());
    m.nfLog.push(nf);
    if (pledge) positions.push(pid);
    res.record.push({ leaf_index: k, op: pledge ? "pledge" : "swap", gas: Number(rc.gasUsed) });
    if ((k + 1) % 256 === 0) console.log(`  ${k + 1} records appended (${Math.round((Date.now() - t0) / 1000)} s)`);
  }
  await w.checkRoots("after the records");
  const g = (a) => a.map((x) => x.gas);
  const swaps = res.record.filter((r) => r.op === "swap" && r.leaf_index > 0);
  const pledges = res.record.filter((r) => r.op === "pledge");
  rep.ok(`${N} records appended, every RCL root equal to the mirror`, m.rcl.leaves.length === N,
    `record without verification: swap ${Math.min(...g(swaps))} .. ${Math.max(...g(swaps))}, ` +
    `pledge ${Math.min(...g(pledges))} .. ${Math.max(...g(pledges))}, first leaf ${res.record[0].gas}`);

  // ---- insertNullifiers: single inserts at powers of two, batches of 32 between ----
  const any = w.agency.connect(w.signers.mallory);
  const insert = async (count) => {
    const from = m.unlCovered;
    const paths = [];
    let sib = 0;
    for (let k = 0; k < count; k++) {
      const ex = await m.unl.exclusion(m.nfLog[from + k]);
      sib += ex.siblings.length;
      paths.push([ex.siblings, ex.oldKey, ex.oldValue, ex.isOld0]);
      await m.unl.insert(m.nfLog[from + k], 1n);
    }
    const rc = await (await any.insertNullifiers(from, paths, { gasLimit: 29000000 })).wait();
    m.unlCovered = from + count;
    assertEq("UNL root", await w.agency.rootUNL(), m.unl.root());
    return { held: from, batch: count, gas: Number(rc.gasUsed),
             per_nullifier: Math.round(Number(rc.gasUsed) / count),
             avg_siblings: Math.round(100 * sib / count) / 100 };
  };
  while (m.unlCovered < N) {
    const held = m.unlCovered;
    const pow2 = held === 0 || (held & (held - 1)) === 0;
    if (pow2) {
      res.insertSingle.push(await insert(1));
    } else {
      const nextPow = 1 << Math.ceil(Math.log2(held + 1));
      res.insertBatch.push(await insert(Math.min(32, nextPow - held, N - held)));
    }
  }
  await w.checkRoots("after the UNL batches");
  rep.ok(`all ${N} nullifiers batched into the UNL, root equal to the mirror after every batch`,
    m.unlCovered === N);

  // ---- recordPassive: one entry per position, PSL growing ----
  for (let k = 0; k < positions.length; k++) {
    const pid = positions[k];
    const ex = await m.psl.exclusion(pid);
    const liq = k % 2 === 1;
    const tx = liq
      ? await venue.recordPassive(pid, 1, w.ETH, 10, w.USDC, 200, ex.siblings, ex.oldKey, ex.oldValue, ex.isOld0, GAS)
      : await venue.recordPassive(pid, 2, w.ETH, 10, w.ETH, 1, ex.siblings, ex.oldKey, ex.oldValue, ex.isOld0, GAS);
    const rc = await tx.wait();
    const ev = w.events(rc, "PassiveRecorded")[0];
    const e = H.passiveEntry({ kind: liq ? 1n : 2n, cid: w.cid, block: BigInt(rc.blockNumber), idx: 0n,
      time: ev.time, asset_a: 2n, amount_a: 10n, asset_b: liq ? 1n : 2n,
      amount_b: liq ? 200n : 1n, value: liq ? 200n : 30n });
    assertEq(`PSL entry ${k}`, ev.entry, e.pentry);
    await m.psl.insert(pid, e.pentry);
    assertEq(`PSL root ${k}`, ev.newRootPSL, m.psl.root());
    res.recordPassive.push({ held: k, siblings: ex.siblings.length, kind: liq ? 1 : 2, gas: Number(rc.gasUsed) });
  }
  await w.checkRoots("after the PSL entries");
  rep.ok(`${positions.length} PSL entries written, PSL root equal to the mirror after each`,
    m.psl.leaves.length === positions.length,
    `gas ${Math.min(...g(res.recordPassive))} .. ${Math.max(...g(res.recordPassive))}`);

  const rcPin = await (await any.pinSnapshot(2027)).wait();
  res.pinSnapshot = Number(rcPin.gasUsed);
  rep.ok("pinSnapshot accepted once the batches cover the log", rcPin.status === 1, `gas ${res.pinSnapshot}`);

  // ---- linear fit: gas per nullifier against path length (single inserts) ----
  const fit = (pts) => {      // least squares y = a + b x
    const n = pts.length, sx = pts.reduce((s, p) => s + p[0], 0), sy = pts.reduce((s, p) => s + p[1], 0);
    const sxx = pts.reduce((s, p) => s + p[0] * p[0], 0), sxy = pts.reduce((s, p) => s + p[0] * p[1], 0);
    const b = (n * sxy - sx * sy) / (n * sxx - sx * sx);
    return { a: Math.round((sy - b * sx) / n), b: Math.round(b) };
  };
  res.fit_batch = fit(res.insertBatch.map((r) => [r.avg_siblings, r.per_nullifier]));
  res.fit_passive = fit(res.recordPassive.map((r) => [r.siblings, r.gas]));
  fs.writeFileSync(path.join(OUT, "gas_sweep.json"), JSON.stringify(res, null, 1));

  console.log("\n==== insertNullifiers, one nullifier per call ====");
  console.log("UNL held   path length   gas");
  for (const r of res.insertSingle) {
    console.log(`${String(r.held).padStart(8)}   ${String(r.avg_siblings).padStart(11)}   ${r.gas}`);
  }
  console.log("\n==== insertNullifiers, batches (up to 32 per call) ====");
  console.log("UNL held   batch   avg path length   gas per nullifier   gas of the call");
  for (const r of res.insertBatch.filter((_, k, a) => k % Math.max(1, Math.floor(a.length / 14)) === 0 || k === a.length - 1)) {
    console.log(`${String(r.held).padStart(8)}   ${String(r.batch).padStart(5)}   ${String(r.avg_siblings).padStart(15)}   ${String(r.per_nullifier).padStart(17)}   ${r.gas}`);
  }
  console.log(`fit over the batches: gas per nullifier = ${res.fit_batch.a} + ${res.fit_batch.b} * path length`);
  console.log("\n==== recordPassive ====");
  console.log("PSL held   path length   kind   gas");
  for (const r of res.recordPassive.filter((x) => x.held < 4 || (x.held & (x.held - 1)) === 0 || x.held === res.recordPassive.length - 1)) {
    console.log(`${String(r.held).padStart(8)}   ${String(r.siblings).padStart(11)}   ${String(r.kind).padStart(4)}   ${r.gas}`);
  }
  console.log(`fit: gas = ${res.fit_passive.a} + ${res.fit_passive.b} * path length`);
  console.log(`\nrecord() without proof verification, leaf 1 .. ${N - 1}: swap ${Math.min(...g(swaps))} .. ${Math.max(...g(swaps))}; pledge ${Math.min(...g(pledges))} .. ${Math.max(...g(pledges))}; leaf 0: ${res.record[0].gas}`);
  console.log(`pinSnapshot: ${res.pinSnapshot}`);
  console.log(`results written: ${path.join(OUT, "gas_sweep.json")}`);
});
