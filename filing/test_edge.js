// Edge cases of the year chain and the tag set, witness level (real wasm of
// the step and boundary circuits, compared with the JS reference):
//  1 zero-length ledger: a first filing of a tag with no record at all
//    (64 padding steps, NF_1 unused on both chains): the verifiable
//    nothing-to-report of the paper
//  2 the tag set grows: filing 2025 covers tag A, filing 2026 covers A and a
//    new tag B (its ledger leaf is created in the boundary circuit)
//  3 negative: an EXISTING tag declared "new" in 2026 to restart its counters
//    must be rejected by the boundary circuit
//  4 negative: filing 2026 directly on top of C_2024 (a skipped period) must
//    be rejected by the boundary circuit
// Usage: node test_edge.js
const core = require("./lib/core");
const { Chain, Taxpayer } = require("./lib/world");
const { buildFiling, toStr, boundaryPublic } = require("./lib/filing");
const { loadCalculator, stepWitness, shortErr } = require("./lib/wtns");
const { OP } = core;
const NT = 2, D = 64, USDC = 1n, ETH = 2n;

let failures = 0;
const report = (ok, label, detail) => {
  if (!ok) failures++;
  console.log(`  ${ok ? "ok  " : "FAIL"} ${label}${detail ? ": " + detail : ""}`);
};

async function witnessAll(f, wcStep, wcB) {
  let z = f.z0;
  for (let k = 0; k < f.steps.length; k++) {
    const w = await stepWitness(wcStep, z, f.steps[k]);
    if (w[1] !== f.digests[k]) throw new Error(`step ${k} digest differs`);
    z = w[1];
  }
  if (z !== f.zn) throw new Error("z_n differs");
  const wb = await wcB.calculateWitness(toStr(f.boundary), 0);
  const pub = boundaryPublic(f.boundary, NT);
  for (let k = 0; k < pub.length; k++) if (wb[1 + k].toString() !== pub[k]) throw new Error("public signal " + k);
}

async function boundaryRejects(f, wcB) {
  try { await wcB.calculateWitness(toStr(f.boundary), 0); return null; }
  catch (e) { return shortErr(e, "edge-boundary"); }
}

async function main() {
  await core.init();
  const wcStep = await loadCalculator("c_fstep");
  const wcB = await loadCalculator("c_boundary");
  const mk = async () => [
    await Chain.create({ cid: 1337n, acaddr: 111n, startBlock: 10n }),
    await Chain.create({ cid: 1338n, acaddr: 222n, startBlock: 20n, firstPositionId: 500n })];
  const snap = async (chains) => [await chains[0].snapshot(), await chains[1].snapshot()];

  console.log("== 1 zero-length ledger");
  {
    const chains = await mk();
    const tp = new Taxpayer([{ tag: 1001n, S: 2002n }]);
    await tp.register(chains, 0);
    await chains[0].noise(3, 100n);
    const f = await buildFiling({ tags: tp.tags, NT, D, snaps: await snap(chains), records: tp.records, prev: null, y: 2026n });
    await witnessAll(f, wcStep, wcB);
    report(f.counts.records === 0 && f.counts.padding === 64 && f.D.income === 0n,
      "first filing with no record: 64 padding steps, D = (0, 0, 0), all step witnesses and the boundary witness accepted");
  }

  console.log("== 2 the tag set grows between two filings");
  const chains = await mk();
  const tp = new Taxpayer([{ tag: 3003n, S: 4004n }]);
  await tp.register(chains, 0);
  await tp.record(chains, 0, 0, { op: OP.CLAIM, assetOut: USDC, amountOut: 900n, value: 900n, time: 1000n });
  await tp.record(chains, 0, 1, { op: OP.SWAP, assetIn: USDC, amountIn: 600n, assetOut: ETH, amountOut: 2n, value: 600n, time: 1100n });
  const s25 = await snap(chains);
  const f25 = await buildFiling({ tags: tp.tags, NT, D, snaps: s25, records: tp.records, prev: null, y: 2025n });
  await witnessAll(f25, wcStep, wcB);
  report(true, "2025: tag A alone (slot 1 inactive)", `D = (${f25.D.proceeds}, ${f25.D.cost}, ${f25.D.income})`);
  const slotB = tp.addTag({ tag: 5005n, S: 6006n });
  await tp.register(chains, slotB);
  await tp.record(chains, slotB, 1, { op: OP.CLAIM, assetOut: ETH, amountOut: 1n, value: 310n, time: 2000n });
  await tp.record(chains, 0, 0, { op: OP.SWAP, assetIn: ETH, amountIn: 3n, assetOut: USDC, amountOut: 1000n, value: 1000n, time: 2100n });
  await tp.record(chains, slotB, 0, { op: OP.CLAIM, assetOut: USDC, amountOut: 5n, value: 5n, time: 2200n });
  const s26 = await snap(chains);
  const f26 = await buildFiling({ tags: tp.tags, NT, D, snaps: s26, records: tp.records, prev: f25.closingState, y: 2026n });
  await witnessAll(f26, wcStep, wcB);
  report(f26.boundary.is_new[0] === 0n && f26.boundary.is_new[1] === 1n,
    "2026: tags A (carried, counters 1 and 1) and B (new), start from C_2025",
    `D = (${f26.D.proceeds}, ${f26.D.cost}, ${f26.D.income}), end counters ${JSON.stringify(toStr(f26.closingState.counters))}`);

  console.log("== 3 an existing tag declared new, to restart its counters at 0");
  {
    // the cheater keeps the carried assets but starts every counter at 0, as
    // if tag A were new in 2026 (its previous ledger leaf would have to be
    // empty), and folds A's ledger from record 1 again
    const f = await buildFiling({ tags: tp.tags, NT, D, snaps: s26, records: tp.records,
      prev: { ...f25.closingState, counters: [] }, y: 2026n, strict: false, noPad: true });
    const why = await boundaryRejects(f, wcB);
    report(why !== null, "boundary circuit rejects", why || "ACCEPTED");
  }

  console.log("== 4 a skipped period: filing 2027 directly on top of C_2025");
  {
    const f = await buildFiling({ tags: tp.tags, NT, D, snaps: s26, records: tp.records,
      prev: f25.closingState, y: 2027n, strict: false, noPad: true });
    const why = await boundaryRejects(f, wcB);
    report(why !== null, "boundary circuit rejects (C_{y-1} is opened with period y - 1)", why || "ACCEPTED");
  }
  console.log(failures === 0 ? "edge cases: ALL OK" : `edge cases: ${failures} FAILED`);
  process.exitCode = failures === 0 ? 0 : 1;
}
main().catch((e) => { console.error("FAILED:", e.message || e); process.exitCode = 1; });
