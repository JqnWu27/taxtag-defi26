// Witness-level validation: for every step of every filing of a scenario the
// step circuit's witness is computed with the real wasm and its output digest
// is compared with the JS reference; then the boundary circuit's witness is
// computed and its public signals are compared with the reference.
// Usage: node test_witness.js [worked-open|worked-liquidation|worked-withdrawal|two-tags|synthetic-100|all]
const core = require("./lib/core");
const sc = require("./scenarios");
const { boundaryPublic, toStr } = require("./lib/filing");
const { loadCalculator, stepWitness } = require("./lib/wtns");

async function runScenario(s, wcStep, wcB) {
  let ok = true;
  console.log(`== scenario ${s.name}`);
  for (const { label, f, check } of s.filings) {
    check();
    let z = f.z0;
    const t0 = Date.now();
    for (let k = 0; k < f.steps.length; k++) {
      const w = await stepWitness(wcStep, z, f.steps[k]);
      if (w[1] !== f.digests[k]) {
        throw new Error(`${label}: step ${k} output digest differs from the reference`);
      }
      z = w[1];
    }
    if (z !== f.zn) throw new Error(`${label}: z_n mismatch`);
    const wb = await wcB.calculateWitness(toStr(f.boundary), 0);
    const pub = boundaryPublic(f.boundary, s.NT);
    for (let k = 0; k < pub.length; k++) {
      if (wb[1 + k].toString() !== pub[k]) throw new Error(`${label}: boundary public signal ${k}`);
    }
    const c = f.counts;
    console.log(`  ${label}`);
    console.log(`    steps ${c.steps} = ${c.records} record + ${c.pslEntries} PSL entry + ${c.stillOpen} still open + ${c.padding} padding;` +
                ` all ${c.steps} step witnesses match the reference, boundary witness ok (${Date.now() - t0} ms)`);
    console.log(`    D = (${f.D.proceeds}, ${f.D.cost}, ${f.D.income})  C_prev = ${short(f.boundary.c_prev)}  C_y = ${short(f.cY)}`);
    console.log(`    closing: ${JSON.stringify(sc.describeClosing(f.closingState), (k, v) => (k === "C" ? undefined : v))}`);
  }
  return ok;
}

const short = (x) => { const s = x.toString(); return s.length > 12 ? s.slice(0, 6) + ".." + s.slice(-4) : s; };

async function main() {
  await core.init();
  const which = process.argv[2] || "all";
  const wcStep = await loadCalculator("c_fstep");
  const wcB = await loadCalculator("c_boundary");
  const list = [];
  if (which === "all" || which === "worked-open") list.push(() => sc.worked("open"));
  if (which === "all" || which === "worked-liquidation") list.push(() => sc.worked("liquidation"));
  if (which === "all" || which === "worked-withdrawal") list.push(() => sc.worked("withdrawal", { closing2026: true }));
  if (which === "all" || which === "two-tags") list.push(() => sc.twoTags());
  if (which === "all" || which === "synthetic-100") list.push(() => sc.synthetic(100, 20));
  if (which === "synthetic-1000") list.push(() => sc.synthetic(1000, 20));
  for (const mk of list) await runScenario(await mk(), wcStep, wcB);
  console.log("witness-level validation: ALL OK");
}

module.exports = { runScenario };
if (require.main === module) {
  main().catch((e) => { console.error("FAILED:", e.message || e); process.exitCode = 1; });
}
