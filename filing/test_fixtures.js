// Integration check with the RECORDING side: every ledger in fixtures/*.json
// (written by the recording harness after real recording proofs were verified
// by the agency contract) is opened by the filing prover. For every filing:
// all trees are rebuilt and compared with the pinned roots, every step
// witness is computed with the real step-circuit wasm and compared with the
// JS reference, the boundary witness is computed, and D and the closing state
// are compared with the recording side's own rule reference.
// Usage: node test_fixtures.js [fixture-name ...]
const fs = require("fs");
const path = require("path");
const core = require("./lib/core");
const { scenarioFromFixture, FIXTURES } = require("./lib/fixture");
const { loadCalculator } = require("./lib/wtns");
const { runScenario } = require("./test_witness");

async function main() {
  await core.init();
  const wanted = process.argv.slice(2);
  const names = fs.readdirSync(FIXTURES).filter((f) => f.endsWith(".json")).map((f) => f.replace(".json", ""))
    .filter((n) => !wanted.length || wanted.includes(n));
  const wcStep = await loadCalculator("c_fstep");
  const wcB = await loadCalculator("c_boundary");
  let count = 0;
  for (const name of names) {
    const fx = JSON.parse(fs.readFileSync(path.join(FIXTURES, `${name}.json`), "utf8"));
    for (const e of fx.expected) {
      await runScenario(await scenarioFromFixture(name, e.taxpayer), wcStep, wcB);
      count++;
    }
  }
  console.log(`recording-side fixtures opened by the filing circuits: ${count} ledgers, ALL OK`);
}
main().catch((e) => { console.error("FAILED:", e.message || e); process.exitCode = 1; });
