// Prints the compile-time constants hard-coded in circuits/filing/c_boundary_core.circom
// (empty-subtree roots of the ledger tree and the empty depth-16 root), and
// with --check verifies that the circuit file carries exactly these values.
const fs = require("fs");
const path = require("path");
const core = require("./lib/core");

async function main() {
  await core.init();
  const { P, DA, DL } = core;
  const EL = [P([0n, 0n, 0n])];
  for (let k = 0; k < DL; k++) EL.push(P([EL[k], EL[k]]));
  let e = P([0n, 0n]);
  for (let k = 0; k < DA; k++) e = P([e, e]);
  console.log("EL =", EL.map(String));
  console.log("EMPTY16 =", String(e));
  if (process.argv.includes("--check")) {
    const src = fs.readFileSync(path.join(__dirname, "..", "circuits", "filing", "c_boundary_core.circom"), "utf8");
    let ok = src.includes(`var EMPTY16 = ${e};`);
    for (const v of EL) ok = ok && src.includes(String(v));
    console.log(ok ? "constants in c_boundary_core.circom: OK" : "constants in c_boundary_core.circom: MISMATCH");
    process.exit(ok ? 0 : 1);
  }
}
main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
