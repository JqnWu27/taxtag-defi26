// End-to-end run of one scenario with REAL proofs:
//   1. the JS reference builds the filing(s),
//   2. the Rust driver folds every padded step sequence with Nova + CycleFold
//      and verifies the IVC proof,
//   3. the boundary circuit is proven with Groth16 (snarkjs) and verified,
//   4. the authority-side checks are replayed: the fold's (z_0, z_n) equal
//      the boundary proof's public (z0, zn), the step count is a power of two
//      >= 64, D and C_y are the reference values, and every filing after the
//      first uses the previous C_y as its C_{y-1}.
// Usage: node e2e.js <worked-open|worked-liquidation|worked-withdrawal|two-tags|tag-added|synthetic-100|synthetic-1000|fixture:NAME[:TAXPAYER]>
//                    [--gen-only] [--skip-boundary] [--from <k>]
//   --from k: fold and prove only filings k.. (earlier ones are identical to
//   another scenario's; their C_y still feeds the year-chain check)
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const core = require("./lib/core");
const sc = require("./scenarios");
const { foldInputJson, boundaryPublic, toStr } = require("./lib/filing");
const { scenarioFromFixture } = require("./lib/fixture");

const BUILD = path.join(__dirname, "build");
const EXE = process.platform === "win32" ? ".exe" : "";
const FOLD_BIN = process.env.FILING_FOLD ||
  path.join(__dirname, "..", "folding", "sonobe", "target", "release", "examples", "filing_fold" + EXE);

async function makeScenario(which) {
  if (which === "worked-open") return sc.worked("open");
  if (which === "worked-liquidation") return sc.worked("liquidation");
  if (which === "worked-withdrawal") return sc.worked("withdrawal", { closing2026: true });
  if (which === "two-tags") return sc.twoTags();
  if (which === "tag-added") return sc.tagAdded();
  // a ledger written by the recording side: fixture:<name>[:<taxpayer>]
  const fx = which.match(/^fixture:([\w-]+)(?::(\w+))?$/);
  if (fx) return scenarioFromFixture(fx[1], fx[2] || "alice");
  // n records, 20 of them pledges (each adds one PSL-entry or still-open step)
  const m = which.match(/^synthetic-(\d+)$/);
  if (m) return sc.synthetic(parseInt(m[1], 10), 20);
  throw new Error("unknown scenario " + which);
}

function runFold(inputPath, outPath, logPath) {
  const r = spawnSync(FOLD_BIN, [inputPath,
    "--r1cs", path.join(BUILD, "c_fstep.r1cs"),
    "--wasm", path.join(BUILD, "c_fstep_js", "c_fstep.wasm"),
    "--out", outPath], { encoding: "utf8", maxBuffer: 1 << 26 });
  fs.writeFileSync(logPath, (r.stdout || "") + (r.stderr || ""));
  return { status: r.status, stdout: r.stdout || "", stderr: r.stderr || "" };
}

const isPow2 = (n) => n > 0 && (n & (n - 1)) === 0;

async function main() {
  await core.init();
  const which = process.argv[2];
  const genOnly = process.argv.includes("--gen-only");
  const skipBoundary = process.argv.includes("--skip-boundary");
  const fromIdx = process.argv.includes("--from") ? parseInt(process.argv[process.argv.indexOf("--from") + 1], 10) : 0;
  const s = await makeScenario(which);
  const dir = path.join(BUILD, "runs", s.name);
  fs.mkdirSync(dir, { recursive: true });
  console.log(`== e2e scenario ${s.name} (boundary circuit: NT=${s.NT}, D=${s.D})`);

  let snarkjs = null, vkey = null;
  if (!genOnly && !skipBoundary) {
    snarkjs = require("snarkjs");
    vkey = JSON.parse(fs.readFileSync(path.join(BUILD, "c_boundary.vkey.json"), "utf8"));
  }
  let prevCy = null;
  let allOk = true;
  for (let k = 0; k < s.filings.length; k++) {
    const { label, f, check } = s.filings[k];
    check();
    const fin = path.join(dir, `f${k}_fold_input.json`);
    const fout = path.join(dir, `f${k}_fold_output.json`);
    fs.writeFileSync(fin, JSON.stringify(foldInputJson(f)));
    fs.writeFileSync(path.join(dir, `f${k}_boundary_input.json`), JSON.stringify(toStr(f.boundary)));
    const pub = boundaryPublic(f.boundary, s.NT);
    fs.writeFileSync(path.join(dir, `f${k}_expected.json`), JSON.stringify({
      label, counts: f.counts, z0: f.z0.toString(), zn: f.zn.toString(),
      D: toStr(f.D), c_prev: f.boundary.c_prev.toString(), c_y: f.cY.toString(),
      closing: sc.describeClosing(f.closingState), boundary_public: pub }, null, 1));
    const c = f.counts;
    console.log(`-- filing ${k}: ${label}`);
    console.log(`   steps ${c.steps} = ${c.records} record + ${c.pslEntries} PSL entry + ${c.stillOpen} still open + ${c.padding} padding`);
    if (genOnly) continue;
    if (k < fromIdx) { console.log("   (not folded in this run, see --from)"); prevCy = f.cY; continue; }

    // 2. fold
    const r = runFold(fin, fout, path.join(dir, `f${k}_fold.log`));
    const keep = r.stdout.split(/\r?\n/).filter((l) =>
      /^(preprocess|augmented|folded|IVC verify|steps =|z_0 =|z_n =|z_n equals|peak)/.test(l));
    for (const l of keep) console.log("   [fold] " + l);
    if (r.status !== 0) {
      console.log(`   [fold] exit code ${r.status}: NO accepting IVC proof`);
      allOk = false;
      continue;
    }
    const fo = JSON.parse(fs.readFileSync(fout, "utf8"));

    // 4a. authority checks on the fold's public values
    const chk = (name, cond) => { console.log(`   [check] ${name}: ${cond ? "ok" : "FAIL"}`); if (!cond) allOk = false; };
    chk("IVC proof verifies", fo.ivc_verified === true);
    chk(`step count ${fo.steps} is a power of two >= 64`, isPow2(fo.steps) && fo.steps >= 64);
    chk("fold z_0 = boundary public z0", fo.z0 === pub[0]);
    chk("fold z_n = boundary public zn", fo.zn === pub[1]);

    // 3. boundary proof
    if (!skipBoundary) {
      const t0 = Date.now();
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        toStr(f.boundary), path.join(BUILD, "c_boundary_js", "c_boundary.wasm"),
        path.join(BUILD, "c_boundary.zkey"));
      const t1 = Date.now();
      const okv = await snarkjs.groth16.verify(vkey, publicSignals, proof);
      const t2 = Date.now();
      fs.writeFileSync(path.join(dir, `f${k}_boundary_proof.json`), JSON.stringify(proof));
      fs.writeFileSync(path.join(dir, `f${k}_boundary_public.json`), JSON.stringify(publicSignals));
      chk(`boundary Groth16 proof verifies (witness+prove ${t1 - t0} ms, verify ${t2 - t1} ms)`, okv === true);
      chk("boundary public signals = reference (T, roots, y, D, C_prev, C_y, closing)",
          JSON.stringify(publicSignals) === JSON.stringify(pub));
    }
    if (prevCy !== null) chk("C_{y-1} of this filing = C_y of the previous filing", f.boundary.c_prev === prevCy);
    prevCy = f.cY;
    console.log(`   D = (${f.D.proceeds}, ${f.D.cost}, ${f.D.income})   closing flag = ${f.boundary.closing}`);
    console.log(`   closing state: ${JSON.stringify(sc.describeClosing(f.closingState), (kk, v) => (kk === "C" ? undefined : v))}`);
  }
  if (!genOnly) console.log(allOk ? `== ${s.name}: ALL OK` : `== ${s.name}: FAILED`);
  return allOk;
}

main().then((ok) => process.exit(ok ? 0 : 1)).catch((e) => { console.error("FAILED:", e); process.exit(1); });
