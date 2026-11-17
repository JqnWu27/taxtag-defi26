// Negative tests (SPEC.md section 8.5, filing part). Every case feeds the
// circuits what a cheating prover would supply and must FAIL to produce an
// accepting proof. Three places can reject:
//
//  step      a folded step violates the step circuit. Shown twice: the wasm
//            witness generator refuses the step, and the REAL fold of the
//            sequence (the arkworks reader ignores failed assertions, like a
//            malicious prover) ends in a failed IVC verification.
//  boundary  the fold itself is a valid IVC proof of a dishonest sequence,
//            but the boundary circuit has no witness. Shown three ways: the
//            real fold verifies, the wasm witness generator refuses the
//            boundary input, and a Groth16 proof forced from the
//            non-satisfying witness does not verify.
//  authority the proof is valid for the prover's own public inputs but the
//            authority verifies against ITS public inputs (its tag set T, its
//            stored C_{y-1}): verification fails.
//  start     every step is valid and the boundary proof is valid, but the
//            chain was run from another state than the claimed z_0. Only the
//            base case of the fold can reject it (folding/basecase_z0.patch):
//            the patched driver ends in a failed IVC verification, the driver
//            built on the unpatched pinned sonobe accepts.
//
// Usage: node negative.js [case-id ...] [--no-fold]
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const snarkjs = require("snarkjs");
const core = require("./lib/core");
const sc = require("./scenarios");
const { buildFiling, foldInputJson, boundaryPublic, toStr } = require("./lib/filing");
const { loadCalculator, stepWitness, shortErr } = require("./lib/wtns");

const BUILD = path.join(__dirname, "build");
const OUT = path.join(BUILD, "runs", "negative");
const EXE = process.platform === "win32" ? ".exe" : "";
const FOLD_BIN = process.env.FILING_FOLD ||
  path.join(__dirname, "..", "folding", "sonobe", "target", "release", "examples", "filing_fold" + EXE);
// the same driver source built against the pinned sonobe WITHOUT the
// base-case constraint (kept to show that the start-state test bites)
const UNPATCHED_BIN = process.env.FILING_FOLD_UNPATCHED ||
  path.join(BUILD, "bin", "filing_fold_unpatched" + EXE);
const { NT, D, USDC } = sc;

const isRec = (e, i) => e.type === "rec" && (i === undefined || e.r.i === i);

// scenario contexts, built once
const ctx = {};
async function workedCtx(variant) {
  if (!ctx[variant]) ctx[variant] = await sc.worked(variant, { only2026: true });
  return ctx[variant];
}
async function twoCtx() {
  if (!ctx.two) ctx.two = await sc.twoTags();
  return ctx.two;
}
const worked2026 = async (variant, extra) => {
  const w = await workedCtx(variant);
  return buildFiling({ tags: w.alice.tags, NT, D, snaps: w.snap26, records: w.alice.records,
                       prev: w.prev26, y: 2026n, strict: false, noPad: true, ...extra });
};
const two2026 = async (extra) => {
  const t = await twoCtx();
  return buildFiling({ tags: t.tp.tags, NT, D, snaps: t.snaps, records: t.tp.records,
                       prev: null, y: 2026n, strict: false, noPad: true, ...extra });
};

const cases = [
  { id: "skipped-counter", level: "step", pad: true,
    title: "skipped counter: record 6 left out, record 7 folded right after record 5",
    build: async () => ({ f: await worked2026("open", { noPad: false, hooks: {
      events: (ev) => ev.filter((e) => !isRec(e, 6n) && e.type !== "open") } }) }) },
  { id: "start-in-the-middle", level: "step",
    title: "start in the middle: a first filing (empty start state) that begins at record 5",
    build: async () => {
      const w = await workedCtx("open");
      return { f: await buildFiling({ tags: w.alice.tags, NT, D, snaps: w.snap26,
        records: w.alice.records, prev: null, y: 2026n, strict: false, noPad: true,
        hooks: { events: (ev) => ev.filter((e) => !(e.type === "rec" && e.r.i <= 4n)) } }) };
    } },
  { id: "start-in-the-middle-claimed-first", level: "boundary",
    title: "start in the middle: start state with counter 4, declared as a first filing (C_{y-1} = 0)",
    build: async () => ({ f: await worked2026("open", { hooks: { boundary: (b) => { b.c_prev = 0n; } } }) }) },
  { id: "hidden-tail", level: "boundary",
    title: "hidden tail: the filing stops before the last record (record 7, the taxed sale)",
    build: async () => ({ f: await worked2026("open", { hooks: {
      events: (ev) => ev.filter((e) => !isRec(e, 7n)) } }) }) },
  { id: "dropped-pair", level: "boundary",
    title: "dropped (tag, chain) pair: no record of (tag B, chain 0) is folded",
    build: async () => ({ f: await two2026({ hooks: {
      events: (ev) => ev.filter((e) => !(e.type === "rec" && e.r.slot === 1 && e.r.ch === 0)) } }) }) },
  { id: "dropped-tag", level: "authority",
    title: "dropped tag: the prover files tag A only, the authority demands T = {A, B}",
    build: async () => {
      const t = await twoCtx();
      const f = await buildFiling({ tags: [t.tp.tags[0]], NT, D, snaps: t.snaps,
        records: t.tp.records, prev: null, y: 2026n, strict: false, noPad: true });
      const pub = boundaryPublic(f.boundary, NT);
      const authority = pub.slice();
      authority[3] = t.tp.tags[1].tag.toString();          // tags[1] of the authority's T
      return { f, authority, what: "the authority's tag set T" };
    } },
  { id: "wrong-start-state", level: "boundary",
    title: "wrong start state: USDC carried at average cost 2 instead of 1, true C_{y-1} public",
    build: async () => ({ f: await worked2026("open", { hooks: { start: tamperStart } }) }) },
  { id: "wrong-c-prev", level: "authority",
    title: "wrong C_{y-1}: the altered start state with a matching forged C_{y-1}",
    build: async () => {
      const w = await workedCtx("open");
      let forged = null;
      const f = await worked2026("open", { hooks: {
        start: (h) => {
          tamperStart(h);
          forged = core.fmt.closingCommitment(
            core.fmt.closingDigest(h.start.ra0, h.start.ledgerPrevRoot, h.start.ro0, h.start.nOpen0),
            core.fmt.blindY(w.alice.tags[0].S, 2025n));
        },
        boundary: (b) => { b.c_prev = forged; } } });
      const authority = boundaryPublic(f.boundary, NT);
      authority[authority.length - 3] = w.prev26.C.toString();   // the C_{y-1} the authority holds
      return { f, authority, what: "the C_{y-1} the authority holds" };
    } },
  { id: "altered-value", level: "step",
    title: "altered value: record 5 opened with value 6600 instead of 6000 (ATK1)",
    build: async () => ({ f: await worked2026("open", { hooks: {
      events: (ev) => ev.map((e) => (isRec(e, 5n) ? { ...e, r: { ...e.r, value: 6600n } } : e)) } }) }) },
  { id: "altered-amount", level: "step",
    title: "altered amount: record 7 opened with 3000 USDC received instead of 3600",
    build: async () => ({ f: await worked2026("open", { hooks: {
      events: (ev) => ev.map((e) => (isRec(e, 7n) ? { ...e, r: { ...e.r, amountOut: 3000n } } : e)) } }) }) },
  { id: "inflated-average", level: "step",
    title: "inflated average cost: buy of record 5 with quotient 4000 and remainder p - 2000",
    build: async () => ({ f: await worked2026("open", { hooks: {
      ext: (k, ext, ev) => {
        if (ev && isRec(ev, 5n)) { ext[115] = 4000n; ext[116] = core.F.p - 2000n; }
      } } }) }) },
  { id: "reordered", level: "step",
    title: "reordered records: two records of different (tag, chain) pairs swapped (ATK6)",
    build: async () => ({ f: await two2026({ hooks: {
      events: (ev) => { const o = ev.slice(); const t = o[2]; o[2] = o[3]; o[3] = t; return o; } } }) }) },
  { id: "undeclared-liquidation", level: "step",
    title: "undeclared liquidation: an occupied PSL leaf presented as still open",
    build: async () => ({ f: await worked2026("liquidation", { hooks: {
      events: (ev) => {
        const p = ev.find((e) => e.type === "psl");
        return ev.filter((e) => e !== p).concat([{ type: "open", ch: p.ch, positionId: p.e.positionId }]);
      } } }) }) },
  { id: "undeclared-liquidation-forged-exclusion", level: "step",
    title: "undeclared liquidation with a forged exclusion proof (non-boolean isOld0)",
    build: async () => {
      const w = await workedCtx("liquidation");
      const e0 = w.snap26[0].pslEntries.get(w.pledge.positionId);
      const { P, F } = core;
      const realLeaf = P([e0.positionId, e0.entry, 1n]);
      const fakeKey = e0.positionId + 1000n, fakeVal = 1n;
      const t = F.toObject(F.sub(F.e(1n), F.div(F.e(realLeaf), F.e(P([fakeKey, fakeVal, 1n])))));
      return { f: await worked2026("liquidation", { hooks: {
        events: (ev) => {
          const p = ev.find((e) => e.type === "psl");
          return ev.filter((e) => e !== p).concat([{ type: "open", ch: p.ch, positionId: p.e.positionId }]);
        },
        ext: (k, ext, ev) => {
          if (ev && ev.type === "open") { ext[74] = fakeKey; ext[75] = fakeVal; ext[76] = t; }
        } } }) };
    } },
  { id: "position-dropped", level: "boundary",
    title: "position silently dropped: the open position gets no still-open step",
    build: async () => ({ f: await worked2026("open", { hooks: {
      events: (ev) => ev.filter((e) => e.type !== "open") } }) }) },
  { id: "liquidation-dropped", level: "boundary",
    title: "liquidated position silently dropped: its PSL entry is never folded",
    build: async () => ({ f: await worked2026("liquidation", { hooks: {
      events: (ev) => ev.filter((e) => e.type !== "psl") } }) }) },
  { id: "double-still-open", level: "step",
    title: "liquidated position hidden behind a second still-open step of another position",
    build: async () => ({ f: await two2026({ hooks: {
      events: (ev) => {
        const o = ev.find((e) => e.type === "open");
        return ev.filter((e) => e.type !== "psl").concat([{ ...o }]);
      } } }) }) },
  { id: "phantom-position", level: "step",
    title: "still-open step for a position that is not in the working set",
    build: async () => ({ f: await worked2026("open", { hooks: {
      events: (ev) => ev.concat([{ type: "open", ch: 0, positionId: 777777n }]) } }) }) },
  { id: "closing-with-open-position", level: "boundary",
    title: "closing flag set while one position is still open",
    build: async () => ({ f: await worked2026("open", { closing: 1n }) }) },
  { id: "fold-starts-elsewhere", level: "start",
    title: "chain run from another start state (USDC carried at average cost 2) while the proof claims the z_0 bound to C_{y-1}",
    build: async () => {
      // the honest filing gives the z_0 that the boundary proof binds to C_{y-1}
      const honest = await worked2026("open", {});
      // every step of the cheat is valid, from the altered start state
      const f = await worked2026("open", { hooks: { start: tamperStart } });
      // boundary input: the honest start, the cheat's end state, D and C_y
      const boundary = { ...f.boundary, z0: honest.z0, ra0: honest.boundary.ra0 };
      return { f, claimedZ0: honest.z0, boundary, honestD: honest.D };
    } },
];

function tamperStart(h) {
  h.assets.set(USDC, { q: 6000n, avg: 2n });
  h.assetTree.set(Number(USDC), core.fmt.assetLeaf(6000n, 2n));
  h.st.rootAssets = h.assetTree.root();
  h.start.ra0 = h.st.rootAssets;
}

// opt.extra: extra fields of the fold input (claimed_z0); opt.bin: another
// driver binary; opt.tag: suffix of the files written
function runFold(dir, id, f, opt = {}) {
  const tag = opt.tag ? `_${opt.tag}` : "";
  const fin = path.join(dir, `${id}${tag}_fold_input.json`);
  const fout = path.join(dir, `${id}${tag}_fold_output.json`);
  fs.writeFileSync(fin, JSON.stringify({ ...foldInputJson(f), ...(opt.extra || {}) }));
  const r = spawnSync(opt.bin || FOLD_BIN, [fin, "--r1cs", path.join(BUILD, "c_fstep.r1cs"),
    "--wasm", path.join(BUILD, "c_fstep_js", "c_fstep.wasm"), "--out", fout],
    { encoding: "utf8", maxBuffer: 1 << 26 });
  fs.writeFileSync(path.join(dir, `${id}${tag}_fold.log`), (r.stdout || "") + (r.stderr || ""));
  const line = (r.stdout || "").split(/\r?\n/).find((l) => l.startsWith("IVC verify:")) || "(no IVC line)";
  // incoming instance (last step) and running instance (all earlier steps)
  const rel = (r.stdout || "").split(/\r?\n/).filter((l) => /^\s*r1cs\((w_i, u_i|W_i, U_i)\)/.test(l))
    .map((l) => l.trim()).join("; ");
  return { status: r.status, line: line.trim(), rel };
}

async function main() {
  await core.init();
  fs.mkdirSync(OUT, { recursive: true });
  const args = process.argv.slice(2);
  const doFold = !args.includes("--no-fold");
  const wanted = args.filter((a) => !a.startsWith("--"));
  const vkey = JSON.parse(fs.readFileSync(path.join(BUILD, "c_boundary.vkey.json"), "utf8"));
  const zkey = path.join(BUILD, "c_boundary.zkey");
  const bwasm = path.join(BUILD, "c_boundary_js", "c_boundary.wasm");
  const wcStep = await loadCalculator("c_fstep");
  const wcB = await loadCalculator("c_boundary");
  const wcBF = await loadCalculator("c_boundary", { force: true });
  const results = [];
  let bad = 0;

  for (const c of cases) {
    if (wanted.length && !wanted.includes(c.id)) continue;
    console.log(`-- ${c.id} [${c.level}] ${c.title}`);
    const built = await c.build();
    const { f, authority, what } = built;
    const res = { id: c.id, level: c.level, title: c.title, steps: f.steps.length, rejected: false };
    const note = (s) => console.log("   " + s);

    // step witnesses with the checking generator
    let failStep = -1, trace = "";
    let z = f.z0;
    for (let k = 0; k < f.steps.length; k++) {
      try {
        const w = await stepWitness(wcStep, z, f.steps[k]);
        z = w[1];
      } catch (e) { failStep = k; trace = shortErr(e, "step"); break; }
    }

    if (c.level === "step") {
      const wasmRejects = failStep >= 0;
      note(`wasm witness: ${wasmRejects ? `step ${failStep} of ${f.steps.length} REJECTED at ${trace}` : "all steps accepted (UNEXPECTED)"}`);
      res.wasm = wasmRejects ? `step ${failStep} rejected at ${trace}` : "accepted";
      let foldRejects = true;
      if (doFold) {
        const r = runFold(OUT, c.id, f);
        foldRejects = r.status === 2;
        note(`real fold of ${f.steps.length} steps: ${r.line}${r.rel ? "  [" + r.rel + "]" : ""}  (exit ${r.status})`);
        res.fold = `${r.line} (exit ${r.status})`;
      }
      res.rejected = wasmRejects && foldRejects;
    } else if (c.level === "boundary") {
      const stepsOk = failStep < 0;
      note(`wasm witness: all ${f.steps.length} steps accepted: ${stepsOk ? "yes (the fold alone does not catch this)" : "NO, step " + failStep + " " + trace}`);
      let foldOk = true;
      if (doFold) {
        const r = runFold(OUT, c.id, f);
        foldOk = r.status === 0;
        note(`real fold of ${f.steps.length} steps: ${r.line} (exit ${r.status})`);
        res.fold = `${r.line} (exit ${r.status})`;
      }
      let bRejects = false, btrace = "";
      try { await wcB.calculateWitness(toStr(f.boundary), 0); }
      catch (e) { bRejects = true; btrace = shortErr(e, "boundary"); }
      note(`boundary wasm witness: ${bRejects ? "REJECTED at " + btrace : "accepted (UNEXPECTED)"}`);
      res.boundaryWasm = bRejects ? `rejected at ${btrace}` : "accepted";
      // forced proof from the non-satisfying witness
      wcBF.resetFailed();
      const wtns = await wcBF.calculateWTNSBin(toStr(f.boundary), 0);
      const failed = wcBF.failedAsserts;
      const { proof, publicSignals } = await snarkjs.groth16.prove(zkey, wtns);
      const okv = await snarkjs.groth16.verify(vkey, publicSignals, proof);
      note(`forced Groth16 proof (${failed} failed assertion(s) ignored): verify -> ${okv}`);
      res.forcedProofVerifies = okv;
      res.rejected = stepsOk && foldOk && bRejects && okv === false;
    } else if (c.level === "start") {
      // Every step is valid and the boundary proof is valid: only the base
      // case of the fold (z_i = z_0 at i = 0) can reject this.
      const stepsOk = failStep < 0;
      note(`wasm witness: all ${f.steps.length} steps accepted from the altered start state: ${stepsOk ? "yes" : "NO, step " + failStep + " " + trace}`);
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(toStr(built.boundary), bwasm, zkey);
      const bOk = await snarkjs.groth16.verify(vkey, publicSignals, proof);
      note(`boundary Groth16 proof with z0 = the honest start digest and the cheat's end state: verify -> ${bOk} ` +
           `(D = (${f.D.proceeds}, ${f.D.cost}, ${f.D.income}) instead of (${built.honestD.proceeds}, ${built.honestD.cost}, ${built.honestD.income}))`);
      res.boundaryVerifies = bOk;
      let patchedRejects = true, unpatchedAccepts = true;
      if (doFold) {
        const extra = { claimed_z0: built.claimedZ0.toString() };
        const r = runFold(OUT, c.id, f, { extra });
        patchedRejects = r.status === 2;
        note(`real fold, driver WITH the base-case constraint: ${r.line}${r.rel ? "  [" + r.rel + "]" : ""}  (exit ${r.status})`);
        res.fold = `${r.line} (exit ${r.status})`;
        if (fs.existsSync(UNPATCHED_BIN)) {
          const u = runFold(OUT, c.id, f, { extra, bin: UNPATCHED_BIN, tag: "unpatched" });
          unpatchedAccepts = u.status === 0;
          note(`real fold, driver built WITHOUT the constraint (pinned sonobe as is): ${u.line} (exit ${u.status})` +
               (unpatchedAccepts ? "  <- the unpatched IVC accepts the chain, so the test bites" : "  (UNEXPECTED)"));
          res.foldUnpatched = `${u.line} (exit ${u.status})`;
        } else {
          note("unpatched driver binary not present, comparison skipped");
        }
      }
      res.rejected = stepsOk && bOk === true && patchedRejects && unpatchedAccepts;
    } else {
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(toStr(f.boundary), bwasm, zkey);
      const own = await snarkjs.groth16.verify(vkey, publicSignals, proof);
      const auth = await snarkjs.groth16.verify(vkey, authority, proof);
      note(`boundary proof against the prover's own public inputs: verify -> ${own}`);
      note(`boundary proof against ${what}: verify -> ${auth}`);
      res.ownVerify = own; res.authorityVerify = auth;
      res.rejected = own === true && auth === false;
    }
    console.log(`   => ${res.rejected ? "REJECTED as required" : "TEST FAILED (not rejected the expected way)"}`);
    if (!res.rejected) bad++;
    results.push(res);
  }
  fs.writeFileSync(path.join(OUT, "negative_results.json"), JSON.stringify(results, null, 1));
  console.log(`negative tests: ${results.length - bad}/${results.length} rejected as required`);
  return bad === 0;
}

main().then((ok) => process.exit(ok ? 0 : 1)).catch((e) => { console.error("FAILED:", e); process.exit(1); });
