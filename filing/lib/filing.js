// Filing prover, JS reference (SPEC.md sections 5, 6, 7): merges the
// period's records and PSL entries by (time, cid, block, idx), runs the rule
// program from the state committed in C_{y-1}, and emits
//   - the padded step sequence for the fold (external_inputs of c_fstep),
//   - the start and end state digests z0, zn,
//   - the boundary circuit input,
//   - D, C_y and the closing state the next filing starts from.
// The generator does not refuse a dishonest sequence when opts.strict is
// false: it feeds the circuits what a cheating prover would supply, which is
// how the negative tests are built.
const core = require("./core");
const { fmt, P, PosTree, bitReverse, nextPow2, DR, DA, DL, DP, MIN_STEPS,
        TWO64, OP, PKIND, KIND } = core;
const { runRules } = require("./rules");

const NS = 12;          // state vector length
const NP = 9;           // pins length
const EIL = NS + NP + 12 + (4 + DL) + (1 + DP + 3) + 2 * (3 + DA) + 2;   // 117

const emptyAssetLeaf = () => fmt.assetLeaf(0n, 0n);
const emptyLedgerLeaf = () => fmt.ledgerLeaf(0n, 0n, 0n);

// the closing state of "no filing yet"
function emptyClosing() {
  return {
    y: null, C: 0n, tagCount: 0,
    assets: new Map(), assetTree: new PosTree(DA, emptyAssetLeaf()),
    counters: [],
    open: new Map(), openTree: new PosTree(DA, emptyAssetLeaf()), nOpen: 0n,
  };
}

function stateVector(s) {
  return [s.rootAssets, s.rootLedger, s.rootOpen, s.cntWork, s.cntFinal,
          s.proceeds, s.cost, s.other, s.keyHi, s.keyLo, s.pins, s.blind];
}

function cmpKey(a, b) {
  for (let k = 0; k < 4; k++) {
    if (a[k] < b[k]) return -1;
    if (a[k] > b[k]) return 1;
  }
  return 0;
}

function ledgerTreeOf(tags, counters, count) {
  const t = new PosTree(DL, emptyLedgerLeaf());
  for (let j = 0; j < count; j++) {
    t.set(j, fmt.ledgerLeaf(tags[j].idTax, counters[j][0], counters[j][1]));
  }
  return t;
}

// opts:
//   tags      [{tag, S, idTax}] in slot order (the demanded set T)
//   NT        tag slots of the boundary circuit
//   D         SMT depth of the boundary circuit's AT / UNL proofs
//   snaps     [snapshot chain 0, snapshot chain 1]
//   records   the taxpayer's own records (any period; filtered here)
//   prev      closing state of the previous filing, or null
//   y         period
//   closing   1n for a closing filing
//   strict    default true: throw if the honest prover would be stuck
//   hooks     { events(list) -> list, ext(k, ext, ev), boundary(input),
//               start(startState) } for the negative tests
async function buildFiling(opts) {
  const { tags, NT, D = 64, snaps, records, y } = opts;
  const closing = opts.closing ? 1n : 0n;
  const strict = opts.strict !== false;
  const hooks = opts.hooks || {};
  const prev = opts.prev || emptyClosing();
  const Fp = core.F.p;
  if (tags.length > NT) throw new Error("more tags than slots");

  // ---- start state ----------------------------------------------------------
  const assets = new Map();
  for (const [k, v] of prev.assets) assets.set(k, { q: v.q, avg: v.avg });
  const assetTree = prev.assetTree.clone();
  const openTree = prev.openTree.clone();
  const open = new Map();
  for (const [k, v] of prev.open) open.set(k, { ...v });
  const m = tags.map((_, j) => (j < prev.counters.length ? [...prev.counters[j]] : [0n, 0n]));
  const isNew = tags.map((_, j) => (j >= prev.counters.length ? 1n : 0n));
  const ledgerPrev = ledgerTreeOf(tags, prev.counters, prev.counters.length);
  const counters = m.map((x) => [...x]);
  const ledger = ledgerTreeOf(tags, counters, tags.length);

  const pinsArr = [snaps[0].cid, snaps[1].cid, snaps[0].acaddr, snaps[1].acaddr,
                   snaps[0].rootRCL, snaps[1].rootRCL, snaps[0].rootPSL, snaps[1].rootPSL,
                   BigInt(y)];
  const blind = fmt.stateBlind(tags[0].S, BigInt(y));
  const st = {
    rootAssets: assetTree.root(), rootLedger: ledger.root(), rootOpen: openTree.root(),
    cntWork: prev.nOpen, cntFinal: 0n, proceeds: 0n, cost: 0n, other: 0n,
    keyHi: 0n, keyLo: 0n, pins: fmt.pins(pinsArr), blind,
  };
  const start = {
    ra0: st.rootAssets, ro0: st.rootOpen, nOpen0: st.cntWork,
    ledgerPrevRoot: ledgerPrev.root(), cPrev: prev.C,
  };
  if (hooks.start) hooks.start({ st, start, assets, assetTree, counters, ledger, m, isNew });
  const startAssets = new Map();
  for (const [k, v] of assets) startAssets.set(k, { q: v.q, avg: v.avg });
  const z0 = fmt.stateDigest(stateVector(st));

  // ---- the merged sequence --------------------------------------------------
  const mine = records.filter((r) =>
    r.slot < tags.length && r.leafIndex < snaps[r.ch].rcl.size && r.i > m[r.slot][r.ch]);
  let events = mine.map((r) => ({ type: "rec", key: [r.time, r.cid, r.block, r.idx], r }));
  // positions to settle: carried ones and this period's pledges
  const positions = [];
  for (const v of prev.open.values()) positions.push({ ch: v.ch, positionId: v.positionId });
  for (const r of mine) if (r.op === OP.PLEDGE) positions.push({ ch: r.ch, positionId: r.positionId });
  const stillOpen = [];
  for (const pos of positions) {
    const e = snaps[pos.ch].pslEntries.get(pos.positionId);
    if (e) events.push({ type: "psl", key: [e.time, e.cid, e.block, e.idx], e, ch: pos.ch });
    else stillOpen.push({ type: "open", ch: pos.ch, positionId: pos.positionId });
  }
  events.sort((a, b) => cmpKey(a.key, b.key));
  events = events.concat(stillOpen);
  if (hooks.events) events = hooks.events(events);

  // ---- one step per event ---------------------------------------------------
  const zerosA = new Array(DA).fill(0n);
  const steps = [];
  const digests = [];
  const findOpenSlot = (ch, positionId) => {
    for (const [slotIdx, v] of open) {
      if (v.ch === ch && v.positionId === positionId) return slotIdx;
    }
    return -1;
  };
  const freeOpenSlot = () => {
    let k = 0;
    while (open.has(k)) k++;
    return k;
  };
  const assetOf = (id) => assets.get(id) || { q: 0n, avg: 0n };

  const push = (ext, ev) => {
    if (ext.length !== EIL) throw new Error(`ext length ${ext.length} != ${EIL}`);
    if (hooks.ext) hooks.ext(steps.length, ext, ev);
    steps.push(ext);
    digests.push(fmt.stateDigest(stateVector(st)));
  };

  for (const ev of events) {
    const sv = stateVector(st);
    const isRec = ev.type === "rec", isPsl = ev.type === "psl", isOpen = ev.type === "open";
    const ch = isRec ? ev.r.ch : ev.ch;
    const snap = snaps[ch];

    // event fields in the circuit's shared layout
    let op = 0n, a1 = 0n, m1 = 0n, a2 = 0n, m2 = 0n, value = 0n, positionId = 0n;
    let block = 0n, idx = 0n, time = 0n;
    if (isRec) {
      const r = ev.r;
      op = r.op; a1 = r.assetIn; m1 = r.amountIn; a2 = r.assetOut; m2 = r.amountOut;
      value = r.value; positionId = r.positionId; block = r.block; idx = r.idx; time = r.time;
    } else if (isPsl) {
      const e = ev.e;
      op = e.kind; a1 = e.assetA; m1 = e.amountA; a2 = e.assetB; m2 = e.amountB;
      value = e.value; positionId = e.positionId; block = e.block; idx = e.idx; time = e.time;
    } else {
      positionId = ev.positionId;
    }
    const swap = isRec && op === OP.SWAP, pledge = isRec && op === OP.PLEDGE;
    const borrow = isRec && op === OP.BORROW, repay = isRec && op === OP.REPAY;
    const claim = isRec && op === OP.CLAIM;
    const liq = isPsl && op === PKIND.LIQUIDATION, wd = isPsl && op === PKIND.WITHDRAWAL;

    // ledger opening and the authenticated path
    let slot = 0n, idTax = 0n, n0 = 0n, n1 = 0n, lsib = new Array(DL).fill(0n);
    let pathKey = 0n, psib = new Array(DP).fill(0n), oldKey = 0n, oldValue = 0n, isOld0 = 0n;
    if (isRec) {
      const r = ev.r;
      slot = BigInt(r.slot);
      idTax = tags[r.slot].idTax;
      [n0, n1] = counters[r.slot];
      lsib = ledger.path(r.slot);
      if (strict && r.i !== counters[r.slot][r.ch] + 1n) {
        throw new Error(`record counter ${r.i} is not next (${counters[r.slot][r.ch] + 1n})`);
      }
      pathKey = bitReverse(r.leafIndex, DR);
      const up = snap.rcl.path(r.leafIndex);
      for (let j = 0; j < DR; j++) psib[j] = up[DR - 1 - j];
      counters[r.slot][r.ch] += 1n;
      ledger.set(r.slot, fmt.ledgerLeaf(idTax, counters[r.slot][0], counters[r.slot][1]));
    } else {
      pathKey = positionId;
      const pr = await snap.psl.proof(positionId, DP);
      psib = pr.siblings;
      if (isOpen) {
        if (strict && pr.found) throw new Error("PSL leaf occupied, position is not still open");
        oldKey = pr.oldKey; oldValue = pr.oldValue; isOld0 = pr.isOld0;
      } else if (strict && !pr.found) {
        throw new Error("PSL entry not found under the pinned root");
      }
    }

    // rule slots
    const s1dis = swap || repay || liq;
    const buyKind = swap || pledge || borrow || claim || wd;
    const buyEn = buyKind && m2 !== 0n;
    const s2buy = swap && m2 !== 0n;
    const s1buy = buyEn && !s2buy;
    const s2open = pledge || isPsl || isOpen;

    let idx1 = 0n, q1 = 0n, avg1 = 0n, sib1 = zerosA;
    let idx2 = 0n, x2 = 0n, y2 = 0n, sib2 = zerosA;
    let avgHint = 0n, rem = 0n;
    const doBuy = (id) => {
      const a = assetOf(id);
      const qpe = a.q + m2;
      const num = a.q * a.avg + value;
      avgHint = num / qpe;
      rem = num % qpe;
      assets.set(id, { q: qpe, avg: avgHint });
      assetTree.set(Number(id), fmt.assetLeaf(qpe, avgHint));
    };
    if (s1dis) {
      const a = assetOf(a1);
      idx1 = a1; q1 = a.q; avg1 = a.avg; sib1 = assetTree.path(Number(a1));
      const d = a.q < m1 ? a.q : m1;
      assets.set(a1, { q: a.q - d, avg: a.avg });
      assetTree.set(Number(a1), fmt.assetLeaf(a.q - d, a.avg));
      if (swap || liq) st.cost += d * a.avg;
    } else if (s1buy) {
      const a = assetOf(a2);
      idx1 = a2; q1 = a.q; avg1 = a.avg; sib1 = assetTree.path(Number(a2));
      doBuy(a2);
    }
    if (s2buy) {
      const a = assetOf(a2);
      idx2 = a2; x2 = a.q; y2 = a.avg; sib2 = assetTree.path(Number(a2));
      doBuy(a2);
    } else if (s2open) {
      const key = fmt.openKey(snap.cid, positionId);
      if (pledge) {
        const k = freeOpenSlot();
        idx2 = BigInt(k); x2 = 0n; y2 = 0n; sib2 = openTree.path(k);
        open.set(k, { ch, positionId, key, mark: 0n });
        openTree.set(k, fmt.openLeaf(key, 0n));
        st.cntWork += 1n;
      } else {
        const k = findOpenSlot(ch, positionId);
        if (k < 0) {
          if (strict) throw new Error("position is not in the open set");
          // a cheating prover has no leaf to show; present an empty slot
          const f = freeOpenSlot();
          idx2 = BigInt(f); sib2 = openTree.path(f);
        } else {
          const v = open.get(k);
          idx2 = BigInt(k); x2 = v.key; y2 = v.mark; sib2 = openTree.path(k);
          if (isPsl) {
            open.delete(k);
            openTree.set(k, emptyAssetLeaf());
          } else {
            if (strict && v.mark === BigInt(y)) throw new Error("position already settled");
            v.mark = BigInt(y);
            openTree.set(k, fmt.openLeaf(key, BigInt(y)));
            st.cntFinal += 1n;
          }
        }
        st.cntWork -= 1n;
      }
    }
    if (swap || liq) st.proceeds += value;
    if (claim || wd) st.other += value;
    if (isRec || isPsl) {
      st.keyHi = time * TWO64 + snap.cid;
      st.keyLo = block * TWO64 + idx;
    }
    st.rootAssets = assetTree.root();
    st.rootLedger = ledger.root();
    st.rootOpen = openTree.root();

    const kind = isRec ? KIND.RECORD : isPsl ? KIND.PSL : KIND.OPEN;
    push([...sv, ...pinsArr, kind, BigInt(ch), op, a1, m1, a2, m2, value, positionId,
          block, idx, time, slot, idTax, n0, n1, ...lsib, pathKey, ...psib, oldKey,
          oldValue, isOld0, idx1, q1, avg1, ...sib1, idx2, x2, y2, ...sib2, avgHint, rem],
         ev);
  }

  // ---- padding to the next power of two, at least 64 -------------------------
  const realSteps = steps.length;
  const total = opts.noPad ? realSteps : Math.max(MIN_STEPS, nextPow2(realSteps));
  while (steps.length < total) {
    const ext = [...stateVector(st), ...pinsArr, ...new Array(EIL - NS - NP).fill(0n)];
    steps.push(ext);
    digests.push(fmt.stateDigest(stateVector(st)));
  }
  const zn = fmt.stateDigest(stateVector(st));

  // ---- D, C_y, closing state --------------------------------------------------
  const income = st.proceeds - st.cost + st.other;
  const Dv = { proceeds: st.proceeds, cost: st.cost, income };
  const cY = fmt.closingCommitment(
    fmt.closingDigest(st.rootAssets, st.rootLedger, st.rootOpen, st.cntFinal),
    fmt.blindY(tags[0].S, BigInt(y)));
  const closingState = {
    y: BigInt(y), C: cY, tagCount: tags.length, assets, assetTree,
    counters: counters.map((x) => [...x]), open, openTree, nOpen: st.cntFinal,
  };

  // ---- boundary circuit input ---------------------------------------------------
  const zrow = () => new Array(D).fill(0n);
  const b = {
    z0, zn,
    tags: [], cid: [snaps[0].cid, snaps[1].cid], acaddr: [snaps[0].acaddr, snaps[1].acaddr],
    root_rcl: [snaps[0].rootRCL, snaps[1].rootRCL], root_unl: [snaps[0].rootUNL, snaps[1].rootUNL],
    root_at: [snaps[0].rootAT, snaps[1].rootAT], root_psl: [snaps[0].rootPSL, snaps[1].rootPSL],
    y: BigInt(y), d_proceeds: Dv.proceeds, d_cost: Dv.cost,
    d_income: ((income % Fp) + Fp) % Fp,
    c_prev: start.cPrev, c_y: cY, closing,
    S: [], blind,
    ra0: start.ra0, ro0: start.ro0, n_open0: start.nOpen0,
    m: [], is_new: [],
    ra1: st.rootAssets, ro1: st.rootOpen, cf1: st.cntFinal,
    proceeds: st.proceeds, cost: st.cost, other: st.other, khi: st.keyHi, klo: st.keyLo,
    n: [], at_sib: [], unl_sib: [], unl_oldKey: [], unl_oldValue: [], unl_isOld0: [],
  };
  for (let j = 0; j < NT; j++) {
    if (j >= tags.length) {
      b.tags.push(0n); b.S.push(0n); b.m.push([0n, 0n]); b.is_new.push(0n); b.n.push([0n, 0n]);
      b.at_sib.push([zrow(), zrow()]); b.unl_sib.push([zrow(), zrow()]);
      b.unl_oldKey.push([0n, 0n]); b.unl_oldValue.push([0n, 0n]); b.unl_isOld0.push([0n, 0n]);
      continue;
    }
    const t = tags[j];
    b.tags.push(t.tag); b.S.push(t.S); b.m.push([...m[j]]); b.is_new.push(isNew[j]);
    b.n.push([...counters[j]]);
    const ats = [], unls = [], ok = [], ov = [], o0 = [];
    for (let c = 0; c < 2; c++) {
      const ap = await snaps[c].at.proof(fmt.atIndex(t.tag), D);
      if (strict && !ap.found) throw new Error("anchor not in the AT");
      ats.push(ap.siblings);
      const nf = fmt.nullifier(t.idTax, snaps[c].cid, snaps[c].acaddr, counters[j][c] + 1n);
      const up = await snaps[c].unl.proof(nf, D);
      if (strict && up.found) throw new Error("NF_{n+1} is used: the ledger has a hidden tail");
      unls.push(up.siblings); ok.push(up.oldKey); ov.push(up.oldValue); o0.push(up.isOld0);
    }
    b.at_sib.push(ats); b.unl_sib.push(unls);
    b.unl_oldKey.push(ok); b.unl_oldValue.push(ov); b.unl_isOld0.push(o0);
  }
  if (hooks.boundary) hooks.boundary(b);

  // independent rule check on the honest path
  if (strict && !hooks.events && !hooks.start) {
    const ref = runRules(startAssets, events);
    if (ref.proceeds !== Dv.proceeds || ref.cost !== Dv.cost || ref.income !== Dv.income) {
      throw new Error("rule engine and step generator disagree on D");
    }
    for (const [k, v] of ref.assets) {
      const a = assets.get(k);
      if (!a || a.q !== v.q || a.avg !== v.avg) throw new Error("asset state mismatch at " + k);
    }
  }

  return {
    z0, zn, steps, digests, realSteps, D: Dv, cY, closingState, boundary: b,
    counts: {
      records: events.filter((e) => e.type === "rec").length,
      pslEntries: events.filter((e) => e.type === "psl").length,
      stillOpen: events.filter((e) => e.type === "open").length,
      padding: steps.length - realSteps, steps: steps.length,
    },
    finalState: { ...st },
  };
}

// JSON helpers ------------------------------------------------------------------
function toStr(x) {
  if (Array.isArray(x)) return x.map(toStr);
  if (typeof x === "bigint") return x.toString();
  if (x && typeof x === "object") {
    const o = {};
    for (const k of Object.keys(x)) o[k] = toStr(x[k]);
    return o;
  }
  return x;
}

function foldInputJson(f) {
  return { n: f.steps.length, z0: [f.z0.toString()], zn: f.zn.toString(),
           steps: f.steps.map((s) => s.map((x) => x.toString())) };
}

// public signals of the boundary circuit, in circuit order
function boundaryPublic(b, NT) {
  return [b.z0, b.zn, ...b.tags.slice(0, NT), ...b.cid, ...b.acaddr, ...b.root_rcl,
          ...b.root_unl, ...b.root_at, ...b.root_psl, b.y, b.d_proceeds, b.d_cost,
          b.d_income, b.c_prev, b.c_y, b.closing].map((x) => x.toString());
}

module.exports = { buildFiling, emptyClosing, stateVector, toStr, foldInputJson,
                   boundaryPublic, NS, NP, EIL };
