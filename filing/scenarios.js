// Validation scenarios of SPEC.md section 8 (filing part). Every scenario
// builds its own synthetic chains (lib/world.js), records the transactions,
// pins the snapshot and calls the filing prover (lib/filing.js).
// Each scenario returns { name, NT, D, filings: [{ label, f, check() }] }.
const core = require("./lib/core");
const { Chain, Taxpayer } = require("./lib/world");
const { buildFiling } = require("./lib/filing");
const { OP, PKIND } = core;

const USDC = 1n, ETH = 2n, DAI = 3n, WBTC = 4n, LINK = 5n, UNI = 6n;
const NT = 2;        // boundary circuit instance used by the tests
const D = 64;

const ALICE = { tag: 0x7c31a9e04b5d2f16n, S: 0x92e4d1c07a3b5e88n };
const ALICE2 = { tag: 0x4be19c2203f7a6d1n, S: 0x1f55c0aa9e3471b2n };

function assertEq(a, b, what) {
  if (a !== b) throw new Error(`${what}: got ${a}, expected ${b}`);
}

async function mkChains() {
  const c0 = await Chain.create({ cid: 1337n, acaddr: 0x00a11ce0000000000000000000000000000a9e01n,
                                  startBlock: 8000n, firstPositionId: 41n });
  const c1 = await Chain.create({ cid: 1338n, acaddr: 0x00a11ce0000000000000000000000000000a9e02n,
                                  startBlock: 520000n, firstPositionId: 9001n });
  // other taxpayers' anchors
  for (const c of [c0, c1]) {
    await c.at.insert(core.fmt.atIndex(424242n), core.fmt.anchor(737373n));
    await c.at.insert(core.fmt.atIndex(515151n), core.fmt.anchor(626262n));
  }
  return [c0, c1];
}

const snapAll = async (chains) => [await chains[0].snapshot(), await chains[1].snapshot()];

function describeClosing(cs) {
  const assets = {};
  for (const [k, v] of cs.assets) assets[k.toString()] = [v.q.toString(), v.avg.toString()];
  return {
    assets, counters: cs.counters.map((x) => x.map(String)),
    open: [...cs.open.values()].map((v) => ({ ch: v.ch, positionId: v.positionId.toString(),
                                              mark: v.mark.toString() })),
    nOpen: cs.nOpen.toString(), C: cs.C.toString(),
  };
}

// ---- (a) (b) the paper's worked example, three consecutive filings ----------
// variant: "open" (the paper's run), "liquidation", "withdrawal"
// hooks2026: optional negative-test hooks for the 2026 filing
async function worked(variant = "open", opts = {}) {
  await core.init();
  const chains = await mkChains();
  const alice = new Taxpayer([ALICE]);
  await alice.register(chains, 0);
  const T0 = 1735700000n;                      // early 2025
  const out = { name: `worked-${variant}`, NT, D, filings: [] };

  // ---- 2025: Alice's previous filing, a first filing. Four records that
  //      close with 6000 USDC at average cost 1 and the counter at 4.
  await chains[0].noise(3, T0);
  await chains[1].noise(2, T0 + 5n);
  await alice.record(chains, 0, 0, { op: OP.CLAIM, assetOut: USDC, amountOut: 2000n, value: 2000n, time: T0 + 100n });
  await chains[0].noise(2, T0 + 150n);
  await alice.record(chains, 0, 0, { op: OP.SWAP, assetIn: USDC, amountIn: 500n, assetOut: DAI, amountOut: 500n, value: 500n, time: T0 + 200n });
  await alice.record(chains, 0, 0, { op: OP.SWAP, assetIn: DAI, amountIn: 500n, assetOut: USDC, amountOut: 500n, value: 500n, time: T0 + 300n });
  await alice.record(chains, 0, 0, { op: OP.CLAIM, assetOut: USDC, amountOut: 4000n, value: 4000n, time: T0 + 400n });
  await chains[0].noisePassive(T0 + 450n);
  const snap25 = await snapAll(chains);
  const f25 = await buildFiling({ tags: alice.tags, NT, D, snaps: snap25, records: alice.records,
                                  prev: null, y: 2025n });
  out.filings.push({
    label: "2025 first filing (records 1-4)", f: f25,
    check: () => {
      const a = f25.closingState.assets;
      assertEq(a.get(USDC).q, 6000n, "2025 USDC q"); assertEq(a.get(USDC).avg, 1n, "2025 USDC avg");
      assertEq(f25.closingState.counters[0][0], 4n, "2025 counter");
      assertEq(f25.boundary.c_prev, 0n, "2025 c_prev");
    },
  });

  // ---- 2026: the worked example, records 5, 6, 7 ------------------------------
  const T1 = T0 + 31536000n;
  await chains[0].noise(2, T1);
  // TX1: swap 6000 USDC for 2 ETH, value 6000 (record 5)
  await alice.record(chains, 0, 0, { op: OP.SWAP, assetIn: USDC, amountIn: 6000n, assetOut: ETH, amountOut: 2n, value: 6000n, time: T1 + 1000n });
  await chains[0].noise(1, T1 + 1500n);
  // TX2: pledge 1 ETH carrying a loan of 2000 USDC, one pledge record (record 6)
  const pledge = await alice.record(chains, 0, 0, { op: OP.PLEDGE, assetIn: ETH, amountIn: 1n, assetOut: USDC, amountOut: 2000n, value: 2000n, time: T1 + 2000n });
  if (variant === "liquidation") {
    // the venue liquidates: 1 ETH seized, 2000 USDC of debt covered
    await chains[0].recordPassive({ positionId: pledge.positionId, kind: PKIND.LIQUIDATION,
      assetA: ETH, amountA: 1n, assetB: USDC, amountB: 2000n, value: 2000n, time: T1 + 2500n });
  }
  // TX3: swap 1 ETH for 3600 USDC through the aggregator, net amounts (record 7)
  await alice.record(chains, 0, 0, { op: OP.SWAP, assetIn: ETH, amountIn: 1n, assetOut: USDC, amountOut: 3600n, value: 3600n, time: T1 + 3000n });
  if (variant === "withdrawal") {
    // Alice repays the loan (record 8) and withdraws; the venue writes the
    // withdrawal entry with 50 USDC of interest earned
    await alice.record(chains, 0, 0, { op: OP.REPAY, assetIn: USDC, amountIn: 2000n, value: 2000n, positionId: pledge.positionId, time: T1 + 3500n });
    await chains[0].recordPassive({ positionId: pledge.positionId, kind: PKIND.WITHDRAWAL,
      assetA: ETH, amountA: 1n, assetB: USDC, amountB: 50n, value: 50n, time: T1 + 4000n });
  }
  await chains[0].noise(2, T1 + 5000n);
  const snap26 = await snapAll(chains);
  out.snap26 = snap26; out.alice = alice; out.prev26 = f25.closingState; out.pledge = pledge;
  const f26 = await buildFiling({ tags: alice.tags, NT, D, snaps: snap26, records: alice.records,
                                  prev: f25.closingState, y: 2026n,
                                  closing: opts.closing2026 ? 1n : 0n,
                                  strict: opts.strict, hooks: opts.hooks2026, noPad: opts.noPad });
  out.filings.push({
    label: `2026 worked example (${variant})`, f: f26,
    check: () => {
      const cs = f26.closingState, a = cs.assets;
      if (variant === "open") {
        assertEq(f26.D.proceeds, 9600n, "D.proceeds"); assertEq(f26.D.cost, 9000n, "D.cost");
        assertEq(f26.D.income, 600n, "D.income");
        assertEq(a.get(ETH).q, 1n, "ETH q"); assertEq(a.get(ETH).avg, 3000n, "ETH avg");
        assertEq(a.get(USDC).q, 5600n, "USDC q"); assertEq(a.get(USDC).avg, 1n, "USDC avg");
        assertEq(cs.counters[0][0], 7n, "counter"); assertEq(cs.nOpen, 1n, "open positions");
      } else if (variant === "liquidation") {
        // + disposal of the seized ETH: proceeds 2000 against cost 3000
        assertEq(f26.D.proceeds, 11600n, "D.proceeds"); assertEq(f26.D.cost, 12000n, "D.cost");
        assertEq(f26.D.income, -400n, "D.income");
        assertEq(a.get(ETH).q, 0n, "ETH q"); assertEq(a.get(USDC).q, 5600n, "USDC q");
        assertEq(cs.counters[0][0], 7n, "counter"); assertEq(cs.nOpen, 0n, "open positions");
      } else {
        // + repay 2000 USDC (no totals), + 50 USDC interest as income
        assertEq(f26.D.proceeds, 9600n, "D.proceeds"); assertEq(f26.D.cost, 9000n, "D.cost");
        assertEq(f26.D.income, 650n, "D.income");
        assertEq(a.get(ETH).q, 1n, "ETH q"); assertEq(a.get(USDC).q, 3650n, "USDC q");
        assertEq(a.get(USDC).avg, 1n, "USDC avg");
        assertEq(cs.counters[0][0], 8n, "counter"); assertEq(cs.nOpen, 0n, "open positions");
      }
    },
  });
  if (opts.only2026) return out;

  // ---- 2027: the next filing starts from C_2026 --------------------------------
  const T2 = T1 + 31536000n;
  await chains[0].noise(1, T2);
  await alice.record(chains, 0, 0, { op: OP.CLAIM, assetOut: USDC, amountOut: 10n, value: 10n, time: T2 + 100n });
  const snap27 = await snapAll(chains);
  const f27 = await buildFiling({ tags: alice.tags, NT, D, snaps: snap27, records: alice.records,
                                  prev: f26.closingState, y: 2027n });
  out.filings.push({
    label: "2027 next filing, starts from C_2026", f: f27,
    check: () => {
      assertEq(f27.boundary.c_prev, f26.cY, "2027 c_prev = C_2026");
      assertEq(f27.D.income, 10n, "2027 income");
      assertEq(f27.closingState.nOpen, variant === "open" ? 1n : 0n, "2027 open positions");
    },
  });
  return out;
}

// ---- (c) two tags on two chains, interleaved by time ---------------------------
async function twoTags(opts = {}) {
  await core.init();
  const chains = await mkChains();
  const tp = new Taxpayer([ALICE, ALICE2]);
  await tp.register(chains, 0);
  await tp.register(chains, 1);
  const T = 1767300000n;
  await chains[0].noise(2, T);
  await chains[1].noise(3, T);
  const rec = (slot, ch, fields) => tp.record(chains, slot, ch, fields);
  // slot 0 = tag A, slot 1 = tag B; chain slots 0 and 1
  await rec(0, 0, { op: OP.CLAIM, assetOut: USDC, amountOut: 9000n, value: 9000n, time: T + 10n });
  await rec(1, 1, { op: OP.CLAIM, assetOut: USDC, amountOut: 4000n, value: 4000n, time: T + 20n });
  await rec(1, 0, { op: OP.SWAP, assetIn: USDC, amountIn: 3000n, assetOut: ETH, amountOut: 1n, value: 3000n, time: T + 30n });
  await rec(0, 1, { op: OP.SWAP, assetIn: USDC, amountIn: 6400n, assetOut: ETH, amountOut: 2n, value: 6400n, time: T + 40n });
  // same timestamp on both chains: the chain id breaks the tie (1337 < 1338)
  const pA = await rec(0, 0, { op: OP.PLEDGE, assetIn: ETH, amountIn: 1n, assetOut: DAI, amountOut: 1500n, value: 1500n, time: T + 50n });
  const pB = await rec(1, 1, { op: OP.PLEDGE, assetIn: ETH, amountIn: 2n, value: 6200n, time: T + 50n });
  // two records of different tags in one block of chain 1: idx breaks the tie
  await rec(0, 1, { op: OP.BORROW, assetOut: USDC, amountOut: 1000n, value: 1000n, positionId: pB.positionId, time: T + 60n });
  await rec(1, 1, { op: OP.SWAP, assetIn: DAI, amountIn: 500n, assetOut: WBTC, amountOut: 1n, value: 520n, time: T + 60n });
  await chains[0].noise(1, T + 65n);
  // the venue on chain 1 liquidates tag B's position
  await chains[1].recordPassive({ positionId: pB.positionId, kind: PKIND.LIQUIDATION,
    assetA: ETH, amountA: 2n, assetB: USDC, amountB: 1000n, value: 1000n, time: T + 70n });
  await rec(0, 0, { op: OP.SWAP, assetIn: ETH, amountIn: 1n, assetOut: USDC, amountOut: 3500n, value: 3500n, time: T + 80n });
  await rec(1, 0, { op: OP.REPAY, assetIn: DAI, amountIn: 700n, value: 700n, positionId: pA.positionId, time: T + 90n });
  await rec(0, 1, { op: OP.CLAIM, assetOut: LINK, amountOut: 40n, value: 610n, time: T + 100n });
  await rec(1, 1, { op: OP.SWAP, assetIn: WBTC, amountIn: 1n, assetOut: USDC, amountOut: 560n, value: 560n, time: T + 110n });
  const snaps = await snapAll(chains);
  const f = await buildFiling({ tags: tp.tags, NT, D, snaps, records: tp.records, prev: null,
                                y: 2026n, strict: opts.strict, hooks: opts.hooks, noPad: opts.noPad });
  return {
    name: "two-tags-two-chains", NT, D, snaps, tp,
    filings: [{
      label: "2026 two tags on two chains (12 records, 1 liquidation, 1 still open)", f,
      check: () => {
        assertEq(f.counts.records, 12, "records"); assertEq(f.counts.pslEntries, 1, "PSL entries");
        assertEq(f.counts.stillOpen, 1, "still open");
        const c = f.closingState.counters;
        assertEq(c[0][0], 3n, "A chain0"); assertEq(c[0][1], 3n, "A chain1");
        assertEq(c[1][0], 2n, "B chain0"); assertEq(c[1][1], 4n, "B chain1");
      },
    }],
  };
}

// ---- (d) synthetic run with n records: 2 tags x 2 chains -------------------------
// n records in total; `pledges` of them are pledges, each settled by one more
// step (liquidation, withdrawal or still open), so steps = n + pledges.
function prng(seed) {
  let s = BigInt(seed) & ((1n << 64n) - 1n);
  return (mod) => {
    s ^= (s << 13n) & ((1n << 64n) - 1n); s ^= s >> 7n; s ^= (s << 17n) & ((1n << 64n) - 1n);
    return Number(s % BigInt(mod));
  };
}

async function synthetic(n, pledges, seed = 20261111) {
  await core.init();
  const chains = await mkChains();
  const tp = new Taxpayer([ALICE, ALICE2]);
  await tp.register(chains, 0);
  await tp.register(chains, 1);
  const rnd = prng(seed);
  const assetsList = [USDC, ETH, DAI, WBTC, LINK, UNI];
  const price = { [USDC]: 1n, [ETH]: 3000n, [DAI]: 1n, [WBTC]: 60000n, [LINK]: 15n, [UNI]: 8n };
  let t = 1767300000n;
  const openPos = [];
  const pledgeAt = new Set();
  while (pledgeAt.size < pledges) pledgeAt.add(2 + rnd(n - 4));
  let made = 0;
  for (let k = 0; k < n; k++) {
    t += BigInt(1 + rnd(900));
    const slot = rnd(2), ch = rnd(2);
    if (rnd(5) === 0) await chains[rnd(2)].noise(1 + rnd(2), t);
    const px = (a) => price[a] + BigInt(rnd(Number(price[a] / 10n + 1n)));
    if (pledgeAt.has(k)) {
      const coll = assetsList[1 + rnd(5)];
      const withLoan = rnd(2) === 0;
      const amt = BigInt(1 + rnd(5));
      const f = { op: OP.PLEDGE, assetIn: coll, amountIn: amt, time: t };
      if (withLoan) { f.assetOut = USDC; f.amountOut = BigInt(100 + rnd(2000)); f.value = f.amountOut; }
      else f.value = amt * px(coll);
      const r = await tp.record(chains, slot, ch, f);
      openPos.push({ ch, positionId: r.positionId, coll, amt, fate: made % 3, at: k + 3 + rnd(20) });
      made++;
    } else {
      const kind = rnd(10);
      if (k < 4 || kind < 2) {
        const a = assetsList[rnd(6)];
        const amt = BigInt(1 + rnd(k < 4 ? 20000 : 300));
        await tp.record(chains, slot, ch, { op: OP.CLAIM, assetOut: a, amountOut: amt, value: amt * px(a), time: t });
      } else if (kind < 7) {
        const a = assetsList[rnd(6)];
        let b = assetsList[rnd(6)];
        if (b === a) b = assetsList[(assetsList.indexOf(a) + 1) % 6];
        const amtIn = BigInt(1 + rnd(400));
        const v = amtIn * px(a);
        let amtOut = v / px(b);
        if (rnd(25) === 0) amtOut = 0n;         // dust swap that returns nothing
        await tp.record(chains, slot, ch, { op: OP.SWAP, assetIn: a, amountIn: amtIn, assetOut: b, amountOut: amtOut, value: v, time: t });
      } else if (kind < 8 && openPos.length) {
        const p = openPos[rnd(openPos.length)];
        const amt = BigInt(50 + rnd(900));
        await tp.record(chains, slot, p.ch, { op: OP.BORROW, assetOut: DAI, amountOut: amt, value: amt, positionId: p.positionId, time: t });
      } else if (kind < 9 && openPos.length) {
        const p = openPos[rnd(openPos.length)];
        const amt = BigInt(50 + rnd(900));
        await tp.record(chains, slot, p.ch, { op: OP.REPAY, assetIn: rnd(2) ? DAI : USDC, amountIn: amt, value: amt, positionId: p.positionId, time: t });
      } else {
        const a = assetsList[1 + rnd(5)];
        const amt = BigInt(1 + rnd(50));
        await tp.record(chains, slot, ch, { op: OP.CLAIM, assetOut: a, amountOut: amt, value: amt * px(a), time: t });
      }
    }
    // passive events written by the venues
    for (const p of openPos) {
      if (p.done || p.at > k || p.fate === 2) continue;
      t += BigInt(1 + rnd(60));
      if (p.fate === 0) {
        const debt = BigInt(100 + rnd(3000));
        await chains[p.ch].recordPassive({ positionId: p.positionId, kind: PKIND.LIQUIDATION,
          assetA: p.coll, amountA: p.amt, assetB: USDC, amountB: debt, value: debt, time: t });
      } else {
        const interest = BigInt(rnd(40));     // may be 0
        await chains[p.ch].recordPassive({ positionId: p.positionId, kind: PKIND.WITHDRAWAL,
          assetA: p.coll, amountA: p.amt, assetB: p.coll, amountB: interest,
          value: interest * px(p.coll), time: t });
      }
      p.done = true;
    }
  }
  const snaps = await snapAll(chains);
  const f = await buildFiling({ tags: tp.tags, NT, D, snaps, records: tp.records, prev: null, y: 2026n });
  return {
    name: `synthetic-${n}`, NT, D,
    filings: [{
      label: `2026 synthetic run, ${n} records, 2 tags x 2 chains`, f,
      check: () => {
        assertEq(f.counts.records, n, "records");
        assertEq(f.counts.pslEntries + f.counts.stillOpen, pledges, "position steps");
      },
    }],
  };
}

// ---- the tag set grows: 2025 covers tag A, 2026 covers A and a new tag B --------
async function tagAdded() {
  await core.init();
  const chains = await mkChains();
  const tp = new Taxpayer([ALICE]);
  await tp.register(chains, 0);
  const T = 1735700000n;
  await chains[0].noise(2, T);
  await tp.record(chains, 0, 0, { op: OP.CLAIM, assetOut: USDC, amountOut: 900n, value: 900n, time: T + 100n });
  await tp.record(chains, 0, 1, { op: OP.SWAP, assetIn: USDC, amountIn: 600n, assetOut: ETH, amountOut: 2n, value: 600n, time: T + 200n });
  const s25 = await snapAll(chains);
  const f25 = await buildFiling({ tags: tp.tags, NT, D, snaps: s25, records: tp.records, prev: null, y: 2025n });
  // the authority issues a second tag; its anchor is written on both chains
  const slotB = tp.addTag(ALICE2);
  await tp.register(chains, slotB);
  const T1 = T + 31536000n;
  await tp.record(chains, slotB, 1, { op: OP.CLAIM, assetOut: ETH, amountOut: 1n, value: 310n, time: T1 + 100n });
  await tp.record(chains, 0, 0, { op: OP.SWAP, assetIn: ETH, amountIn: 3n, assetOut: USDC, amountOut: 1000n, value: 1000n, time: T1 + 200n });
  await tp.record(chains, slotB, 0, { op: OP.CLAIM, assetOut: USDC, amountOut: 5n, value: 5n, time: T1 + 300n });
  const s26 = await snapAll(chains);
  const f26 = await buildFiling({ tags: tp.tags, NT, D, snaps: s26, records: tp.records,
                                  prev: f25.closingState, y: 2026n });
  return {
    name: "tag-added", NT, D,
    filings: [
      { label: "2025 first filing, tag A alone (slot 1 inactive)", f: f25,
        check: () => { assertEq(f25.boundary.tags[1], 0n, "slot 1 inactive"); assertEq(f25.D.income, 900n, "2025 income"); } },
      { label: "2026 filing, tags A (carried) and B (new in this filing), starts from C_2025", f: f26,
        check: () => {
          assertEq(f26.boundary.is_new[0], 0n, "A carried"); assertEq(f26.boundary.is_new[1], 1n, "B new");
          assertEq(f26.boundary.c_prev, f25.cY, "c_prev = C_2025");
          // 3 ETH held at floor((600 + 310) / 3) = 303: cost 909
          assertEq(f26.D.proceeds, 1000n, "proceeds"); assertEq(f26.D.cost, 909n, "cost"); assertEq(f26.D.income, 406n, "income");
          const c = f26.closingState.counters;
          assertEq(c[0][0], 2n, "A chain0"); assertEq(c[0][1], 1n, "A chain1");
          assertEq(c[1][0], 1n, "B chain0"); assertEq(c[1][1], 1n, "B chain1");
        } },
    ],
  };
}

// ---- sixteen tags on two chains (the full depth-4 ledger tree), NT = 16 ----------
// 28 records: every tag but one claims on one chain, every second tag swaps on
// the other chain, two pledges (one stays open, one is liquidated), three
// second records. Tag 7 has no record at all (zero-length ledgers).
// opts.hooks / opts.strict / opts.noPad as in buildFiling (negative test).
const tagOf = (j) => ({ tag: 0x51a9000000000000n + BigInt(j) * 0x9e3779b97f4an + 7n,
                        S: 0x7f4a7c15d3b20000n + BigInt(j) * 0x2545f4914f6cdd1dn % (1n << 60n) + 3n });
async function sixteenTags(opts = {}) {
  await core.init();
  const N = 16;
  const chains = await mkChains();
  const tp = new Taxpayer(Array.from({ length: N }, (_, j) => tagOf(j)));
  for (let j = 0; j < N; j++) await tp.register(chains, j);
  let t = 1767300000n;
  await chains[0].noise(2, t);
  await chains[1].noise(2, t);
  const rec = async (slot, ch, fields) => { t += 10n; return tp.record(chains, slot, ch, { ...fields, time: t }); };
  for (let j = 0; j < N; j++) {
    if (j === 7) continue;                                   // tag 7: no record anywhere
    const amt = 1000n + 100n * BigInt(j);
    await rec(j, j % 2, { op: OP.CLAIM, assetOut: USDC, amountOut: amt, value: amt });
  }
  for (let j = 0; j < N; j += 2) {
    await rec(j, 1 - (j % 2), { op: OP.SWAP, assetIn: USDC, amountIn: 300n, assetOut: ETH, amountOut: 1n, value: 300n + BigInt(j) });
  }
  const pOpen = await rec(3, 1, { op: OP.PLEDGE, assetIn: ETH, amountIn: 1n, assetOut: DAI, amountOut: 150n, value: 150n });
  const pLiq = await rec(11, 0, { op: OP.PLEDGE, assetIn: ETH, amountIn: 2n, value: 640n });
  for (const j of [5, 9, 13]) {
    await rec(j, j % 2, { op: OP.SWAP, assetIn: ETH, amountIn: 1n, assetOut: USDC, amountOut: 330n, value: 330n });
  }
  t += 10n;
  await chains[0].recordPassive({ positionId: pLiq.positionId, kind: PKIND.LIQUIDATION,
    assetA: ETH, amountA: 2n, assetB: USDC, amountB: 500n, value: 500n, time: t });
  const snaps = await snapAll(chains);
  const f = await buildFiling({ tags: tp.tags, NT: N, D, snaps, records: tp.records, prev: null,
                                y: 2026n, strict: opts.strict, hooks: opts.hooks, noPad: opts.noPad });
  return {
    name: "sixteen-tags", NT: N, D, snaps, tp, pOpen,
    filings: [{
      label: "2026 sixteen tags on two chains (28 records, 1 liquidation, 1 still open)", f,
      check: () => {
        assertEq(f.counts.records, 28, "records"); assertEq(f.counts.pslEntries, 1, "PSL entries");
        assertEq(f.counts.stillOpen, 1, "still open");
        const c = f.closingState.counters;
        assertEq(c[7][0] + c[7][1], 0n, "tag 7 has no record");
        assertEq(c[0][0], 1n, "tag 0 chain 0"); assertEq(c[0][1], 1n, "tag 0 chain 1");
        assertEq(c[5][1], 2n, "tag 5 chain 1"); assertEq(c[11][0], 1n, "tag 11 chain 0 (pledge)");
      },
    }],
  };
}

module.exports = { worked, twoTags, synthetic, tagAdded, sixteenTags, describeClosing, NT, D,
                   ALICE, ALICE2, USDC, ETH, DAI, WBTC, LINK, UNI };
