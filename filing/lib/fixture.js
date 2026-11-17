// Opens a ledger written by the RECORDING side (fixtures/*.json, schema
// taxtag-recording-fixture/1, read-only) with the filing prover: the leaves
// the agency contract appended, with real recording proofs, must open in the
// filing step circuit. Every tree is rebuilt here from the listed leaves and
// its root compared with the root the contract pinned.
//
// The filing circuits are sized for two chains. A fixture with one chain gets
// a second covered chain without activity: a locally built chain (cid 1338)
// whose AT holds the taxpayer's anchors and whose RCL, UNL and PSL are empty.
const fs = require("fs");
const path = require("path");
const core = require("./core");
const { fmt, PosTree, Smt, recordLeafOf, pslEntryOf, DR } = core;
const { Chain } = require("./world");
const { buildFiling } = require("./filing");

const FIXTURES = path.join(__dirname, "..", "..", "fixtures");
const B = (x) => BigInt(x);

function eq(a, b, what) {
  if (a !== b) throw new Error(`fixture cross-check failed: ${what}: ${a} != ${b}`);
}

async function snapFromFixture(chain, snap) {
  const rcl = new PosTree(DR, 0n);
  for (let k = 0; k < snap.leaf_count; k++) rcl.append(B(chain.rcl.leaves[k]));
  const unl = await Smt.create();
  for (let k = 0; k < snap.nf_count; k++) await unl.insert(B(chain.nf_log[k]), 1n);
  const at = await Smt.create();
  for (let k = 0; k < snap.at_count; k++) await at.insert(B(chain.at.leaves[k][0]), B(chain.at.leaves[k][1]));
  const psl = await Smt.create();
  const pslEntries = new Map();
  for (let k = 0; k < snap.psl_count; k++) {
    const e = chain.psl.entries[k];
    const mine = {
      positionId: B(e.position_id), kind: B(e.kind), cid: B(e.cid), block: B(e.block), idx: B(e.idx),
      time: B(e.time), assetA: B(e.asset_a), amountA: B(e.amount_a), assetB: B(e.asset_b),
      amountB: B(e.amount_b), value: B(e.value),
    };
    mine.entry = pslEntryOf(mine);
    eq(mine.entry, B(e.pentry), `PSL entry hash of position ${e.position_id}`);
    await psl.insert(mine.positionId, mine.entry);
    pslEntries.set(mine.positionId, mine);
  }
  eq(rcl.root(), B(snap.root_rcl), `RCL root, chain ${chain.cid}, period ${snap.period}`);
  eq(unl.root, B(snap.root_unl), `UNL root, chain ${chain.cid}, period ${snap.period}`);
  eq(at.root, B(snap.root_at), `AT root, chain ${chain.cid}, period ${snap.period}`);
  eq(psl.root, B(snap.root_psl), `PSL root, chain ${chain.cid}, period ${snap.period}`);
  return { cid: B(chain.cid), acaddr: B(chain.acaddr), rcl, unl, at, psl, pslEntries,
           rootRCL: rcl.root(), rootUNL: unl.root, rootAT: at.root, rootPSL: psl.root };
}

// Returns a scenario { name, NT, D, filings: [{ label, f, check }] } for one
// taxpayer of one fixture, one filing per pinned period.
async function scenarioFromFixture(name, taxpayerName = "alice", NT = 2, D = 64) {
  await core.init();
  const fx = JSON.parse(fs.readFileSync(path.join(FIXTURES, `${name}.json`), "utf8"));
  const tp = fx.taxpayers.find((t) => t.name === taxpayerName);
  if (!tp) throw new Error(`no taxpayer ${taxpayerName} in ${name}`);
  const tags = tp.tags.map((g) => {
    const t = { name: g.name, tag: B(g.tag), S: B(g.S) };
    t.idTax = fmt.idTax(t.tag, t.S);
    eq(t.idTax, B(g.id_tax), `id_tax of ${g.name}`);
    return t;
  });

  // own records, with the leaf and the nullifier recomputed from the fields
  const records = [];
  tp.tags.forEach((g, slot) => {
    g.ledgers.forEach((led, ch) => {
      const chain = fx.chains[ch];
      eq(chain.cid, led.cid, "ledger order = chain order");
      for (const ref of led.records) {
        const c = chain.records.find((r) => r.leaf_index === ref.leaf_index);
        const r = {
          nf: B(c.nf), cid: B(c.cid), block: B(c.block), idx: B(c.idx), time: B(c.time), op: B(c.op),
          assetIn: B(c.asset_in), amountIn: B(c.amount_in), assetOut: B(c.asset_out),
          amountOut: B(c.amount_out), value: B(c.value), positionId: B(c.position_id),
          leafIndex: c.leaf_index, slot, ch, i: B(ref.i),
        };
        eq(r.nf, fmt.nullifier(tags[slot].idTax, B(chain.cid), B(chain.acaddr), r.i),
           `nullifier of ${g.name} record ${ref.i}`);
        r.leaf = recordLeafOf(r);
        eq(r.leaf, B(c.leaf), `leaf of ${g.name} record ${ref.i}`);
        eq(r.leaf, B(chain.rcl.leaves[c.leaf_index]), `RCL leaf ${c.leaf_index}`);
        records.push(r);
      }
    });
  });

  // a one-chain fixture gets a second covered chain without activity
  let idle = null;
  if (fx.chains.length === 1) {
    const c1 = await Chain.create({ cid: B(fx.chains[0].cid) + 1n, acaddr: B(fx.chains[0].acaddr) });
    c1.unl = await Smt.create();                       // no sentinel, as the contract
    for (const t of tags) await c1.writeAnchor(t.tag, t.S);
    idle = await c1.snapshot();
  }

  const expected = (fx.expected.find((e) => e.taxpayer === taxpayerName) || { filings: [] }).filings;
  const periods = fx.chains[0].snapshots.map((s) => s.period);
  const out = { name: `fixture-${name}-${taxpayerName}`, NT, D, filings: [] };
  let prev = null;
  for (let k = 0; k < periods.length; k++) {
    const snaps = [];
    for (const chain of fx.chains) {
      const s = chain.snapshots.find((x) => x.period === periods[k]);
      snaps.push(await snapFromFixture(chain, s));
    }
    if (idle) snaps.push(idle);
    const f = await buildFiling({ tags, NT, D, snaps, records, prev, y: B(periods[k]) });
    const exp = expected.find((e) => e.period === periods[k]);
    out.filings.push({
      label: `${name}.json, ${taxpayerName}, period ${periods[k]} (ledger written by the recording side)`,
      f,
      check: () => {
        if (!exp) return;
        eq(f.D.proceeds.toString(), exp.D.proceeds, "D.proceeds vs recording-side reference");
        eq(f.D.cost.toString(), exp.D.cost, "D.cost vs recording-side reference");
        eq(f.D.income.toString(), exp.D.income, "D.income vs recording-side reference");
        const cs = f.closingState;
        for (const [id, a] of Object.entries(exp.closing_state.assets)) {
          const mine = cs.assets.get(B(id)) || { q: 0n, avg: 0n };
          eq(mine.q.toString(), a.q, `closing q of asset ${id}`);
          eq(mine.avg.toString(), a.avg, `closing avg of asset ${id}`);
        }
        for (const [key, n] of Object.entries(exp.closing_state.counters)) {
          const [tname, cid] = key.split("@");
          const slot = tags.findIndex((t) => t.name === tname);
          const ch = snaps.findIndex((s) => s.cid.toString() === cid);
          eq(cs.counters[slot][ch].toString(), String(n), `closing counter ${key}`);
        }
        const mineOpen = [...cs.open.values()].map((v) => `${snaps[v.ch].cid}:${v.positionId}`).sort();
        eq(JSON.stringify(mineOpen), JSON.stringify(exp.closing_state.open.slice().sort()), "open positions");
      },
    });
    prev = f.closingState;
  }
  return out;
}

module.exports = { scenarioFromFixture, FIXTURES };
