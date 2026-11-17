// Reference evaluation of the moving-average rule program (SPEC.md
// section 6) in plain JavaScript integers. It is NOT part of the protocol
// and not the filing circuit; the recording harness uses it only to put an
// "expected" block into the fixtures, so the filing side has an independent
// number to compare with.
//
// Conventions taken here (the filing side has its own, filing/lib/rules.js):
//   - one asset leaf (q, avg) per asset id over all chains and tags
//   - buy:      avg' = floor((q*avg + cost) / (q + q_in)),  q' = q + q_in
//               (integer average; `exact` says whether any division
//               left a remainder, i.e. whether a rounding convention matters)
//   - dispose:  cost += min(q, amount) * avg,  q' = max(q - amount, 0)
//   - income = proceeds - cost + rewards + interest
//   - merge key (time, cid, block, idx), strictly increasing
const { OP, KIND } = require("./hashes");

const cmpKey = (a, b) => {
  for (const k of ["time", "cid", "block", "idx"]) {
    if (a[k] < b[k]) return -1;
    if (a[k] > b[k]) return 1;
  }
  return 0;
};

function emptyState() {
  return { assets: {}, counters: {}, open: [] };
}

// state:   { assets: {id: {q, avg}}, counters: {"tag@cid": n}, open: ["cid:pid"] }
// records: leaf-field objects with .tag and .i   (the period's records of the demanded tags)
// passive: PSL entry objects                      (the period's entries, all positions)
// Returns { D, closing, sequence, exact }.
function evaluate(start, records, passive) {
  const st = JSON.parse(JSON.stringify(start, (k, v) => (typeof v === "bigint" ? v.toString() : v)));
  const assets = {};
  for (const [id, a] of Object.entries(st.assets)) assets[id] = { q: BigInt(a.q), avg: BigInt(a.avg) };
  const counters = { ...st.counters };
  const open = new Set(st.open);
  let proceeds = 0n, cost = 0n, rewards = 0n, interest = 0n;
  let exact = true;

  const leafOf = (id) => (assets[id] ??= { q: 0n, avg: 0n });
  const buy = (id, qIn, c) => {
    const a = leafOf(id);
    const num = a.q * a.avg + c;
    const den = a.q + qIn;
    if (den === 0n) return;
    if (num % den !== 0n) exact = false;
    a.avg = num / den;
    a.q = den;
  };
  const dispose = (id, qOut) => {
    const a = leafOf(id);
    const covered = qOut < a.q ? qOut : a.q;
    a.q -= covered;
    return covered * a.avg;
  };

  // only PSL entries of positions that are open (carried or pledged in this
  // period) belong to this taxpayer; pledges are known from the records
  const mine = new Set(open);
  for (const r of records) if (r.op === OP.PLEDGE) mine.add(`${r.cid}:${r.position_id}`);
  const seq = [
    ...records.map((r) => ({ type: "record", ...r })),
    ...passive.filter((e) => mine.has(`${e.cid}:${e.position_id}`))
              .map((e) => ({ type: "passive", ...e })),
  ].sort(cmpKey);
  for (let k = 1; k < seq.length; k++) {
    if (cmpKey(seq[k - 1], seq[k]) >= 0) throw new Error("merge key not strictly increasing");
  }

  for (const e of seq) {
    if (e.type === "record") {
      const ck = `${e.tag}@${e.cid}`;
      const n = BigInt(counters[ck] ?? 0);
      if (BigInt(e.i) !== n + 1n) throw new Error(`counter gap on ${ck}: have ${n}, got ${e.i}`);
      counters[ck] = Number(e.i);
      switch (e.op) {
        case OP.SWAP:
          proceeds += e.value;
          cost += dispose(e.asset_in, e.amount_in);
          buy(e.asset_out, e.amount_out, e.value);
          break;
        case OP.PLEDGE:
          open.add(`${e.cid}:${e.position_id}`);
          if (e.amount_out !== 0n) buy(e.asset_out, e.amount_out, e.value);   // loan of the same call
          break;
        case OP.BORROW:
          buy(e.asset_out, e.amount_out, e.value);
          break;
        case OP.REPAY:
          dispose(e.asset_in, e.amount_in);        // removed at its average cost, no totals
          break;
        case OP.CLAIM:
          buy(e.asset_out, e.amount_out, e.value);
          rewards += e.value;
          break;
        default: throw new Error("unknown op " + e.op);
      }
    } else {
      const pk = `${e.cid}:${e.position_id}`;
      if (!open.has(pk)) throw new Error("PSL entry before its pledge: " + pk);
      open.delete(pk);
      if (e.kind === KIND.LIQUIDATION) {
        proceeds += e.value;
        cost += dispose(e.asset_a, e.amount_a);
      } else if (e.kind === KIND.WITHDRAWAL) {
        if (e.amount_b !== 0n) buy(e.asset_b, e.amount_b, e.value);
        interest += e.value;
      } else throw new Error("unknown kind " + e.kind);
    }
  }
  const income = proceeds - cost + rewards + interest;
  return {
    D: { proceeds, cost, income },
    parts: { rewards, interest },
    closing: { assets, counters, open: [...open].sort() },
    sequence: seq.map((e) => (e.type === "record"
      ? { type: "record", time: e.time, cid: e.cid, block: e.block, idx: e.idx, tag: e.tag, i: e.i }
      : { type: "passive", time: e.time, cid: e.cid, block: e.block, idx: e.idx,
          position_id: e.position_id, kind: e.kind })),
    exact,
  };
}

module.exports = { evaluate, emptyState, cmpKey };
