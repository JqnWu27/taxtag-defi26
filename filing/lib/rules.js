// Moving-average rule program of SPEC.md section 6, written directly from
// the table as an independent check of the step generator in filing.js (which
// follows the circuit's slot layout) and of the circuit itself.
//
// State per asset: quantity q and integer average cost avg.
//   buy(m, value):  avg' = floor((q*avg + value) / (q + m)), q' = q + m
//                   (a buy of m = 0 units is skipped)
//   dispose(m):     d = min(q, m), q' = q - d, cost of the disposal d * avg,
//                   units beyond the recorded quantity cost 0, avg unchanged
const { OP, PKIND } = require("./core");

function getAsset(assets, id) {
  const a = assets.get(id);
  return a ? a : { q: 0n, avg: 0n };
}

function buy(assets, id, m, value) {
  if (m === 0n) return;
  const a = getAsset(assets, id);
  const q = a.q + m;
  assets.set(id, { q, avg: (a.q * a.avg + value) / q });
}

function dispose(assets, id, m) {
  const a = getAsset(assets, id);
  const d = a.q < m ? a.q : m;
  assets.set(id, { q: a.q - d, avg: a.avg });
  return d * a.avg;
}

// events: [{ type: "rec", r } | { type: "psl", e }], already in merge order
function runRules(startAssets, events) {
  const assets = new Map();
  for (const [k, v] of startAssets) assets.set(k, { q: v.q, avg: v.avg });
  let proceeds = 0n, cost = 0n, other = 0n;
  for (const ev of events) {
    if (ev.type === "rec") {
      const r = ev.r;
      if (r.op === OP.SWAP) {
        cost += dispose(assets, r.assetIn, r.amountIn);
        buy(assets, r.assetOut, r.amountOut, r.value);
        proceeds += r.value;
      } else if (r.op === OP.PLEDGE) {
        buy(assets, r.assetOut, r.amountOut, r.value);   // loan in the same call
      } else if (r.op === OP.BORROW) {
        buy(assets, r.assetOut, r.amountOut, r.value);
      } else if (r.op === OP.REPAY) {
        dispose(assets, r.assetIn, r.amountIn);          // no totals
      } else if (r.op === OP.CLAIM) {
        buy(assets, r.assetOut, r.amountOut, r.value);
        other += r.value;
      } else {
        throw new Error("unknown op " + r.op);
      }
    } else if (ev.type === "psl") {
      const e = ev.e;
      if (e.kind === PKIND.LIQUIDATION) {
        cost += dispose(assets, e.assetA, e.amountA);
        proceeds += e.value;
      } else if (e.kind === PKIND.WITHDRAWAL) {
        buy(assets, e.assetB, e.amountB, e.value);
        other += e.value;
      } else {
        throw new Error("unknown PSL kind " + e.kind);
      }
    }
  }
  return { assets, proceeds, cost, other, income: proceeds - cost + other };
}

module.exports = { runRules, buy, dispose, getAsset };
