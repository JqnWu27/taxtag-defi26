// Shared pieces of the scenario scripts: a small pass/fail reporter and the
// common first act of the paper's worked example (issuance, the previous
// year's four records, the first snapshot) and its three transactions.
const { World, assertEq, OP } = require("./world");

// ---- pass/fail reporter -----------------------------------------------------
class Report {
  constructor(title) { this.title = title; this.pass = 0; this.fail = 0; this.lines = []; }
  ok(name, cond, detail = "") {
    if (cond) { this.pass++; console.log(`PASS  ${name}${detail ? "  -- " + detail : ""}`); }
    else { this.fail++; console.log(`FAIL  ${name}${detail ? "  -- " + detail : ""}`); }
    this.lines.push([cond ? "PASS" : "FAIL", name]);
    return cond;
  }
  eq(name, a, b) { return this.ok(name, BigInt(a) === BigInt(b), `${a}${BigInt(a) === BigInt(b) ? "" : " != " + b}`); }
  // fn must throw; pattern (optional) must match the message
  async throws(name, fn, pattern) {
    try { await fn(); }
    catch (e) {
      const msg = String(e && e.message ? e.message : e).split("\n")[0].slice(0, 160);
      return this.ok(name, !pattern || pattern.test(String(e.message)), `throws: ${msg}`);
    }
    return this.ok(name, false, "did not throw");
  }
  finish() {
    console.log(`\n== ${this.title}: ${this.pass} passed, ${this.fail} failed ==`);
    return this.fail === 0;
  }
}

async function run(title, body) {
  const rep = new Report(title);
  console.log(`\n==== ${title} ====`);
  try {
    await body(rep);
  } catch (e) {
    console.error(e);
    rep.ok("scenario ran to the end", false, String(e.message).split("\n")[0]);
  }
  const good = rep.finish();
  process.exit(good ? 0 : 1);
}

// ---- test secrets (never real ones) -------------------------------------------
const SECRETS = {
  alice:  { tag: 7311111111111111n, S: 9244444444444444n, ta: 5 },
  alice2: { tag: 7322222222222222n, S: 9255555555555555n, ta: 5 },
  bob:    { tag: 5522222222222222n, S: 8833333333333333n, ta: 11 },
  carol:  { tag: 4433333333333333n, S: 6611111111111111n, ta: 0 },
  dave:   { tag: 3344444444444444n, S: 5577777777777777n, ta: 15 },
};
const tagOf = (w, name) => w.makeTag(name, SECRETS[name].tag, SECRETS[name].S, SECRETS[name].ta);

// ---- act one: issuance and the previous year --------------------------------
// TA writes: an unrelated anchor, an unrelated revocation, Alice's and Bob's
// anchors. Alice's records 1..4 are four reward claims of 1500 USDC, so her
// previous filing closes with 6000 USDC at average cost 1 and counter 4.
// Bob's two records are interleaved, so Alice's leaves are not contiguous.
// Ends with the UNL batch and the snapshot of period 2026.
async function actOne(w) {
  const H = w.H;
  const alice = tagOf(w, "alice");
  const bob = tagOf(w, "bob");

  await w.warp("2026-01-10T09:00:00Z");
  await w.writeAnchorRaw(H.atIndex(5555n), H.anchor(6666n));        // another taxpayer
  await w.revoke(H.atIndex(999999n));                               // an unrelated revoked tag
  await w.issueTag(alice);
  await w.issueTag(bob);
  await w.approveAll("alice");
  await w.approveAll("bob");
  await (await w.usdc.mint(w.addr.bob, 100000)).wait();             // Bob's unrecorded holdings
  await (await w.eth.mint(w.addr.bob, 1000)).wait();
  await (await w.lending.setClaimable(w.addr.alice, 6000)).wait();

  await w.warp("2026-03-02T10:00:00Z");
  await w.claim(alice, "alice", 1500, "Alice record 1: claim 1500 USDC");
  await w.warp("2026-05-11T15:30:00Z");
  await w.swapDirect(bob, "bob", w.poolA, w.USDC, 3000,
    { asset_in: 1, amount_in: 3000, asset_out: 2, amount_out: 100, value: 3000 },
    "Bob record 1: swap 3000 USDC for 1 ETH, pool A direct");
  await w.warp("2026-06-01T08:00:00Z");
  await w.claim(alice, "alice", 1500, "Alice record 2: claim 1500 USDC");
  await w.warp("2026-09-01T08:00:00Z");
  await w.claim(alice, "alice", 1500, "Alice record 3: claim 1500 USDC");
  await w.warp("2026-10-20T19:45:00Z");
  await w.swapWrapped(bob, "bob", w.ETH, 50,
    { asset_in: 2, amount_in: 50, asset_out: 1, amount_out: 1500, value: 1500 },
    "Bob record 2: swap 0.5 ETH for 1500 USDC through the wrapper");
  await w.warp("2026-12-01T08:00:00Z");
  await w.claim(alice, "alice", 1500, "Alice record 4: claim 1500 USDC");

  await w.warp("2026-12-31T23:58:00Z");
  await w.insertNullifiers(undefined, "insertNullifiers, year 2026");
  const snap = await w.pinSnapshot(2026, "pinSnapshot 2026");
  return { alice, bob, snap2026: snap };
}

// ---- the three transactions of the worked example ----------------------------
async function tx1(w, alice) {       // record 5: buy 2 ETH for 6000 USDC, pool called directly
  await w.warp("2027-02-01T10:00:00Z");
  return w.swapDirect(alice, "alice", w.poolA, w.USDC, 6000,
    { asset_in: 1, amount_in: 6000, asset_out: 2, amount_out: 200, value: 6000 },
    "TX1 record 5: swap 6000 USDC for 2 ETH, pool A direct");
}
async function tx2(w, alice) {       // record 6: pledge 1 ETH, loan 2000 USDC, ONE pledge record
  await w.warp("2027-03-15T14:00:00Z");
  return w.pledge(alice, "alice", w.ETH, 100, w.USDC, 2000,
    "TX2 record 6: pledge 1 ETH with a loan of 2000 USDC");
}
async function tx3(w, alice, iso = "2027-06-20T11:00:00Z") {
  // record 7: sell 1 ETH for 3600 USDC through the aggregator over two pools
  await w.setEthPrice(36);
  await w.warp(iso);
  return w.swapSplit(alice, "alice", w.ETH, w.USDC,
    [[w.contracts.poolA, 60], [w.contracts.poolB, 40]],
    { asset_in: 2, amount_in: 100, asset_out: 1, amount_out: 3600, value: 3600 },
    "TX3 record 7: swap 1 ETH for 3600 USDC, aggregator over pools A and B");
}

// gas lines of a world, grouped for the result tables
function gasSummary(w) {
  return w.gas.map((g) => `${String(g.gas).padStart(9)}  ${g.label}`).join("\n");
}

module.exports = { Report, run, SECRETS, tagOf, actOne, tx1, tx2, tx3, gasSummary,
                   World, assertEq, OP };
