// The paper's worked example (Section 4, SPEC.md section 8.1), recording
// side, end to end: real Groth16 proofs against live contract state on an
// in-process EVM, every root checked against the JavaScript mirrors.
//
//   start   Alice's counter is 4 (records 1..4: four claims of 1500 USDC),
//           snapshot 2026 pinned
//   TX1     record 5: swap 6000 USDC for 2 ETH (value 6000), pool called directly
//   TX2     record 6: pledge 1 ETH with a loan of 2000 USDC, ONE pledge record
//   TX3     record 7: swap 1 ETH for 3600 USDC, aggregator over two pools, ONE record
//   close   insertNullifiers, pinSnapshot 2027
//
// Usage: node harness/run_example.js        (writes fixtures/example.json)
const { run, actOne, tx1, tx2, tx3, gasSummary, World, OP } = require("./lib/scenario");
const { writeFixture } = require("./lib/fixture");

run("worked example (recording side)", async (rep) => {
  const w = await World.create({});
  console.log(`agency contract ${w.acaddrHex}, chain id ${w.cid}`);
  const { alice, bob } = await actOne(w);
  rep.eq("start: Alice's counter is 4", w.ledgerOf(alice).length, 4);
  let bal = await w.balances("alice");
  rep.eq("start: Alice holds 6000 USDC", bal.usdc, 6000);

  // ---- TX1 ----
  const leavesBefore = w.m.rcl.leaves.length;
  const r5 = await tx1(w, alice);
  bal = await w.balances("alice");
  rep.ok("TX1 recorded as record 5 by the pool itself (direct call)",
    r5.i === 5n && r5.op === OP.SWAP && w.m.rcl.leaves.length === leavesBefore + 1);
  rep.ok("TX1 leaf: 6000 USDC in, 2 ETH (200 units) out, value 6000",
    r5.amount_in === 6000n && r5.amount_out === 200n && r5.value === 6000n);
  rep.ok("TX1 balances: USDC 0, ETH 200 units", bal.usdc === 0n && bal.eth === 200n);

  // an unrelated record lands in between
  await w.warp("2027-02-20T09:00:00Z");
  await w.swapDirect(bob, "bob", w.poolB, w.ETH, 100,
    { asset_in: 2, amount_in: 100, asset_out: 1, amount_out: 3000, value: 3000 },
    "Bob record 3: swap 1 ETH for 3000 USDC, pool B direct");

  // ---- TX2 ----
  const { rec: r6, positionId } = await tx2(w, alice);
  bal = await w.balances("alice");
  rep.ok("TX2 is ONE pledge record carrying the loan and the position id",
    r6.i === 6n && r6.op === OP.PLEDGE && r6.asset_in === 2n && r6.amount_in === 100n &&
    r6.asset_out === 1n && r6.amount_out === 2000n && r6.position_id === positionId,
    `position id ${positionId}`);
  rep.eq("TX2 value = oracle value of the loan", r6.value, 2000);
  rep.ok("TX2 balances: USDC 2000, ETH 100 units", bal.usdc === 2000n && bal.eth === 100n);

  // ---- TX3 ----
  const before3 = w.m.rcl.leaves.length;
  const r7 = await tx3(w, alice);
  bal = await w.balances("alice");
  rep.ok("TX3 through the aggregator over two pools is ONE record (the pools record nothing)",
    w.m.rcl.leaves.length === before3 + 1 && r7.i === 7n);
  rep.ok("TX3 leaf carries the net amounts: 1 ETH (100 units) in, 3600 USDC out, value 3600",
    r7.asset_in === 2n && r7.amount_in === 100n && r7.asset_out === 1n &&
    r7.amount_out === 3600n && r7.value === 3600n);
  rep.ok("TX3 balances: USDC 5600, ETH 0 (1 ETH still pledged)", bal.usdc === 5600n && bal.eth === 0n);

  // ---- close the year ----
  await w.warp("2027-12-31T23:58:00Z");
  rep.ok("pinSnapshot is refused while the UNL batches lag the log",
    !!(await w.expectRevert("pinSnapshot before the batch", w.agency, "pinSnapshot",
      [2027], "UNL batches do not cover the log", w.signers.mallory)));
  await w.insertNullifiers(undefined, "insertNullifiers, year 2027");
  const snap = await w.pinSnapshot(2027, "pinSnapshot 2027");
  rep.ok("snapshot 2027 pins RCL, UNL, AT and PSL roots equal to the mirror", !!snap);
  rep.eq("PSL leaf of the pledge position is still empty (position open)",
    (await w.m.psl.has(positionId)) ? 1 : 0, 0);

  // ---- the ledger can be rebuilt from chain events and (tag, S) alone ----
  const rebuilt = await w.rebuildLedger(alice);
  const local = w.ledgerOf(alice);
  rep.ok("Alice's ledger rebuilt from events and (tag, S) alone equals the local ledger",
    rebuilt.length === 7 && rebuilt.every((r, k) =>
      r.leaf_index === local[k].leaf_index && r.leaf === local[k].leaf));
  rep.eq("counter after the year", local.length, 7);

  // ---- fixture ----
  const { file, fixture } = writeFixture("example", {
    scenario: "Paper worked example: records 1..4 in 2026 (snapshot 2026), TX1..TX3 in 2027 (snapshot 2027). Bob's records are unrelated and interleaved.",
    worlds: [w],
    taxpayers: [
      { name: "alice", role: "alice", tags: [alice] },
      { name: "bob", role: "bob", tags: [bob], expected: false },
    ],
    notes: [
      "ETH amounts are in units of 0.01 ETH: 2 ETH = 200, 1 ETH = 100; the ETH feed quotes 30 then 36 USD per unit (3000 then 3600 USD per ETH).",
      "Alice's filing for 2027 starts from the closing state of 2026: USDC (6000, 1), counter 4.",
    ],
  });
  const f = fixture.expected[0].filings;
  rep.ok("reference rule, 2026 closing state: USDC (6000, 1), counter 4, no open position",
    f[0].closing_state.assets["1"].q === "6000" && f[0].closing_state.assets["1"].avg === "1" &&
    f[0].closing_state.counters["alice@1337"] === 4 && f[0].closing_state.open.length === 0);
  rep.ok("reference rule, 2027: D = (9600, 9000, 600)",
    f[1].D.proceeds === "9600" && f[1].D.cost === "9000" && f[1].D.income === "600",
    `D = (${f[1].D.proceeds}, ${f[1].D.cost}, ${f[1].D.income})`);
  rep.ok("reference rule, 2027 closing state: ETH (100 units, 30) = 1 ETH at 3000, USDC (5600, 1), counter 7, one open position",
    f[1].closing_state.assets["2"].q === "100" && f[1].closing_state.assets["2"].avg === "30" &&
    f[1].closing_state.assets["1"].q === "5600" && f[1].closing_state.assets["1"].avg === "1" &&
    f[1].closing_state.counters["alice@1337"] === 7 && f[1].closing_state.open.length === 1);
  console.log(`fixture written: ${file}`);
  console.log(`\nproving times (ms, in-process fullProve incl. witness): ${w.proveMs.join(" ")}`);
  console.log("\ngas used per transaction:\n" + gasSummary(w));
});
