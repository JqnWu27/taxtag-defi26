// The worked example with a withdrawal with interest (SPEC.md sections 5
// and 8.2). It also exercises borrow (op 3), repay (op 4) and a partial
// withdrawal, which writes nothing.
//
//   records 1..4, snapshot 2026, TX1, TX2, TX3 as in the worked example
//   record 8   borrow 400 USDC more on the same position
//   record 9   repay 2400 USDC
//   partial withdrawal of 0.4 ETH: nothing is written anywhere
//   the venue credits 0.2 ETH interest
//   full withdrawal: 0.6 ETH collateral returned + 0.2 ETH interest, PSL
//   entry kind 2, value = oracle value of the interest (20 units * 36 = 720)
//
// Usage: node harness/run_withdrawal.js     (writes fixtures/withdrawal.json)
const { run, actOne, tx1, tx2, tx3, gasSummary, World, OP } = require("./lib/scenario");
const { writeFixture } = require("./lib/fixture");

run("withdrawal with interest run", async (rep) => {
  const w = await World.create({});
  const { alice, bob } = await actOne(w);
  await tx1(w, alice);
  const { positionId } = await tx2(w, alice);
  await tx3(w, alice);

  await w.warp("2027-07-05T12:00:00Z");
  const r8 = await w.borrow(alice, "alice", positionId, w.USDC, 400,
    "record 8: borrow 400 USDC on the open position");
  rep.ok("borrow is record 8, op 3: nothing in, 400 USDC out, value 400, position id kept",
    r8.i === 8n && r8.op === OP.BORROW && r8.asset_in === 0n && r8.amount_in === 0n &&
    r8.asset_out === 1n && r8.amount_out === 400n && r8.value === 400n && r8.position_id === positionId);

  await w.warp("2027-09-01T12:00:00Z");
  const r9 = await w.repay(alice, "alice", positionId, w.USDC, 2400,
    "record 9: repay 2400 USDC");
  rep.ok("repay is record 9, op 4: 2400 USDC in, nothing out, value 2400",
    r9.i === 9n && r9.op === OP.REPAY && r9.asset_in === 1n && r9.amount_in === 2400n &&
    r9.asset_out === 0n && r9.amount_out === 0n && r9.value === 2400n);

  // ---- partial withdrawal: writes nothing ----
  const digest = await w.stateDigest();
  await w.warp("2027-09-10T12:00:00Z");
  const rc = await w.tx("partial withdrawal [tx: lending.withdrawPartial, nothing recorded]",
    w.lending.connect(w.signers.alice).withdrawPartial(positionId, 40));
  rep.ok("partial withdrawal emits no agency event and changes no agency state",
    rc.logs.every((l) => l.address.toLowerCase() !== w.acaddrHex.toLowerCase()) &&
    digest === (await w.stateDigest()));
  rep.eq("partial withdrawal returned 0.4 ETH", (await w.balances("alice")).eth, 40);

  // ---- interest and the closing withdrawal ----
  await (await w.lending.creditInterest(positionId, 20)).wait();
  const leaves = w.m.rcl.leaves.length, nfs = w.m.nfLog.length;
  await w.warp("2027-10-01T12:00:00Z");
  const e = await w.withdraw("alice", positionId,
    { asset_a: 2, amount_a: 60, asset_b: 2, amount_b: 20, value: 720 },
    "full withdrawal with interest");
  rep.ok("withdrawal wrote one PSL entry, kind 2, at the position id",
    e.kind === 2n && e.position_id === positionId);
  rep.ok("entry: 0.6 ETH collateral returned, 0.2 ETH interest, value 720",
    e.asset_a === 2n && e.amount_a === 60n && e.asset_b === 2n && e.amount_b === 20n && e.value === 720n);
  rep.ok("no taxpayer proof involved: no RCL leaf, no nullifier",
    w.m.rcl.leaves.length === leaves && w.m.nfLog.length === nfs);
  const bal = await w.balances("alice");
  rep.ok("Alice holds 1.2 ETH (120 units) and 3600 USDC", bal.eth === 120n && bal.usdc === 3600n,
    `ETH ${bal.eth}, USDC ${bal.usdc}`);
  await w.expectRevert("second withdrawal of the same position", w.lending, "withdraw",
    [positionId, [[], 0, 0, true]], "not your open position", w.signers.alice);

  await w.warp("2027-12-31T23:58:00Z");
  await w.insertNullifiers(undefined, "insertNullifiers, year 2027");
  await w.pinSnapshot(2027, "pinSnapshot 2027");

  const { file, fixture } = writeFixture("withdrawal", {
    scenario: "Worked example followed by borrow, repay, a partial withdrawal (unrecorded) and a full withdrawal with interest: PSL entry kind 2.",
    worlds: [w],
    taxpayers: [
      { name: "alice", role: "alice", tags: [alice] },
      { name: "bob", role: "bob", tags: [bob], expected: false },
    ],
    notes: [
      "ETH amounts are in units of 0.01 ETH. Interest is 20 units (0.2 ETH) at 36 USD per unit, value 720.",
      "The partial withdrawal of 40 units is not on chain in any agency structure; the entry's amount_a is the 60 units returned at the close.",
    ],
  });
  const f = fixture.expected[0].filings[1];
  rep.ok("reference rule, 2027: D = (9600, 9000, 1320), interest part 720",
    f.D.proceeds === "9600" && f.D.cost === "9000" && f.D.income === "1320" &&
    f.income_parts.interest === "720", `D = (${f.D.proceeds}, ${f.D.cost}, ${f.D.income})`);
  rep.ok("reference rule, closing state: ETH (120 units, 31), USDC (3600, 1), counter 9, no open position",
    f.closing_state.assets["2"].q === "120" && f.closing_state.assets["2"].avg === "31" &&
    f.closing_state.assets["1"].q === "3600" && f.closing_state.assets["1"].avg === "1" &&
    f.closing_state.counters["alice@1337"] === 9 && f.closing_state.open.length === 0 &&
    f.integer_average_exact === true);
  console.log(`fixture written: ${file}`);
  console.log("\ngas used per transaction:\n" + gasSummary(w));
});
