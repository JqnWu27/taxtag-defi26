// The worked example with a liquidation (SPEC.md sections 5 and 8.2).
//
//   records 1..4, snapshot 2026, TX1, TX2 as in the worked example
//   then ETH falls from 3000 to 2200: a liquidator covers the 2000 USDC debt
//   and seizes the pledged 1 ETH. The venue's call writes a PSL entry
//   (kind 1) at the position id. No taxpayer proof, no nullifier, no RCL leaf.
//   ETH recovers to 3600 and TX3 sells the other ETH. Snapshot 2027.
//
// Usage: node harness/run_liquidation.js    (writes fixtures/liquidation.json)
const { run, actOne, tx1, tx2, tx3, gasSummary, World } = require("./lib/scenario");
const { writeFixture } = require("./lib/fixture");

run("liquidation run", async (rep) => {
  const w = await World.create({});
  const { alice, bob } = await actOne(w);
  await (await w.usdc.mint(w.addr.liquidator, 50000)).wait();
  await w.approveAll("liquidator");

  await tx1(w, alice);
  const { positionId } = await tx2(w, alice);
  rep.ok("position is healthy at 3000 USD per ETH",
    !(await w.lending.isLiquidatable(positionId)));
  await w.expectRevert("liquidating a healthy position", w.lending, "liquidate",
    [positionId, await w.pslPath(positionId)], "position is healthy", w.signers.liquidator);

  // ---- the crash and the liquidation ----
  await w.setEthPrice(22);
  rep.ok("position is liquidatable at 2200 USD per ETH",
    await w.lending.isLiquidatable(positionId));
  const digestBefore = await w.stateDigest();
  const leaves = w.m.rcl.leaves.length, nfs = w.m.nfLog.length;
  const aliceBefore = await w.balances("alice");
  await w.warp("2027-04-10T03:00:00Z");
  const e = await w.liquidate("liquidator", positionId,
    { asset_a: 2, amount_a: 100, asset_b: 1, amount_b: 2000, value: 2000 },
    "liquidation of Alice's position by a third party");
  rep.ok("liquidation wrote one PSL entry, kind 1, at the position id",
    e.kind === 1n && e.position_id === positionId);
  rep.ok("entry: 1 ETH (100 units) seized, 2000 USDC debt covered, value 2000",
    e.asset_a === 2n && e.amount_a === 100n && e.asset_b === 1n &&
    e.amount_b === 2000n && e.value === 2000n);
  rep.ok("no taxpayer proof involved: no RCL leaf, no nullifier",
    w.m.rcl.leaves.length === leaves && w.m.nfLog.length === nfs &&
    BigInt(await w.agency.nextLeafIndex()) === BigInt(leaves));
  rep.ok("the PSL root changed and equals the mirror",
    digestBefore !== (await w.stateDigest()) && (await w.agency.rootPSL()) === w.m.psl.root());
  const aliceAfter = await w.balances("alice");
  rep.ok("Alice sent nothing and keeps the borrowed 2000 USDC",
    aliceAfter.usdc === aliceBefore.usdc && aliceAfter.eth === aliceBefore.eth && aliceAfter.usdc === 2000n);
  const pos = await w.agency.positions(positionId);
  rep.ok("the agency contract marks the position closed", pos[1] === true);
  await w.expectRevert("second liquidation of the same position", w.lending, "liquidate",
    [positionId, [[], 0, 0, true]], "position is healthy", w.signers.liquidator);
  await w.expectRevert("withdrawal of a liquidated position", w.lending, "withdraw",
    [positionId, [[], 0, 0, true]], "not your open position", w.signers.alice);

  // ---- recovery and TX3 ----
  const r7 = await tx3(w, alice);
  rep.ok("TX3 lands after the liquidation as record 7", r7.i === 7n);

  await w.warp("2027-12-31T23:58:00Z");
  await w.insertNullifiers(undefined, "insertNullifiers, year 2027");
  const snap = await w.pinSnapshot(2027, "pinSnapshot 2027");
  rep.ok("snapshot 2027 pins a non-empty PSL root", snap.root_psl !== 0n && snap.psl_count === 1);

  const { file, fixture } = writeFixture("liquidation", {
    scenario: "Worked example with a liquidation between TX2 and TX3: PSL entry kind 1 at Alice's position.",
    worlds: [w],
    taxpayers: [
      { name: "alice", role: "alice", tags: [alice] },
      { name: "bob", role: "bob", tags: [bob], expected: false },
    ],
    notes: [
      "ETH amounts are in units of 0.01 ETH. Feed: 30, then 22 at the liquidation, then 36 at TX3.",
      "The PSL entry's merge key lies between record 6 and record 7.",
    ],
  });
  const f = fixture.expected[0].filings[1];
  rep.ok("reference rule, 2027: D = (11600, 12000, -400)",
    f.D.proceeds === "11600" && f.D.cost === "12000" && f.D.income === "-400",
    `D = (${f.D.proceeds}, ${f.D.cost}, ${f.D.income})`);
  rep.ok("reference rule: merged order is record 5, record 6, PSL entry, record 7",
    f.merged_sequence.map((s) => s.type).join(",") === "record,record,passive,record");
  rep.ok("reference rule, closing state: ETH 0, USDC (5600, 1), counter 7, no open position",
    f.closing_state.assets["2"].q === "0" && f.closing_state.assets["1"].q === "5600" &&
    f.closing_state.counters["alice@1337"] === 7 && f.closing_state.open.length === 0);
  console.log(`fixture written: ${file}`);
  console.log("\ngas used per transaction:\n" + gasSummary(w));
});
