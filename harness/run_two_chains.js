// Two tags on two chains, interleaved by time (input for SPEC.md section
// 8.3; the filing itself is the filing side's work). Two in-process chains
// with chain ids 1337 and 1338, each with its own agency contract (at the
// same address, so only the chain id separates the nullifiers).
//
// Alice holds tags "alice" (T1) and "alice2" (T2). Ledgers:
//   (T1, 1337) 4 records   (T1, 1338) 1 record
//   (T2, 1337) 0 records   (T2, 1338) 3 records
// One pair of records has the SAME timestamp on the two chains, so the merge
// order is decided by the chain id.
//
// Usage: node harness/run_two_chains.js     (writes fixtures/two_chains.json)
const { run, tagOf, World, OP } = require("./lib/scenario");
const { writeFixture } = require("./lib/fixture");

run("two tags on two chains", async (rep) => {
  const w0 = await World.create({ chainId: 1337, ethPrice: 30 });
  const w1 = await World.create({ chainId: 1338, ethPrice: 45 });
  rep.ok("both chains run their own agency contract at the same address",
    w0.acaddr === w1.acaddr && w0.cid !== w1.cid, `${w0.acaddrHex}, chain ids ${w0.cid} and ${w1.cid}`);
  const t1 = tagOf(w0, "alice"), t2 = tagOf(w0, "alice2"), bob = tagOf(w1, "bob");
  const A = w0.addr.alice;

  // the TA writes each anchor into each covered chain's anchor table
  for (const w of [w0, w1]) {
    await w.warp("2027-01-10T09:00:00Z");
    await w.issueTag(t1);
    await w.issueTag(t2);
    await w.approveAll("alice");
    await (await w.lending.setClaimable(A, 3000)).wait();
  }
  rep.ok("the two anchor tables hold the same entries and have the same root",
    w0.m.at.root() === w1.m.at.root());
  rep.ok("NF_1 of the same tag differs between the chains (chain id is in the nullifier)",
    w0.H.nullifier(t1.idTax, w0.cid, w0.acaddr, 1n) !== w1.H.nullifier(t1.idTax, w1.cid, w1.acaddr, 1n));

  // cross-chain replay: a first-record proof made for chain 1337 sent to chain 1338.
  // Roots, contract address and owner are all equal; only cid differs.
  const foreign = await w0.buildRec(t2, A);
  rep.ok("a proof made for chain 1337 is rejected on chain 1338",
    !!(await w1.expectRevert("cross-chain replay", w1.lending, "claimReward",
      [3000, foreign.rec], "invalid proof", w1.signers.alice)));
  await w1.issueTag(bob);                    // only on chain 1338, after the check above
  await w1.approveAll("bob");
  await (await w1.usdc.mint(w1.addr.bob, 10000)).wait();

  await w0.warp("2027-02-01T10:00:00Z");
  await w0.claim(t1, "alice", 3000, "chain 1337, T1 record 1: claim 3000 USDC");
  await w1.warp("2027-02-03T10:00:00Z");
  await w1.claim(t2, "alice", 3000, "chain 1338, T2 record 1: claim 3000 USDC");
  await w0.warp("2027-03-01T10:00:00Z");
  await w0.swapDirect(t1, "alice", w0.poolA, w0.USDC, 2400,
    { asset_in: 1, amount_in: 2400, asset_out: 2, amount_out: 80, value: 2400 },
    "chain 1337, T1 record 2: swap 2400 USDC for 0.8 ETH");
  await w1.warp("2027-03-05T10:00:00Z");
  await w1.swapDirect(t2, "alice", w1.poolA, w1.USDC, 1800,
    { asset_in: 1, amount_in: 1800, asset_out: 2, amount_out: 40, value: 1800 },
    "chain 1338, T2 record 2: swap 1800 USDC for 0.4 ETH");
  await w1.warp("2027-03-20T10:00:00Z");
  await w1.swapDirect(bob, "bob", w1.poolB, w1.USDC, 450,
    { asset_in: 1, amount_in: 450, asset_out: 2, amount_out: 10, value: 450 },
    "chain 1338, Bob record 1 (unrelated)");
  await w1.warp("2027-04-01T10:00:00Z");
  await w1.swapSplit(t1, "alice", w1.ETH, w1.USDC,
    [[w1.contracts.poolA, 25], [w1.contracts.poolB, 15]],
    { asset_in: 2, amount_in: 40, asset_out: 1, amount_out: 1800, value: 1800 },
    "chain 1338, T1 record 1: swap 0.4 ETH for 1800 USDC, aggregator");
  await w0.warp("2027-05-01T10:00:00Z");
  const { positionId } = await w0.pledge(t1, "alice", w0.ETH, 50, null, 0,
    "chain 1337, T1 record 3: pledge 0.5 ETH, no loan");

  // the same timestamp on both chains
  await w0.warp("2027-06-01T00:00:00Z");
  await w1.warp("2027-06-01T00:00:00Z");
  const ra = await w0.swapDirect(t1, "alice", w0.poolB, w0.ETH, 30,
    { asset_in: 2, amount_in: 30, asset_out: 1, amount_out: 900, value: 900 },
    "chain 1337, T1 record 4: swap 0.3 ETH for 900 USDC");
  const rb = await w1.swapDirect(t2, "alice", w1.poolA, w1.USDC, 2250,
    { asset_in: 1, amount_in: 2250, asset_out: 2, amount_out: 50, value: 2250 },
    "chain 1338, T2 record 3: swap 2250 USDC for 0.5 ETH");
  rep.ok("two records on different chains carry the same timestamp", ra.time === rb.time, `time ${ra.time}`);

  for (const w of [w0, w1]) {
    await w.warp("2027-12-31T23:58:00Z");
    await w.insertNullifiers(undefined, `insertNullifiers, chain ${w.cid}`);
    await w.pinSnapshot(2027, `pinSnapshot 2027, chain ${w.cid}`);
  }
  rep.ok("ledger lengths: (T1,1337) 4, (T1,1338) 1, (T2,1337) 0, (T2,1338) 3",
    w0.ledgerOf(t1).length === 4 && w1.ledgerOf(t1).length === 1 &&
    w0.ledgerOf(t2).length === 0 && w1.ledgerOf(t2).length === 3);
  const b0 = await w0.balances("alice"), b1 = await w1.balances("alice");
  rep.ok("balances: chain 1337 USDC 1500, ETH 0 (0.5 pledged); chain 1338 USDC 750, ETH 50 units",
    b0.usdc === 1500n && b0.eth === 0n && b1.usdc === 750n && b1.eth === 50n);

  const { file, fixture } = writeFixture("two_chains", {
    scenario: "Two tags of one taxpayer on two chains (1337, 1338), records interleaved by time, one pair with equal timestamps, one zero-length ledger, one open position.",
    worlds: [w0, w1],
    taxpayers: [
      { name: "alice", role: "alice", tags: [t1, t2] },
      { name: "bob", role: "bob", tags: [bob], expected: false },
    ],
    notes: [
      "ETH amounts are in units of 0.01 ETH. The ETH feed quotes 30 USD per unit on chain 1337 and 45 on chain 1338.",
      "Both agency contracts sit at the same address; only cid separates the nullifiers of one tag on the two chains.",
      "Records (1337, T1, 4) and (1338, T2, 3) have the same time; the merge key (time, cid, block, idx) puts chain 1337 first. In the other order the average cost of ETH would not be 40.",
      "(T2, 1337) is a zero-length ledger: T2 is anchored on chain 1337 and NF_1 is unused there.",
    ],
  });
  const f = fixture.expected[0].filings[0];
  rep.ok("reference rule: D = (9150, 8900, 6250), rewards part 6000",
    f.D.proceeds === "9150" && f.D.cost === "8900" && f.D.income === "6250" &&
    f.income_parts.rewards === "6000", `D = (${f.D.proceeds}, ${f.D.cost}, ${f.D.income})`);
  rep.ok("reference rule, closing state: ETH (100 units, 40), USDC (2250, 1), one open position",
    f.closing_state.assets["2"].q === "100" && f.closing_state.assets["2"].avg === "40" &&
    f.closing_state.assets["1"].q === "2250" && f.closing_state.assets["1"].avg === "1" &&
    f.closing_state.open.join() === `1337:${positionId}` && f.integer_average_exact === true);
  rep.ok("reference rule: 8 records merged, the equal-time pair ordered by chain id",
    f.merged_sequence.length === 8 &&
    f.merged_sequence[6].cid === "1337" && f.merged_sequence[7].cid === "1338" &&
    f.merged_sequence[6].time === f.merged_sequence[7].time);
  console.log(`fixture written: ${file}`);
});
