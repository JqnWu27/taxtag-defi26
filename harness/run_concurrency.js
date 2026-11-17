// Concurrency test (SPEC.md sections 1.4 and 8.4): recordings whose proofs
// were built against the SAME roots must BOTH land, because a proof may cite
// any earlier RCL / AT root and freshness is checked against used[nf].
//
//   C0  two first records (i = 1) of different taxpayers, same roots
//   C1  two later records (i > 1, predecessor check on) of different
//       taxpayers, same roots, submitted one after the other
//   C2  two records of two different tags of the same owner, same roots
//   C3  two records built against the same roots mined in ONE block
//       (idx 0 and idx 1)
//   C4  a proof submitted after three other records landed (old root)
//   C5  a record and a PSL entry mined in ONE block: record() and
//       recordPassive() share one per-block idx counter (both orders)
//
// Usage: node harness/run_concurrency.js    (writes fixtures/concurrency.json)
const { run, tagOf, gasSummary, World, OP } = require("./lib/scenario");
const { writeFixture } = require("./lib/fixture");

run("concurrency test", async (rep) => {
  const w = await World.create({});
  const alice = tagOf(w, "alice"), alice2 = tagOf(w, "alice2"), bob = tagOf(w, "bob");
  await w.warp("2027-01-10T09:00:00Z");
  for (const t of [alice, alice2, bob]) await w.issueTag(t);
  for (const r of ["alice", "bob"]) {
    await w.approveAll(r);
    await (await w.usdc.mint(w.addr[r], 100000)).wait();
  }
  const A = w.addr.alice, B = w.addr.bob;
  const swapExp = (usdc) => ({ op: OP.SWAP, asset_in: 1, amount_in: usdc, asset_out: 2,
                               amount_out: usdc / 30, value: usdc, position_id: 0 });
  const poolSwap = (pool, role, usdc, pr) =>
    pool.connect(w.signers[role]).swap(w.USDC, usdc, 0, w.addr[role], pr.rec);

  // ---- C0: two first records against the same (empty) RCL root ----
  let pa = await w.buildRec(alice, A);
  let pb = await w.buildRec(bob, B);
  rep.ok("C0 both proofs cite the same RCL, AT and TRL roots",
    pa.rootRCL === pb.rootRCL && pa.rootAT === pb.rootAT &&
    pa.input.root_trl === pb.input.root_trl && pa.rootRCL === w.m.rcl.root(0));
  await w.warp("2027-02-01T10:00:00Z");
  let rc = await w.tx("C0 Alice record 1", poolSwap(w.poolA, "alice", 300, pa));
  await w.absorbRecord(rc, alice, pa, swapExp(300), "C0 Alice record 1");
  rc = await w.tx("C0 Bob record 1", poolSwap(w.poolB, "bob", 600, pb));
  await w.absorbRecord(rc, bob, pb, swapExp(600), "C0 Bob record 1 (cites the root before Alice's record)");
  rep.ok("C0 both first records landed", w.ledgerOf(alice).length === 1 && w.ledgerOf(bob).length === 1);

  // ---- C1: two later records of different taxpayers, same roots ----
  const R1 = w.m.rcl.root();
  pa = await w.buildRec(alice, A);         // i = 2, predecessor leaf 0
  pb = await w.buildRec(bob, B);           // i = 2, predecessor leaf 1
  rep.ok("C1 both proofs (i = 2) cite the same roots", pa.rootRCL === R1 && pb.rootRCL === R1 &&
    pa.rootAT === pb.rootAT && pa.input.root_trl === pb.input.root_trl);
  rc = await w.tx("C1 Alice record 2", poolSwap(w.poolA, "alice", 900, pa));
  await w.absorbRecord(rc, alice, pa, swapExp(900), "C1 Alice record 2");
  rep.ok("C1 the RCL root moved after the first of the two", w.m.rcl.root() !== R1);
  rc = await w.tx("C1 Bob record 2", poolSwap(w.poolB, "bob", 1200, pb));
  await w.absorbRecord(rc, bob, pb, swapExp(1200), "C1 Bob record 2 (its cited root is no longer current)");
  rep.ok("C1 BOTH recordings built against the same roots landed",
    w.ledgerOf(alice).length === 2 && w.ledgerOf(bob).length === 2);

  // ---- C2: two tags of the same owner, same roots ----
  let p2 = await w.buildRec(alice2, A);    // first record of the second tag
  rc = await w.tx("C2 Alice tag 2 record 1", poolSwap(w.poolA, "alice", 300, p2));
  await w.absorbRecord(rc, alice2, p2, swapExp(300), "C2 Alice tag 2 record 1");
  const R2 = w.m.rcl.root();
  pa = await w.buildRec(alice, A);         // tag 1, i = 3
  p2 = await w.buildRec(alice2, A);        // tag 2, i = 2
  rep.ok("C2 proofs of two different tags cite the same roots, same owner address",
    pa.rootRCL === R2 && p2.rootRCL === R2 && pa.input.owner === p2.input.owner && pa.nf !== p2.nf);
  rc = await w.tx("C2 Alice tag 1 record 3", poolSwap(w.poolA, "alice", 1500, pa));
  await w.absorbRecord(rc, alice, pa, swapExp(1500), "C2 Alice tag 1 record 3");
  rc = await w.tx("C2 Alice tag 2 record 2", poolSwap(w.poolB, "alice", 1800, p2));
  await w.absorbRecord(rc, alice2, p2, swapExp(1800), "C2 Alice tag 2 record 2");
  rep.ok("C2 BOTH records of different tags landed",
    w.ledgerOf(alice).length === 3 && w.ledgerOf(alice2).length === 2);

  // ---- C3: same roots, same block ----
  const R3 = w.m.rcl.root();
  pa = await w.buildRec(alice, A);         // i = 4
  pb = await w.buildRec(bob, B);           // i = 3
  await w.warp("2027-03-01T10:00:00Z");
  const rcpts = await w.sameBlock([
    { role: "alice", contract: w.poolA, method: "swap", args: [w.USDC, 2100, 0, A, pa.rec] },
    { role: "bob", contract: w.poolB, method: "swap", args: [w.USDC, 2400, 0, B, pb.rec] },
  ]);
  rep.ok("C3 both transactions succeeded in ONE block",
    rcpts.length === 2 && rcpts.every((r) => r.status === 1) &&
    rcpts[0].blockNumber === rcpts[1].blockNumber, `block ${rcpts[0].blockNumber}`);
  const byFrom = (r) => (r.from.toLowerCase() === A.toLowerCase()
    ? [alice, pa, 2100, "Alice record 4"] : [bob, pb, 2400, "Bob record 3"]);
  const recs = [];
  for (let k = 0; k < 2; k++) {
    const [t, pr, usdc, name] = byFrom(rcpts[k]);
    recs.push(await w.absorbRecord(rcpts[k], t, pr, { ...swapExp(usdc), idx: k },
      `C3 ${name} (same block, idx ${k})`, { partial: k === 0 }));
  }
  rep.ok("C3 the two leaves carry idx 0 and idx 1 of the same block, same timestamp",
    recs[0].idx === 0n && recs[1].idx === 1n && recs[0].block === recs[1].block &&
    recs[0].time === recs[1].time && pa.rootRCL === R3 && pb.rootRCL === R3);

  // ---- C4: a proof submitted after three other records landed ----
  const old = await w.buildRec(alice, A);  // i = 5, built now
  const R4 = old.rootRCL;
  for (let k = 0; k < 3; k++) {
    const p = await w.buildRec(bob, B);
    rc = await w.tx(`C4 Bob record ${4 + k}`, poolSwap(w.poolB, "bob", 300, p));
    await w.absorbRecord(rc, bob, p, swapExp(300), `C4 Bob record ${4 + k}`);
  }
  rep.ok("C4 the cited root is three appends old but still a known root",
    w.m.rcl.root() !== R4 && (await w.agency.knownRCL(R4)));
  rc = await w.tx("C4 Alice record 5 (old proof)", poolSwap(w.poolA, "alice", 3000, old));
  await w.absorbRecord(rc, alice, old, swapExp(3000), "C4 Alice record 5 (proof three appends old)");
  rep.ok("C4 the old proof landed", w.ledgerOf(alice).length === 5);

  // ---- C5: a record and a PSL entry in ONE block share the idx counter ----
  // The filing side's merge key (time, cid, block, idx) relies on idx being
  // unique per block over records AND PSL entries of one agency contract.
  // The order inside a block is the miner's choice (ganache puts Alice's
  // transaction first), so the two roles are swapped in the second block to
  // see both orders.
  const pl1 = await w.pledge(bob, "bob", w.ETH, 20, null, 0, "C5 Bob pledges 0.2 ETH (position for the test)");
  const pl2 = await w.pledge(alice, "alice", w.ETH, 10, null, 0, "C5 Alice pledges 0.1 ETH (position for the test)");
  const mixedBlock = async (recRole, recTag, pool, pasRole, pos, coll) => {
    const who = w.addr[recRole];
    const pr = await w.buildRec(recTag, who);
    const rs = await w.sameBlock([
      { role: recRole, contract: pool, method: "swap", args: [w.USDC, 300, 0, who, pr.rec] },
      { role: pasRole, contract: w.lending, method: "withdraw", args: [pos, await w.pslPath(pos)] },
    ]);
    if (rs.length !== 2 || rs.some((r) => r.status !== 1) || rs[0].blockNumber !== rs[1].blockNumber) {
      throw new Error("C5: the two transactions did not land in one block");
    }
    const out = { order: [] };
    for (let k = 0; k < 2; k++) {
      if (rs[k].from.toLowerCase() === who.toLowerCase()) {
        out.rec = await w.absorbRecord(rs[k], recTag, pr, { ...swapExp(300), idx: k },
          `C5 record in a mixed block (idx ${k})`, { partial: k === 0 });
        out.order.push("record");
      } else {
        out.pas = await w.absorbPassive(rs[k], { position_id: pos, kind: 2, asset_a: 2, amount_a: coll,
          asset_b: 0, amount_b: 0, value: 0, idx: k }, `C5 PSL entry in a mixed block (idx ${k})`,
          { partial: k === 0 });
        out.order.push("PSL entry");
      }
    }
    return out;
  };
  const mb1 = await mixedBlock("alice", alice, w.poolA, "bob", pl1.positionId, 20);
  const mb2 = await mixedBlock("bob", bob, w.poolB, "alice", pl2.positionId, 10);
  for (const [n, mb] of [["first", mb1], ["second", mb2]]) {
    rep.ok(`C5 ${n} mixed block: record and PSL entry share the block and get idx 0 and 1 from ONE counter`,
      mb.rec.block === mb.pas.block && mb.rec.time === mb.pas.time &&
      mb.rec.idx !== mb.pas.idx && mb.rec.idx + mb.pas.idx === 1n,
      `block ${mb.rec.block}: ${mb.order[0]} idx 0, ${mb.order[1]} idx 1`);
  }
  rep.ok("C5 both orders occurred (record first, PSL entry first)",
    mb1.order[0] !== mb2.order[0], `${mb1.order.join(" then ")}; ${mb2.order.join(" then ")}`);

  await w.warp("2027-12-31T23:58:00Z");
  await w.insertNullifiers(5, "insertNullifiers, first batch of 5");
  await w.insertNullifiers(undefined, "insertNullifiers, second batch (the rest)");
  await w.pinSnapshot(2027, "pinSnapshot 2027");
  rep.ok("UNL built in two batches covers the whole log and matches the mirror",
    w.m.unlCovered === w.m.nfLog.length);

  const { file } = writeFixture("concurrency", {
    scenario: "Three ledgers (alice, alice2 with the same owner address, bob) whose records were proven against shared roots; two records share one block (idx 0 and 1); two blocks hold one record and one PSL entry each.",
    worlds: [w],
    taxpayers: [
      { name: "alice", role: "alice", tags: [alice, alice2] },
      { name: "bob", role: "bob", tags: [bob] },
    ],
    notes: [
      "Every record is a swap of USDC for ETH at 30 USD per unit, paid from holdings that were never recorded, so the reference rule sees disposals of USDC beyond the recorded quantity (cost 0 for the missing part).",
      "Alice's two tags form one filing: a two-tag, one-chain merge with a same-block pair in it.",
    ],
  });
  console.log(`fixture written: ${file}`);
  console.log("\ngas used per transaction:\n" + gasSummary(w));
});
