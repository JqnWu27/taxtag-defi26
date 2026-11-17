// "Repay under another tag": can a position WITH debt, pledged under a tag
// that was revoked afterwards, be closed by repaying under another tag of
// the same taxpayer?
//
// One owner address holds two tags, A and B, both issued and anchored, each
// with its own ledger.
//   under tag A   record 1: claim 6000 USDC
//                 record 2: swap 6000 USDC for 2 ETH
//                 record 3: pledge 1 ETH with a loan of 2000 USDC, ONE
//                           pledge record, position P
//   the authority revokes tag A
//   (a) a further record under tag A fails
//   (b) withdrawing P while the loan is outstanding
//   (c) the loan is repaid for position P with a record under tag B, by the
//       same owner address
//   (d) the venue's withdrawal of P writes the PSL entry (recordPassive)
//   (e) insertNullifiers, pinSnapshot
//   (f) the rule reference over BOTH tags
// Nothing in the contracts was changed for this scenario.
//
// Usage: node harness/run_revoked_repay.js  (writes fixtures/revoked_repay.json)
const { run, tagOf, gasSummary, World, OP } = require("./lib/scenario");
const { writeFixture } = require("./lib/fixture");

run("repay under another tag after a revocation", async (rep) => {
  const w = await World.create({});
  const H = w.H;
  const A = tagOf(w, "alice");       // tag A, revoked later
  const B = tagOf(w, "alice2");      // tag B, same owner address
  const bob = tagOf(w, "bob");       // another taxpayer, another address
  const owner = w.addr.alice;
  const sg = w.signers;

  await w.warp("2027-01-10T09:00:00Z");
  await w.writeAnchorRaw(H.atIndex(5555n), H.anchor(6666n));        // another taxpayer
  await w.revoke(H.atIndex(999999n));                               // an unrelated revoked tag
  await w.issueTag(A);
  await w.issueTag(B);
  await w.issueTag(bob);
  await w.approveAll("alice");
  await w.approveAll("bob");
  await (await w.usdc.mint(w.addr.bob, 10000)).wait();
  await (await w.lending.setClaimable(owner, 6000)).wait();
  rep.ok("tags A and B are both anchored and belong to one owner address",
    (await w.agency.anchorAt(A.atKey)) === A.anchor && (await w.agency.anchorAt(B.atKey)) === B.anchor);

  // ---- under tag A: the assets, then the pledge with a loan ----
  await w.warp("2027-02-01T10:00:00Z");
  await w.claim(A, "alice", 6000, "tag A record 1: claim 6000 USDC");
  await w.warp("2027-02-10T10:00:00Z");
  await w.swapDirect(A, "alice", w.poolA, w.USDC, 6000,
    { asset_in: 1, amount_in: 6000, asset_out: 2, amount_out: 200, value: 6000 },
    "tag A record 2: swap 6000 USDC for 2 ETH");
  await w.warp("2027-03-15T14:00:00Z");
  const { rec: pledgeRec, positionId: P } = await w.pledge(A, "alice", w.ETH, 100, w.USDC, 2000,
    "tag A record 3: pledge 1 ETH with a loan of 2000 USDC");
  rep.ok("the pledge is ONE record under tag A carrying the loan and position P",
    pledgeRec.i === 3n && pledgeRec.op === OP.PLEDGE && pledgeRec.amount_out === 2000n &&
    pledgeRec.position_id === P, `P = ${P}`);
  const posBefore = await w.agency.positions(P);
  rep.ok("the agency contract binds position P to the venue that pledged it, not to a tag",
    posBefore[0].toLowerCase() === w.contracts.lending.toLowerCase() && posBefore[1] === false);

  // ---- the authority revokes tag A ----
  const inflight = await w.buildRec(A, owner);          // record 4 of tag A, proven before the revocation
  const oldEx = await w.m.trl.exclusion(A.atKey);
  await w.warp("2027-04-01T09:00:00Z");
  await w.revoke(A.atKey, "revokeTag (tag A)");

  // ---- (a) a further record under tag A fails ----
  console.log("\n-- (a) a further record under tag A");
  rep.ok("(a) a tag A proof made before the revocation is rejected",
    !!(await w.expectRevert("(a) tag A, proof in flight", w.poolA, "swap",
      [w.ETH, 10, 0, owner, inflight.rec], "invalid proof", sg.alice)));
  await rep.throws("(a) no non-membership path exists for tag A in the TRL",
    () => w.makeInput(A, owner), /already present/);
  await rep.throws("(a) the old non-membership path against the current TRL root: no witness",
    async () => w.prove(await w.makeInput(A, owner, { trl: { root: w.m.trl.root(), ex: oldEx } })),
    /Assert Failed/);
  // a repay for P under tag A itself is a record under tag A, so it fails the same way
  rep.ok("(a) repaying the loan under tag A (proof in flight) is rejected too",
    !!(await w.expectRevert("(a) repay under tag A", w.lending, "repay",
      [P, 2000, inflight.rec], "invalid proof", sg.alice)));

  // ---- (b) withdrawing P while the loan is outstanding ----
  console.log("\n-- (b) withdrawing P with the loan outstanding");
  rep.ok("(b) the lending venue refuses the withdrawal while the loan is outstanding",
    !!(await w.expectRevert("(b) withdraw with debt", w.lending, "withdraw",
      [P, await w.pslPath(P)], "repay the loan first", sg.alice)));

  // another address cannot repay: the demo venue only lets the position's owner repay
  rep.ok("(b') another address is refused by the venue's owner check (venue policy, not the agency contract)",
    !!(await w.expectRevert("(b') repay by another address", w.lending, "repay",
      [P, 2000, [0n, new Array(8).fill(0n), 0n, 0n]], "not your open position", sg.bob)));

  // ---- (c) repay for position P, recorded under tag B, same owner address ----
  console.log("\n-- (c) repay under tag B");
  const digest = await w.stateDigest();
  const usdcBefore = (await w.balances("alice")).usdc;
  await w.warp("2027-05-01T10:00:00Z");
  let repayRec = null, blocked = null;
  try {
    repayRec = await w.repay(B, "alice", P, w.USDC, 2000,
      "tag B record 1: repay 2000 USDC for position P (pledged under tag A)");
  } catch (e) {
    blocked = String(e.reason ?? e.shortMessage ?? e.message).split("\n")[0];
  }
  rep.ok("(c) the repay recorded under tag B for position P SUCCEEDS",
    repayRec !== null, blocked ? `blocked: ${blocked}` : "accepted by the lending venue and the agency contract");
  if (repayRec === null) throw new Error(`repay under tag B was blocked: ${blocked}`);
  rep.ok("(c) it is record 1 of tag B: op 4, 2000 USDC in, nothing out, value 2000, position P",
    repayRec.i === 1n && repayRec.tag === "alice2" && repayRec.op === OP.REPAY &&
    repayRec.asset_in === 1n && repayRec.amount_in === 2000n && repayRec.asset_out === 0n &&
    repayRec.amount_out === 0n && repayRec.value === 2000n && repayRec.position_id === P);
  rep.ok("(c) the leaf holds tag B's nullifier NF_1, tag A's ledger did not grow",
    repayRec.nf === H.nullifier(B.idTax, w.cid, w.acaddr, 1n) &&
    w.ledgerOf(A).length === 3 && w.ledgerOf(B).length === 1);
  rep.ok("(c) agency state changed and 2000 USDC left the owner",
    digest !== (await w.stateDigest()) && (await w.balances("alice")).usdc === usdcBefore - 2000n);
  const lp = await w.lending.positions(P);
  rep.ok("(c) the venue shows no debt left on P", lp[4] === 0n && lp[6] === true, `debt ${lp[4]}`);

  // ---- (d) the withdrawal writes the PSL entry ----
  console.log("\n-- (d) withdrawal of P");
  const leaves = w.m.rcl.leaves.length, nfs = w.m.nfLog.length;
  const ethBefore = (await w.balances("alice")).eth;
  await w.warp("2027-05-02T10:00:00Z");
  const e = await w.withdraw("alice", P,
    { asset_a: 2, amount_a: 100, asset_b: 0, amount_b: 0, value: 0 },
    "withdrawal of position P (no taxpayer proof)");
  rep.ok("(d) the withdrawal wrote one PSL entry, kind 2, at position P, through recordPassive",
    e.kind === 2n && e.position_id === P && e.asset_a === 2n && e.amount_a === 100n && e.value === 0n);
  rep.ok("(d) no proof, no RCL leaf, no nullifier; 1 ETH came back",
    w.m.rcl.leaves.length === leaves && w.m.nfLog.length === nfs &&
    (await w.balances("alice")).eth === ethBefore + 100n);
  const posAfter = await w.agency.positions(P);
  rep.ok("(d) the agency contract marks P closed", posAfter[1] === true);

  // ---- (e) UNL batch and snapshot ----
  console.log("\n-- (e) insertNullifiers, pinSnapshot");
  await w.warp("2027-12-31T23:58:00Z");
  await w.insertNullifiers(undefined, "insertNullifiers, year 2027");
  const snap = await w.pinSnapshot(2027, "pinSnapshot 2027");
  rep.ok("(e) the UNL covers the log and the four roots are pinned",
    w.m.unlCovered === w.m.nfLog.length && snap.leaf_count === 4 && snap.psl_count === 1,
    `${snap.leaf_count} leaves, ${snap.nf_count} nullifiers, ${snap.psl_count} PSL entry`);
  const ra = await w.rebuildLedger(A), rb = await w.rebuildLedger(B);
  rep.ok("(e) both ledgers rebuilt from events and (tag, S) alone: tag A 3 records, tag B 1 record",
    ra.length === 3 && rb.length === 1 && rb[0].leaf === repayRec.leaf);

  // ---- (f) rule reference over BOTH tags ----
  console.log("\n-- (f) rule reference over both tags");
  const { file, fixture } = writeFixture("revoked_repay", {
    scenario: "One owner, two tags. Tag A: claim, swap, pledge with a loan (position P). Tag A is revoked. The loan is repaid with a record under tag B, then P is withdrawn (PSL entry kind 2).",
    worlds: [w],
    taxpayers: [
      { name: "alice", role: "alice", tags: [A, B] },
      { name: "bob", role: "bob", tags: [bob], expected: false },
    ],
    notes: [
      "ETH amounts are in units of 0.01 ETH, feed 30 USD per unit.",
      "Tag A (name alice) is revoked: trl.leaves holds its index. Filing checks no revocation, so its three records must still open.",
      "The repay record of position P is record 1 of tag B (name alice2); the pledge of P is record 3 of tag A. A filing has to cover both tags to see the pledge, the repay and the PSL entry together.",
      "Bob has a tag and no record (a zero-length ledger of another taxpayer).",
    ],
  });
  const f = fixture.expected[0].filings[0];
  rep.ok("(f) D = (6000, 6000, 6000): the swap's proceeds and cost, the claimed 6000 as income",
    f.D.proceeds === "6000" && f.D.cost === "6000" && f.D.income === "6000" &&
    f.income_parts.rewards === "6000" && f.income_parts.interest === "0",
    `D = (${f.D.proceeds}, ${f.D.cost}, ${f.D.income})`);
  rep.ok("(f) closing state: ETH (200 units, 30) = 2 ETH at 3000, USDC 0, NO open position",
    f.closing_state.assets["2"].q === "200" && f.closing_state.assets["2"].avg === "30" &&
    f.closing_state.assets["1"].q === "0" && f.closing_state.open.length === 0 &&
    f.integer_average_exact === true);
  rep.ok("(f) counters: tag A 3, tag B 1; merged order: A1, A2, A3, B1, PSL entry",
    f.closing_state.counters["alice@1337"] === 3 && f.closing_state.counters["alice2@1337"] === 1 &&
    f.merged_sequence.map((s) => (s.type === "record" ? `${s.tag}#${s.i}` : "psl")).join(",") ===
      "alice#1,alice#2,alice#3,alice2#1,psl");
  const bal = await w.balances("alice");
  rep.ok("(f) the owner's balances agree with the closing state: 200 ETH units, 0 USDC",
    bal.eth === 200n && bal.usdc === 0n, `ETH ${bal.eth}, USDC ${bal.usdc}`);
  console.log(`fixture written: ${file}`);
  console.log("\ngas used per transaction:\n" + gasSummary(w));
});
