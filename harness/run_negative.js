// Negative tests of the recording side (SPEC.md section 8.5 and the
// paper's attack traces). Every "must revert" case is checked twice: the
// revert reason on a static call, then the transaction is really sent and
// must be mined as failed without changing any agency state. Every "cannot
// be proven" case must make the witness generator fail.
//
//   N1  reused nullifier (replay, fork at the same counter, ledger restart)
//   N2  skipped counter (no witness against a real root; a forged tree
//       proves but its root is unknown), start in the middle, counter 0
//   N3  wrong owner address
//   N4  revoked tag cannot record (also not with a forged non-boolean
//       exclusion flag), its position can still be withdrawn
//   N5  stale TRL root rejected
//   N6  unknown RCL root, unknown AT root, forged credential
//   N7  direct call to a covered pool records or reverts
//   N8  direct call that bypasses the wrapper succeeds unrecorded (the limit)
//   N9  access control and write-once rules of the agency contract
//   N10 non-canonical SMT inputs on chain (old key + p, flag not 0/1)
//
// Usage: node harness/run_negative.js       (writes fixtures/revoked.json)
const { ethers } = require("ethers");
const { run, tagOf, World, OP } = require("./lib/scenario");
const { Smt, Rcl } = require("./lib/trees");
const { writeFixture } = require("./lib/fixture");

run("negative tests", async (rep) => {
  const w = await World.create({});
  const H = w.H;
  const alice = tagOf(w, "alice"), bob = tagOf(w, "bob");
  const carol = tagOf(w, "carol"), dave = tagOf(w, "dave");
  await w.warp("2027-01-10T09:00:00Z");
  await w.writeAnchorRaw(H.atIndex(5555n), H.anchor(6666n));
  await w.revoke(H.atIndex(999999n));
  for (const t of [alice, bob, carol]) await w.issueTag(t);   // Dave holds a signed tag that is never anchored
  for (const r of ["alice", "bob", "carol", "dave", "mallory"]) {
    await w.approveAll(r);
    await (await w.usdc.mint(w.addr[r], 100000)).wait();
    await (await w.eth.mint(w.addr[r], 1000)).wait();
  }
  const A = w.addr.alice, B = w.addr.bob, C = w.addr.carol, D = w.addr.dave, M = w.addr.mallory;
  const sg = w.signers;
  const zeros8 = new Array(8).fill(0n);
  const swapExp = (usdc) => ({ op: OP.SWAP, asset_in: 1, amount_in: usdc, asset_out: 2,
                               amount_out: usdc / 30, value: usdc, position_id: 0 });
  const poolArgs = (to, usdc, rec) => [w.USDC, usdc, 0, to, rec];
  const mustFailWitness = (name, inputPromise) =>
    rep.throws(name, async () => w.prove(await inputPromise), /Assert Failed|Error in template/);

  // honest start: Alice records 1 and 2
  await w.warp("2027-02-01T10:00:00Z");
  await w.swapDirect(alice, "alice", w.poolA, w.USDC, 300, swapExp(300), "Alice record 1");
  const pr2 = await w.buildRec(alice, A);
  let rc = await w.tx("Alice record 2", w.poolA.connect(sg.alice).swap(...poolArgs(A, 600, pr2.rec)));
  await w.absorbRecord(rc, alice, pr2, swapExp(600), "Alice record 2");

  // ---------------------------------------------------------------- N1
  console.log("\n-- N1 reused nullifier");
  rep.ok("N1a replay of an accepted proof reverts",
    !!(await w.expectRevert("N1a replay", w.poolA, "swap", poolArgs(A, 600, pr2.rec),
      "nullifier used", sg.alice)));
  // the same nullifier written as NF + p: another mapping key, same field element
  const P_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  rep.ok("N1a' replay with the nullifier written as NF + p reverts (verifier rejects non-canonical inputs)",
    !!(await w.expectRevert("N1a' replay, NF + p", w.poolA, "swap",
      poolArgs(A, 600, [pr2.nf + P_FIELD, pr2.words, pr2.rootRCL, pr2.rootAT]),
      "invalid proof", sg.alice)));
  const fork = await w.buildRec(alice, A, { i: 2 });       // a second record 2
  rep.ok("N1b fork: a fresh, valid proof for counter 2 exists off chain", await w.verifyOffchain(fork));
  rep.ok("N1b fork at counter 2 reverts on chain",
    !!(await w.expectRevert("N1b fork", w.poolB, "swap", poolArgs(A, 900, fork.rec),
      "nullifier used", sg.alice)));
  const restart = await w.buildRec(alice, A, { i: 1 });    // ATK3, ledger restart
  rep.ok("N1c restart: a fresh, valid proof for counter 1 exists off chain", await w.verifyOffchain(restart));
  rep.ok("N1c ledger restart (NF_1 again) reverts on chain",
    !!(await w.expectRevert("N1c restart", w.poolA, "swap", poolArgs(A, 300, restart.rec),
      "nullifier used", sg.alice)));

  // ---------------------------------------------------------------- N2
  console.log("\n-- N2 skipped counter");
  const led = w.ledgerOf(alice);
  await mustFailWitness("N2a counter 4 with record 2 as predecessor (record 3 does not exist): no witness",
    w.makeInput(alice, A, { i: 4, prev: led[1] }));
  // forged tree: the real leaves plus a fabricated leaf holding NF_3
  const fake = new Rcl(H, 32);
  for (const l of w.m.rcl.leaves) fake.append(l);
  const ff = { nf: H.nullifier(alice.idTax, w.cid, w.acaddr, 3n), cid: w.cid, block: 999n,
               idx: 0n, time: 1800000000n, op: 1n, asset_in: 1n, amount_in: 1n,
               asset_out: 2n, amount_out: 1n, value: 1n, position_id: 0n };
  const fh = H.recordLeaf(ff);
  const fidx = fake.append(fh.leaf);
  const forged = await w.buildRec(alice, A, {
    i: 4, prev: { block: ff.block, idx: ff.idx, body: fh.body, tail: fh.tail, leaf_index: fidx },
    prevPath: fake.path(fidx).siblings, rootRCL: fake.root(),
  });
  rep.ok("N2b forged RCL with a fabricated record 3: the proof verifies off chain",
    await w.verifyOffchain(forged));
  rep.ok("N2b ... and the contract rejects it, its root was never an RCL root",
    !!(await w.expectRevert("N2b forged tree", w.poolA, "swap", poolArgs(A, 300, forged.rec),
      "unknown RCL root", sg.alice)));
  await mustFailWitness("N2c start in the middle: Bob (no record) proves counter 2 on Alice's leaf: no witness",
    w.makeInput(bob, B, { i: 2, prev: led[0] }));
  await mustFailWitness("N2d counter 0: no witness", w.makeInput(alice, A, { i: 0 }));
  await mustFailWitness("N2e predecessor path under a root that does not contain it: no witness",
    w.makeInput(alice, A, { i: 3, rootRCL: w.m.rcl.root(1) }));
  await mustFailWitness("N2f counter 3 opened on record 1 instead of record 2: no witness",
    w.makeInput(alice, A, { i: 3, prev: led[0] }));

  // ---------------------------------------------------------------- N3
  console.log("\n-- N3 wrong owner address");
  const pr3 = await w.buildRec(alice, A);                  // record 3, bound to Alice's address
  rep.ok("N3a Mallory submits Alice's proof: the pool reports Mallory as owner, proof rejected",
    !!(await w.expectRevert("N3a wrong owner", w.poolA, "swap", poolArgs(M, 900, pr3.rec),
      "invalid proof", sg.mallory)));
  rc = await w.tx("Alice record 3 (the same proof, sent by its owner)",
    w.poolA.connect(sg.alice).swap(...poolArgs(A, 900, pr3.rec)));
  await w.absorbRecord(rc, alice, pr3, swapExp(900), "Alice record 3");
  rep.ok("N3b the same proof lands when its owner sends it (control)", led.length === 3);

  // ---------------------------------------------------------------- N6 (first-record cases, before Bob records)
  console.log("\n-- N6 unknown roots, forged credential");
  const anyRoot = await w.buildRec(bob, B, { rootRCL: 123456789n });   // i = 1: root_rcl unconstrained
  rep.ok("N6a first record citing an arbitrary RCL root: the proof verifies off chain",
    await w.verifyOffchain(anyRoot));
  rep.ok("N6a ... and the contract rejects the unknown RCL root",
    !!(await w.expectRevert("N6a unknown RCL root", w.poolA, "swap", poolArgs(B, 300, anyRoot.rec),
      "unknown RCL root", sg.bob)));
  // Dave: valid credential, anchor never written. He proves against his own tree.
  const fakeAt = await Smt.create(w.F);
  for (const [k, v] of w.m.at.leaves) await fakeAt.insert(k, v);
  await fakeAt.insert(dave.atKey, dave.anchor);
  const unanch = await w.buildRec(dave, D, {
    at: { root: fakeAt.root(), siblings: (await fakeAt.inclusion(dave.atKey)).siblings } });
  rep.ok("N6b unanchored tag proving against a self-made anchor table: the proof verifies off chain",
    await w.verifyOffchain(unanch));
  rep.ok("N6b ... and the contract rejects the unknown AT root",
    !!(await w.expectRevert("N6b unknown AT root", w.poolA, "swap", poolArgs(D, 300, unanch.rec),
      "unknown AT root", sg.dave)));
  await rep.throws("N6c unanchored tag against the real anchor table: no opening exists",
    () => w.makeInput(dave, D), /key not in tree/);
  // leaked (tag, S) without the TA signature: signed by a key outside the recognized set
  const s2 = w.c.eddsa.signPoseidon(Buffer.from("ab".repeat(32), "hex"), w.F.e(H.credMsg(alice.tag)));
  const noCred = { ...alice, sig: { R8x: w.F.toObject(s2.R8[0]), R8y: w.F.toObject(s2.R8[1]), S: s2.S } };
  await mustFailWitness("N6d tag and S without a recognized TA signature: no witness",
    w.makeInput(noCred, A));

  // ---------------------------------------------------------------- N5
  console.log("\n-- N5 stale TRL root");
  const stale = await w.buildRec(bob, B);                  // built against the current TRL root
  await w.revoke(H.atIndex(888888n), "revokeTag (an unrelated tag)");
  rep.ok("N5a a proof built before an unrelated revocation is rejected (TRL root must be current)",
    !!(await w.expectRevert("N5a stale TRL root", w.poolA, "swap", poolArgs(B, 300, stale.rec),
      "invalid proof", sg.bob)));
  await w.swapDirect(bob, "bob", w.poolA, w.USDC, 300, swapExp(300), "Bob record 1 (re-proven)");
  rep.ok("N5b re-proven against the current TRL root it lands", w.ledgerOf(bob).length === 1);

  // ---------------------------------------------------------------- N4
  console.log("\n-- N4 revoked tag");
  const { positionId: carolPos } = await w.pledge(carol, "carol", w.ETH, 50, null, 0,
    "Carol record 1: pledge 0.5 ETH, no loan");
  const inflight = await w.buildRec(carol, C);             // record 2, built before the revocation
  const oldEx = await w.m.trl.exclusion(carol.atKey);
  await w.revoke(carol.atKey, "revokeTag (Carol)");
  rep.ok("N4a Carol's proof in flight is rejected after her tag is revoked",
    !!(await w.expectRevert("N4a revoked, proof in flight", w.poolA, "swap",
      poolArgs(C, 300, inflight.rec), "invalid proof", sg.carol)));
  await rep.throws("N4b no non-membership path exists for a revoked tag in the mirrored TRL",
    () => w.makeInput(carol, C), /already present/);
  await mustFailWitness("N4c old non-membership path against the current TRL root: no witness",
    w.makeInput(carol, C, { trl: { root: w.m.trl.root(), ex: oldEx } }));
  const inc = await w.m.trl.inclusion(carol.atKey);
  await mustFailWitness("N4d the revocation leaf itself passed off as the neighbouring leaf: no witness",
    w.makeInput(carol, C, { trl: { root: w.m.trl.root(),
      ex: { siblings: inc.siblings, oldKey: carol.atKey, oldValue: 1n, isOld0: false } } }));
  // the isOld0 gap: a non-boolean flag that scales an arbitrary "old leaf"
  // into Carol's revocation leaf (see harness/test_isold0.js)
  {
    const fake = H.smtLeaf(123456789n, 1n), real = H.smtLeaf(carol.atKey, 1n);
    const x = w.F.toObject(w.F.sub(w.F.one, w.F.div(w.F.e(real), w.F.e(fake))));
    await rep.throws("N4g forged NON-BOOLEAN exclusion flag for the revoked tag: no witness (flag constrained in the circuit)",
      async () => w.prove(await w.makeInput(carol, C, { trl: { root: w.m.trl.root(),
        ex: { siblings: inc.siblings, oldKey: 123456789n, oldValue: 1n, isOld0: x } } })),
      /Assert Failed\. Error in template CRec_\d+ line/);
  }
  const ethBefore = (await w.balances("carol")).eth;
  const ce = await w.withdraw("carol", carolPos,
    { asset_a: 2, amount_a: 50, asset_b: 0, amount_b: 0, value: 0 },
    "Carol (revoked) withdraws her position");
  rep.ok("N4e the revoked tag's position is withdrawn through recordPassive, no proof needed",
    ce.kind === 2n && (await w.balances("carol")).eth === ethBefore + 50n);
  await w.swapDirect(alice, "alice", w.poolA, w.USDC, 300, swapExp(300), "Alice record 4 (after the revocations)");
  rep.ok("N4f other tags keep recording after a revocation (control)", led.length === 4);

  // ---------------------------------------------------------------- N7
  console.log("\n-- N7 direct call to a covered pool");
  rep.ok("N7a a direct call with a valid proof is recorded by the pool itself (records above)",
    w.m.records.filter((r) => r.label.startsWith("Alice record")).length === 4);
  rep.ok("N7b a direct call with no recording arguments reverts",
    !!(await w.expectRevert("N7b no proof", w.poolA, "swap",
      poolArgs(M, 300, [0n, zeros8, 0n, 0n]), "unknown RCL root", sg.mallory)));
  rep.ok("N7c a direct call with known roots and a null proof reverts",
    !!(await w.expectRevert("N7c null proof", w.poolA, "swap",
      poolArgs(M, 300, [12345n, zeros8, w.m.rcl.root(), w.m.at.root()]), "invalid proof", sg.mallory)));
  const writers = w.art.CoveredPool.abi.filter((f) => f.type === "function" &&
    f.stateMutability !== "view" && f.stateMutability !== "pure").map((f) => f.name).sort();
  rep.ok("N7d the covered pool has no other trading entry point (state-changing functions: setPrice, swap)",
    writers.join(",") === "setPrice,swap", writers.join(","));
  const rogue = await w.deploy("Aggregator", [w.acaddrHex]);          // NOT registered as an entry contract
  await (await w.usdc.connect(sg.alice).approve(await rogue.getAddress(), ethers.MaxUint256)).wait();
  const spare = await w.buildRec(alice, A);                // record 5, valid, bound to Alice
  rep.ok("N7e an unregistered aggregator cannot make the pools skip recording",
    !!(await w.expectRevert("N7e unregistered aggregator", rogue, "swapSplit",
      [w.USDC, w.ETH, [w.contracts.poolA, w.contracts.poolB], [300, 300], 0, spare.rec],
      "unknown RCL root", sg.alice)));

  // ---------------------------------------------------------------- N8
  console.log("\n-- N8 bypassing the wrapper (documented limit)");
  const dg = await w.stateDigest();
  const mEth = (await w.balances("mallory")).eth;
  rc = await w.tx("N8a direct swap on the unregistered pool behind the wrapper",
    w.plainPool.connect(sg.mallory).swap(w.USDC, 300, 0, M));
  rep.ok("N8a a direct call to the wrapped, unregistered pool SUCCEEDS UNRECORDED (documented limit)",
    rc.status === 1 && (await w.balances("mallory")).eth === mEth + 10n &&
    dg === (await w.stateDigest()) &&
    rc.logs.every((l) => l.address.toLowerCase() !== w.acaddrHex.toLowerCase()));
  await w.absorbRecord(await w.tx("Alice record 5 through the wrapper",
    w.wrapper.connect(sg.alice).swap(w.USDC, 300, 0, spare.rec)),
    alice, spare, swapExp(300), "Alice record 5 through the wrapper");
  rep.ok("N8b the same swap through the wrapper is recorded (control)", led.length === 5);

  // ---------------------------------------------------------------- N9
  console.log("\n-- N9 agency contract access control and write-once rules");
  const p6 = await w.buildRec(alice, A);                   // record 6, valid, bound to Alice
  const recArgs = (op, tin, ain, tout, aout, pid) =>
    [p6.nf, A, p6.words, p6.rootRCL, p6.rootAT, op, tin, ain, tout, aout, pid];
  const Z = ethers.ZeroAddress;
  const R = async (name, contract, method, args, reason, signer) =>
    rep.ok(name, !!(await w.expectRevert(name, contract, method, args, reason, signer)));
  await R("N9a record() called by an unregistered address", w.agency, "record",
    recArgs(1, w.USDC, 300, w.ETH, 10, 0), "not an entry contract or covered venue", sg.mallory);
  await R("N9b registerVenue by a non-owner", w.agency, "registerVenue", [M], "not the owner", sg.mallory);
  await R("N9c registerAsset by a non-owner", w.agency, "registerAsset", [M, 9, M], "not the owner", sg.mallory);
  await (await w.agency.registerVenue(D)).wait();          // Dave's address acts as a bare venue
  await R("N9d record with a token that is not in the asset table", w.agency, "record",
    recArgs(1, w.contracts.poolA, 300, w.ETH, 10, 0), "asset not covered", sg.dave);
  await R("N9e swap record with a position id", w.agency, "record",
    recArgs(1, w.USDC, 300, w.ETH, 10, 5), "bad swap fields", sg.dave);
  await R("N9f unknown operation code", w.agency, "record",
    recArgs(9, w.USDC, 300, w.ETH, 10, 0), "unknown operation", sg.dave);
  await R("N9g amount of 2^64", w.agency, "record",
    recArgs(1, w.USDC, 1n << 64n, w.ETH, 10, 0), "field out of range", sg.dave);
  await R("N9h borrow on a position that was never pledged", w.agency, "record",
    recArgs(3, Z, 0, w.USDC, 100, 4242), "not an open position of the caller", sg.dave);
  rc = await w.tx("record() called directly by a bare venue: pledge, position 7001",
    w.agency.connect(sg.dave).record(...recArgs(2, w.ETH, 10, Z, 0, 7001)));
  await w.absorbRecord(rc, alice, p6, { op: OP.PLEDGE, asset_in: 2, amount_in: 10, asset_out: 0,
    amount_out: 0, value: 300, position_id: 7001 }, "Alice record 6: pledge via the bare venue");
  const p7 = await w.buildRec(alice, A);                   // record 7
  await R("N9i second pledge with a position id already taken", w.agency, "record",
    [p7.nf, A, p7.words, p7.rootRCL, p7.rootAT, 2, w.ETH, 10, Z, 0, 7001], "position id taken", sg.dave);
  rc = await w.tx("Alice record 7: pledge through the lending venue",
    w.lending.connect(sg.alice).pledge(w.ETH, 20, Z, 0, p7.rec));
  const lendPos = (await w.lending.nextPositionId()) - 1n;
  await w.absorbRecord(rc, alice, p7, { op: OP.PLEDGE, asset_in: 2, amount_in: 20, asset_out: 0,
    amount_out: 0, value: 600, position_id: lendPos }, "Alice record 7: pledge via the lending venue");

  const path7001 = await w.pslPath(7001n);
  const passArgs = (pid, kind, ta, aa, tb, ab, path) => [pid, kind, ta, aa, tb, ab, ...path];
  await R("N9j recordPassive by a non-venue", w.agency, "recordPassive",
    passArgs(7001, 2, w.ETH, 10, Z, 0, path7001), "not a covered venue", sg.mallory);
  await R("N9k recordPassive on another venue's position", w.agency, "recordPassive",
    passArgs(lendPos, 2, w.ETH, 20, Z, 0, await w.pslPath(lendPos)), "not a position of the caller", sg.dave);
  await R("N9l recordPassive with an unknown kind", w.agency, "recordPassive",
    passArgs(7001, 3, w.ETH, 10, Z, 0, path7001), "unknown kind", sg.dave);
  await R("N9m liquidation entry with no debt covered", w.agency, "recordPassive",
    passArgs(7001, 1, w.ETH, 10, Z, 0, path7001), "no debt covered", sg.dave);
  await R("N9n recordPassive with a wrong PSL path", w.agency, "recordPassive",
    passArgs(7001, 2, w.ETH, 10, Z, 0, [[], 0, 0, true]), "bad exclusion proof", sg.dave);
  rc = await w.tx("recordPassive called directly by a bare venue (withdrawal, no interest)",
    w.agency.connect(sg.dave).recordPassive(...passArgs(7001, 2, w.ETH, 10, Z, 0, path7001)));
  await w.absorbPassive(rc, { position_id: 7001, kind: 2, asset_a: 2, amount_a: 10,
    asset_b: 0, amount_b: 0, value: 0 }, "PSL entry at position 7001");
  await R("N9o second PSL entry at the same position (write-once)", w.agency, "recordPassive",
    passArgs(7001, 1, w.ETH, 10, w.USDC, 5, [[], 0, 0, true]), "position already closed", sg.dave);

  await R("N9p second anchor at an occupied index (ATK4)", w.agency, "writeAnchor",
    [alice.atKey, H.anchor(424242n), [], 0, 0, true], "occupied", sg.ta);
  await R("N9q writeAnchor by a non-TA", w.agency, "writeAnchor",
    [H.atIndex(1n), 5n, [], 0, 0, true], "not a recognized TA", sg.mallory);
  await R("N9r revokeTag by a non-TA", w.agency, "revokeTag",
    [alice.atKey, [], 0, 0, true], "not a recognized TA", sg.mallory);

  const m = w.m;
  const ex0 = await m.unl.exclusion(m.nfLog[0]);
  const path0 = [ex0.siblings, ex0.oldKey, ex0.oldValue, ex0.isOld0];
  await R("N9s insertNullifiers from the wrong log index", w.agency, "insertNullifiers",
    [1, [path0]], "batch does not start at the covered index", sg.mallory);
  await R("N9t insertNullifiers past the end of the log", w.agency, "insertNullifiers",
    [0, new Array(m.nfLog.length + 1).fill(path0)], "batch runs past the log", sg.mallory);
  await R("N9u insertNullifiers with a wrong non-membership path", w.agency, "insertNullifiers",
    [0, [[[777n], 0, 0, true]]], "bad exclusion proof", sg.mallory);
  await R("N9v pinSnapshot while nullifiers are still outside the UNL", w.agency, "pinSnapshot",
    [2027], "UNL batches do not cover the log", sg.mallory);

  // ---- SMT inputs must be canonical (contract-side counterpart of the isOld0 fix) ----
  console.log("\n-- N10 non-canonical SMT inputs on chain");
  const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  await w.insertNullifiers(1, "insertNullifiers, first nullifier");
  // The UNL now holds exactly nf0, so nf1's path meets nf0's leaf. An old key
  // nf0 + m*p hashes to the same leaf but has other bits; before the fix this
  // call was accepted and left nf0 provably "absent" from the UNL.
  let alias = m.nfLog[0] + FIELD;
  for (let k = 2n; (alias & 1n) !== (m.nfLog[1] & 1n) && m.nfLog[0] + k * FIELD < (1n << 256n); k++) {
    alias = m.nfLog[0] + k * FIELD;
  }
  await R("N10a insertNullifiers with a non-canonical old key (nf + m*p)", w.agency, "insertNullifiers",
    [1, [[[], alias, 1n, false]]], "old leaf not canonical", sg.mallory);
  await R("N10b insertNullifiers with an old leaf given for an empty slot", w.agency, "insertNullifiers",
    [1, [[[], 5n, 1n, true]]], "old leaf given for an empty slot", sg.mallory);
  await R("N10c writeAnchor with a key that is not a field element", w.agency, "writeAnchor",
    [H.atIndex(77n) + FIELD, 5n, [], 0, 0, true], "key or value not a field element", sg.ta);
  {
    // isOld0 = 2 cannot be expressed through the ABI encoder: patch the word
    const good = w.agency.interface.encodeFunctionData("insertNullifiers", [1, [[[], 0n, 0n, true]]]);
    const words = good.slice(10).match(/.{64}/g);
    const flagAt = 7;      // [from, off, len, off, off(sibs), oldKey, oldValue, isOld0, sibs.length]
    const isOne = BigInt("0x" + words[flagAt]) === 1n && words.length === 9;
    words[flagAt] = (2n).toString(16).padStart(64, "0");
    const data = good.slice(0, 10) + words.join("");
    let callReverted = false;
    try { await w.provider.call({ to: w.acaddrHex, data, from: M }); } catch (e) { callReverted = true; }
    const before = await w.stateDigest();
    let mined = null;
    try { mined = await (await sg.mallory.sendTransaction({ to: w.acaddrHex, data, gasLimit: 3000000 })).wait(); }
    catch (e) { mined = e.receipt ?? null; }
    rep.ok("N10d insertNullifiers with isOld0 = 2 in raw calldata is rejected by the ABI decoder",
      isOne && callReverted && mined !== null && mined.status === 0 && before === (await w.stateDigest()));
  }
  await w.warp("2027-12-31T23:58:00Z");
  await w.insertNullifiers(undefined, "insertNullifiers, year 2027");
  await w.pinSnapshot(2027, "pinSnapshot 2027");
  await R("N9w pinSnapshot of a period that is already pinned", w.agency, "pinSnapshot",
    [2027], "period already pinned", sg.mallory);

  await w.checkRoots("end of the negative tests");
  rep.ok("after all rejected calls every contract root still equals the mirror", true);
  rep.eq("accepted records in total (Alice 7, Bob 1, Carol 1)", m.records.length, 9);

  const { file, fixture } = writeFixture("revoked", {
    scenario: "Ledger state after the negative tests: Carol's tag is revoked after her pledge (record 1) and her position is closed by a PSL withdrawal entry; Alice has 7 records including two pledges, one closed.",
    worlds: [w],
    taxpayers: [
      { name: "alice", role: "alice", tags: [alice] },
      { name: "bob", role: "bob", tags: [bob] },
      { name: "carol", role: "carol", tags: [carol] },
    ],
    notes: [
      "Carol's TRL leaf is set (trl.leaves holds her index). Filing checks no revocation, so her one-record ledger must still open, with the PSL entry of her position.",
      "Dave's tag is signed but was never anchored; it has no ledger and is not listed.",
    ],
  });
  const cf = fixture.expected.find((e) => e.taxpayer === "carol").filings[0];
  rep.ok("reference rule for the revoked tag: one record, position closed, D = (0, 0, 0)",
    cf.D.proceeds === "0" && cf.D.cost === "0" && cf.D.income === "0" &&
    cf.closing_state.counters["carol@1337"] === 1 && cf.closing_state.open.length === 0);
  console.log(`fixture written: ${file}`);
});
