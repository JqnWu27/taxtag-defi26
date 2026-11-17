# TaxTag prototype: specification

Hash layouts, record and state formats and public inputs of the prototype.
The worked example is the one of Section 4 of the paper, and the numbers
are those of its Section 5.

## 1. Design decisions

1. **No intent in the proof.** The contract writes every field.
2. **One recording circuit** for every record. The anchor is checked at
   every record. A predecessor check applies when `i > 1`.
3. **Nullifier in the leaf.** The leaf holds `NF_i`. The
   recording proof for `i > 1` shows, privately, that the leaf holding
   `NF_{i-1}` is in the record leaf list (RLL). Chain id enters the nullifier.
4. **Root rule.** A recording proof may cite any earlier RLL root and any
   earlier AT root (the contract stores every root). The TRL root must be
   the current one. Nullifier freshness is checked by the contract against
   its own storage. So two recordings built against the same roots both land.
5. **Nullifier storage.** `used[NF]` mapping plus an append log. Anyone can
   call a batch function that inserts the logged nullifiers into the UNL SMT
   in log order and publishes the new root. The snapshot pins the UNL root
   once the batches cover every nullifier up to the boundary.
6. **Leaf fields.** The leaf carries a timestamp and one number, the
   value. No fee field. No cash list: stablecoins are ordinary assets.
7. **Entry contract.** The contract that moves the owner's assets (pool,
   router, aggregator) records once with the net amounts and reports the
   owner. The owner is the address that calls the entry contract. The
   paper calls it the taxpayer's address. A covered contract records itself unless a registered entry
   contract calls it. A wrapper in front of an unchanged service also
   records, but a direct call bypasses it.
8. **Asset table in the agency contract.** Token address to (asset id,
   price feed). One asset id per asset on every chain.
9. **Passive events in the main fold.** Liquidation and withdrawal are PSL
   entries written by the venue with no taxpayer proof (section 5).
10. **Year chain.** A filing folds only its period's records, starting from
    the state committed in `C_{y-1}` and ending in `C_y`. First filing starts
    empty. `C_y`'s blinding is derived from the first tag's `S` and the
    period.
11. **Merge order.** Records and PSL entries are merged by their
    coordinates `(time, cid, block, idx)`, strictly increasing over all
    tags and chains. One asset leaf per asset across all chains and tags.
12. **Multi-tag, two chains** run end to end.
13. **Padding.** The fold is padded with empty steps to the next power of
    two, at least 64. (Not mentioned in the paper.)
14. **Blind-then-compress** for the compressing proof (HyperNova, Kothapalli and
    Setty, CRYPTO 2024, appendix on zero-knowledge folding).
15. **D = (proceeds, costs, income).** No separate gain line.
    income = proceeds - costs + rewards + interest. The code calls the
    second value `cost`.

## 2. Hash conventions (shared by circuits, contract and scripts)

Poseidon over BN254 as in circomlib. `P(a, b, ...)` is Poseidon with that
many inputs. Small integers in first position are domain tags.
Use only arities 2, 3 and 5 on chain.

| Object | Formula | Note |
|---|---|---|
| hidden identifier | `id_tax = P(1, tag, S)` | |
| AT / TRL index | `P(3, tag)` | |
| anchor, credential message, keyset digest | as in `circuits/rec/taxtag_rec_common.circom` | |
| nullifier | `NF_i = P(8, id_tax, cid, acaddr, i)` | arity 5 |
| leaf meta | `meta = P(7, NF_i, cid, block, idx)` | arity 5 |
| leaf body | `body = P(op, asset_in, amount_in, asset_out, amount_out)` | arity 5 |
| leaf tail | `tail = P(10, value, position_id, time, 0)` | arity 5 |
| record leaf | `leaf = P(meta, body, tail)` | arity 3, appended to the RLL (depth 32) |
| PSL entry meta | `pmeta = P(11, kind, cid, block, idx)` | kind 1 liquidation, 2 withdrawal |
| PSL entry body | `pbody = P(asset_a, amount_a, asset_b, amount_b, value)` | see section 5 |
| PSL entry | `pentry = P(pmeta, pbody, time)` | stored at key `position_id` in the PSL SMT, write-once |
| closing commitment | `C_y = P(state_digest, blind_y)`, `blind_y = P(13, S, y)` | `S` of the taxpayer's first tag |

Operation codes: 1 swap, 2 pledge, 3 borrow, 4 repay, 5 claim reward.
A field an operation does not use is 0. "In" is what the taxpayer gives,
"out" is what the taxpayer receives.

| op | asset_in / amount_in | asset_out / amount_out | position_id |
|---|---|---|---|
| swap | asset given | asset received | 0 |
| pledge | collateral | loan, if the same call borrows, else 0 | yes |
| borrow | 0 | loan | yes |
| repay | coins repaid | 0 | yes |
| claim reward | 0 | reward | 0 |

Asset ids are 1..65535 (leaf index in the depth-16 asset tree), 0 = none.
Amounts, values, block, idx, time are below 2^64. Amounts are integers in
the unit the demo tokens use. Value is an integer in the oracle's unit
(USD in the demo): `value = amount_out * price(asset_out)` when the
taxpayer receives something, else `amount_in * price(asset_in)`.
Every covered asset must have a price feed (a mock feed in the demo).

`time`, `cid`, `block` and `idx` are the coordinates of a record or a PSL
entry. `idx` is the order in which the agency contract wrote the entry
within its block. Records and PSL entries share this counter, because a
contract cannot read the transaction index.

## 3. Agency contract

A recognized agency writes anchors and revokes tags (`writeAnchor`,
`revokeTag`). The keyset digest is fixed at deployment. The other functions:

- `registerEntry(addr)`, `registerVenue(addr)`, `registerAsset(token, assetId, feed)` (owner only, demo set-up).
- `record(nf, owner, proof, rootRCL, rootAT, op, tokenIn, amountIn, tokenOut, amountOut, positionId)`:
  caller must be a registered entry contract or covered venue.
  Checks: `knownRCL[rootRCL]`, `knownAT[rootAT]`, current `rootTRL`,
  `!used[nf]`, Groth16 proof with public inputs
  `[nf, rootRCL, rootAT, rootTRL, keysetDigest, cid, acaddr, owner]`.
  Effects: `used[nf] = true`, append `nf` to the log, look up asset ids and
  the price, compute `value`, form the leaf, append it to the RLL, store the
  new RLL root in `knownRCL`, emit an event with every leaf field.
- `insertNullifiers(...)`: anyone. Inserts the next logged nullifiers into
  the UNL SMT in log order, each with a non-membership path against the
  running root, and stores the new `rootUNL` and how far the log is covered.
- `recordPassive(positionId, kind, ...)`: covered venue only. Writes the
  PSL entry (write-once) with timestamp and chain position.
- `pinSnapshot(period)`: pins `(rootRCL, rootUNL, rootAT, rootPSL)`.
  Requires the UNL batches to cover the whole log.
- Demo contracts: two pools, one aggregator that splits a swap over both
  pools and records once, one lending venue (pledge with optional loan,
  borrow, repay, liquidate, withdraw), one wrapper in front of an
  unregistered pool, mock tokens and mock price feeds.
- A covered pool records itself unless `isEntry[msg.sender]`.

## 4. Recording circuit `c_rec.circom`

Public inputs, in this order: `nf, root_rcl, root_at, root_trl,
keyset_digest, cid, acaddr, owner`.

Checks:
1. Credential: EdDSA signature on the tag under one of the recognized keys.
2. Anchor: `id_tax = P(1, tag, S)` and the AT holds the anchor at index `P(3, tag)` under `root_at`.
3. Non-revocation: TRL leaf at `P(3, tag)` empty under `root_trl`.
4. Nullifier: `nf = P(8, id_tax, cid, acaddr, i)`.
5. Predecessor, only when `i > 1`: `nf_prev = P(8, id_tax, cid, acaddr, i-1)`,
   `leaf_prev = P(P(7, nf_prev, cid, block_prev, idx_prev), body_prev, tail_prev)`
   is in the RLL under `root_rcl`. `nf_prev` stays private. For `i = 1` the
   check is switched off and `root_rcl` is unconstrained.

Parameters: SMT depth D in {16, 64, 128}, RLL depth 32, 16 keys.
Constraints are measured at all three depths, proving time and memory at
D = 64.

## 5. Passive events: liquidation and withdrawal, in the main fold

Every pledge ends liquidated or withdrawn. The venue writes a PSL entry at
the position id with how it ended, the timestamp and the chain position.
No taxpayer proof is needed, so a revoked tag can still withdraw.

- **Liquidation entry.** `asset_a, amount_a` = collateral seized,
  `asset_b, amount_b` = debt covered, `value` = oracle value of the debt
  covered. Rule: a disposal of the collateral at that moment's average
  cost, with proceeds `value`. The borrowed coins stay in their leaf.
- **Withdrawal entry.** `asset_a, amount_a` = collateral returned,
  `asset_b, amount_b` = interest earned, `value` = oracle value of the
  interest. Rule: the position leaves the open set, the interest coins
  enter their asset leaf at cost `value`, and `value` is added to income.
  A partial withdrawal writes nothing. Its interest is counted when the
  position closes. There is no separate claim record for this interest.
- `C_y` carries the position ids of pledges that are still open.
- The fold merges records, liquidation entries and withdrawal entries into
  one time-ordered sequence by their coordinates `(time, cid, block, idx)`.
- Each filing opens the PSL leaf of every open position under `rootPSL(B)`:
  empty means the position stays open and goes into `C_y`; a PSL entry
  found there must be folded as described above.
- The closing check is "`C_y` has no open position", checked in the
  boundary circuit.

## 6. Rule program: moving average

State per asset: quantity `q` and average cost `avg`.

| Event | Asset leaf | Sums |
|---|---|---|
| swap | asset_in: dispose `amount_in`; asset_out: buy `amount_out` for `value` | proceeds += value, costs += amount_in * avg(asset_in) |
| pledge | no leaf changes (a loan in the same call is handled as a borrow) | none |
| borrow | asset_out: buy `amount_out` for `value` | none |
| repay | asset_in: remove `amount_in` at its average cost | none |
| claim reward | asset_out: buy `amount_out` for `value` | rewards and interest += value |
| liquidation | collateral: dispose `amount_a` | proceeds += value, costs += amount_a * avg |
| withdrawal | interest asset: buy `amount_b` for `value` | rewards and interest += value |

The state holds three sums, the proceeds, the costs, and the rewards and
interest. Units disposed beyond the recorded quantity carry no cost (cost 0
for the missing part, quantity floors at 0). A buy of `n` units for `cost`
gives `avg' = (q*avg + cost)/(q + n)`.
`D = (proceeds, costs, income)` with `income = proceeds - costs + rewards + interest`
computed at finalization.

## 7. Filing: fold and final checks

Step circuit for Nova + CycleFold (sonobe), IVC state = one Poseidon digest
of the state vector.

State (outline; the exact layout is in the header of
`circuits/filing/c_fstep.circom`):
asset tree root (depth 16, leaf `P(q, avg)`); ledger tree root over the
demanded tags (depth 4, leaf `P(id_tax, n_chain0, n_chain1)` = identifier
and the counter reached on each of two chains); working open-position set
and final open-position set (SMT roots plus counts, key `P(cid, position_id)`);
the three sums (proceeds, costs, rewards and interest); the coordinates of
the record or PSL entry folded last; digest of the pinned RLL and PSL roots
at B of both chains; blinding.

Step kinds: (a) record step: next counter of one (tag, chain), `NF` formed
in circuit, leaf opened under the pinned RLL root, coordinates strictly
larger than the last ones, rule update, a pledge adds its position to the
working set; (b) PSL-entry step: the PSL entry of a working position, merged
by its own coordinates, rule update, position removed from the working set;
(c) still-open step: PSL leaf empty under `rootPSL(B)`, position moved from
the working set to the final set; (d) padding step: no change.

Checks of the boundary circuit (the paper's boundary proof; it carries the
same public start and end state digests as the compressing proof):
1. Start: the start state is the one committed in `C_{y-1}` (empty at the
   first filing), with zero totals and the public pinned roots.
2. Anchor: for each demanded tag, `id_tax = P(1, tag, S)` and the anchor is
   in the AT under `rootAT(B)`.
3. End of records: for each (tag, chain), `NF_{n+1}` is a non-member of the
   UNL under `rootUNL(B)`, kept private.
4. Every pair: each demanded (tag, chain) has its start, anchor and end.
5. The working open-position set is empty at the end.
6. `D` equals the final totals, and `C_y` commits to the closing state
   (asset tree, ledger tree, final open set) with `blind_y`.
7. Optional public flag for a closing filing: the final open set is empty.

Public to the authority: tag set `T`, per chain the snapshot roots and
`acaddr`, the rule-version key, `D`, `C_{y-1}`, `C_y`. Nothing else.

### Where each check of the paper is enforced

Recording statement (Figure 2 of the paper), all in template `CRec` of
`circuits/rec/taxtag_rec_common.circom`:

| Check of Figure 2 | Where |
|---|---|
| 1 Credential | `KeySelect` and `EdDSAPoseidonVerifier` on `P(9, tag)`; the key set is bound by the public `keyset_digest` |
| 2 Anchor | `id_tax = P(1, tag, S)`, inclusion of `P(2, S)` at `P(3, tag)` under `root_at` |
| 3 Non-revocation | exclusion at `P(3, tag)` under `root_trl`; `AgencyContract.record` passes its current TRL root |
| 4 Nullifier | `nf = P(8, id_tax, cid, acaddr, i)`; freshness is `!used[nf]` in `AgencyContract.record` |
| 5 Predecessor | for `i > 1`, the leaf holding `NF_{i-1}` opens under `root_rcl` |

Filing statement (Figure 3 of the paper):

| Check of Figure 3 | Where | Negative cases in `filing/negative.js` |
|---|---|---|
| 1 Start | boundary circuit, check 1 | start in the middle, wrong start state, wrong `C_{y-1}`, chain run from another start state |
| 2 Anchor | boundary circuit, check 2 | |
| 3 Openings | step circuit, record step: counter `n + 1`, `NF` formed in circuit, leaf opened under the pinned RLL root. The boundary circuit recomputes the pins from the public roots | skipped counter, altered value, altered amount |
| 4 End of records | boundary circuit, check 3 | hidden tail |
| 5 Positions | step circuit, PSL-entry step and still-open step; boundary circuit, check 5 | undeclared liquidation, position dropped, liquidated position dropped or hidden, still-open step for a position outside the working set |
| 6 Merge | step circuit, coordinates strictly larger at every record and PSL entry; the boundary circuit starts them at zero | reordered records |
| 7 Rule evaluation | step circuit, rule update; boundary circuit, check 6 (`D` and `C_y`) | inflated average cost |
| every demanded pair is covered | boundary circuit, check 4 | dropped (tag, chain) pair, dropped tag |
| the two proofs belong to one filing | `folding-runner/verify_filing.sh`, checks 4 and 5 (equal start and end digests) | the four filings of `measure_filings.sh negatives` |

## 8. Validation the artifact must show

1. **Worked example of the paper** (Section 4). Start state: 6000 USDC
   at average cost 1, counter 4. TX1 swap 6000 USDC for 2 ETH (value 6000),
   record 5. TX2 pledge 1 ETH with a loan of 2000 USDC, one pledge record,
   record 6. TX3 swap 1 ETH for 3600 USDC through the aggregator over two
   pools, record 7. Filing: `D = (9600, 9000, 600)`. Closing state: ETH
   (1, 3000), USDC (5600, 1), counter 7, one open position.
2. The same with a liquidation, and with a withdrawal with interest.
3. Two tags on two chains in one filing, interleaved by time.
4. Two recordings built against the same roots both land (concurrency).
5. Negative tests: skipped counter, start in the middle, hidden tail,
   dropped (tag, chain) pair, wrong start state, altered value, reordered
   records, undeclared liquidation, direct call to a covered pool (must
   record or revert), direct call bypassing the wrapper (succeeds unrecorded,
   the documented limit), revoked tag cannot record but can withdraw.

## 9. Numbers the paper needs (reported in `RESULTS.md`)

- Recording circuit constraints at D = 16, 64, 128. Proving time and peak
  memory at D = 64 (snarkjs), proof size.
- Gas: writeAnchor, revokeTag, record (range) with the proof verification
  share, recordPassive, insertNullifiers per nullifier, pinSnapshot.
- Step circuit constraints. Fold time per step and memory at 100 (128 with
  padding) and 1000 (1024) records. Folded-instance verify time.
- Compressing proof (blind-then-compress) and boundary proof: constraints,
  proving time, peak memory, proof size, verify time.
- Reference machine: a laptop with an 8-core Ryzen AI 7 H 350 and 32 GB RAM.
- Every number reproducible by script, with `REPRODUCE.md`.

## 10. Choices taken in this specification

Liquidation proceeds = oracle value of the debt covered; arities and tags
of section 2; `blind_y` from the first tag's `S`; ledger tree leaf layout;
closing flag as an optional public input.
