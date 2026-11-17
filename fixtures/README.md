# Recording-side fixtures (TaxTag artifact)

Each JSON file here is the complete public state one scenario left on the
in-process chain(s), plus the test secrets of the taxpayers, so the filing
side can open the ledgers without running the recording harness.

Every file was written by a scenario script at the end of a run in which
real Groth16 recording proofs were verified by the agency contract and every
contract root was checked against the JavaScript mirrors
(`harness/lib/trees.js`). Regenerate with the command in the table, or all of them with
`bash harness/run_all.sh`, which ends with `node harness/check_fixtures.js`,
a check of every file from the JSON alone. The
chain is deterministic (fixed accounts, fixed block timestamps), so a rerun
reproduces every file byte for byte. Only the proofs and the transaction
hashes (which cover the proofs) differ between runs, and neither is stored.

| File | Script | Content |
|---|---|---|
| `example.json` | `node harness/run_example.js` | The paper's worked example. Alice: records 1..4 in 2026 (four claims of 1500 USDC), snapshot 2026, then TX1 (record 5), TX2 (record 6), TX3 (record 7), snapshot 2027. Bob's three records are interleaved and unrelated. |
| `liquidation.json` | `node harness/run_liquidation.js` | The same with a liquidation of Alice's position between TX2 and TX3 (PSL entry kind 1). |
| `withdrawal.json` | `node harness/run_withdrawal.js` | The worked example followed by a borrow (record 8), a repay (record 9), a partial withdrawal (not recorded anywhere) and a full withdrawal with interest (PSL entry kind 2). |
| `two_chains.json` | `node harness/run_two_chains.js` | Two tags of one taxpayer on two chains (1337 and 1338), interleaved by time, one pair of records with equal timestamps, one zero-length ledger, one open position. |
| `concurrency.json` | `node harness/run_concurrency.js` | Three ledgers proven against shared roots. Two records share one block (`idx` 0 and 1), and two further blocks each hold one record and one PSL entry (`idx` 0 and 1, in both orders). Alice holds two tags on one chain. |
| `revoked.json` | `node harness/run_negative.js` | State after the negative tests: Carol's tag is revoked after her one pledge record and her position is closed by a withdrawal entry. |
| `revoked_repay.json` | `node harness/run_revoked_repay.js` | One owner with two tags. Tag A (`alice`): claim, swap, pledge with a loan (position 1001), then tag A is revoked. The loan is repaid with a record under tag B (`alice2`), then the position is withdrawn (PSL entry kind 2). A two-tag filing on one chain. |

## Conventions

- **Numbers.** Every field element and every 64-bit quantity is a decimal
  string. Small counts and indices (`leaf_index`, `leaf_count`, `period`,
  `ta_key_index`, ...) are JSON numbers.
- **Hashes.** Poseidon over BN254 with circomlib parameters, exactly the
  layouts of `SPEC.md` section 2. `harness/lib/hashes.js` is a small
  reference implementation.
- **Sparse Merkle trees** (AT, TRL, UNL, PSL) are circomlib / circomlibjs
  trees: leaf hash `P(key, value, 1)`, node `P(left, right)`, empty subtree
  `0`, key bits taken from the least significant bit. Rebuild one with
  circomlibjs `newMemEmptyTrie()` and insert the listed `[key, value]` pairs
  in the listed order. The root does not depend on the order, the list
  order is the on-chain write order. There is no sentinel leaf: an empty tree
  has root `0`.
- **RLL** (`rcl` in the JSON) is a positional append-only Merkle tree of depth 32: node
  `P(left, right)`, empty leaf `0`, leaf `k` at position `k`. The root at a
  snapshot is the root over the first `leaf_count` leaves.
- **Units.** Amounts are integers in token units. The demo USDC has 0
  decimals (1 unit = 1 USDC). The demo ETH has 2 decimals (1 unit = 0.01
  ETH), because the worked example splits a sale of 1 ETH over two pools.
  So "2 ETH" is `200` and "1 ETH" is `100`. `value` is an integer number of
  USD: `amount * price`, where the mock feed quotes USD per token unit (ETH
  30 = 3000 USD per ETH, later 36 or 22, 45 on the second chain). In token
  units the closing state of the worked example is ETH `(q, avg) = (100, 30)`,
  which is 1 ETH at 3000, and USDC `(5600, 1)`.
- **Asset ids.** `1` = USDC, `2` = ETH, `0` = none, on every chain.
- **idx.** The per-block sequence number of the entries the agency contract
  wrote in that block. Records and PSL entries share the counter. The EVM
  does not expose the transaction index.
- **Test secrets only.** `tag`, `S` and the credential signatures are
  fixed test constants. The 16 TA keys are deterministic test keys.

## Schema `taxtag-recording-fixture/1`

```
{
  "schema": "taxtag-recording-fixture/1",
  "scenario": "<file name without .json>",
  "description": "...",
  "params": { "smt_depth": 64, "rcl_depth": 32, "ta_keys": 16 },
  "units": { ... prose ... },
  "keyset": { "pubx": [16], "puby": [16], "digest": "P(P(pubx), P(puby))" },

  "chains": [ {                      // one object per chain
    "cid": "1337",                   // chain id, as in the nullifier and the leaf
    "acaddr": "<decimal>",           // agency contract address as a field element
    "acaddr_hex": "0x...",
    "keyset_digest": "...",
    "assets": [ { "asset_id": 1, "symbol": "USDC", "token": "0x...", "decimals": 0, "unit": "1 USDC" }, ... ],
    "contracts": { "poolA": "0x...", "poolB": ..., "aggregator": ..., "lending": ..., "plainPool": ..., "wrapper": ... },

    "rcl": { "depth": 32, "empty_leaf": "0", "root": "<current root>",
             "leaves": [ "<leaf 0>", "<leaf 1>", ... ] },      // ALL leaves in order, every taxpayer

    "records": [ {                   // one per RLL leaf, same order as rcl.leaves
      "leaf_index": 6,
      "leaf": "...",                 // = P(meta, body, tail)
      "nf": "...",                   // NF_i = P(8, id_tax, cid, acaddr, i)
      "cid": "1337", "block": "71", "idx": "0", "time": "1801476000",
      "op": "1",                     // 1 swap, 2 pledge, 3 borrow, 4 repay, 5 claim reward
      "asset_in": "1", "amount_in": "6000",
      "asset_out": "2", "amount_out": "200",
      "value": "6000", "position_id": "0",
      "meta": "...",                 // P(7, nf, cid, block, idx)
      "body": "...",                 // P(op, asset_in, amount_in, asset_out, amount_out)
      "tail": "...",                 // P(10, value, position_id, time, 0)
      "test_only": {                 // NOT on chain: what the harness knows
        "tag": "alice", "i": "5", "label": "...", "owner": "0x...",
        "cited_root_rcl": "..."      // the RLL root the recording proof cited
      }
    } ],

    "nf_log": [ "<nf of leaf 0>", ... ],   // the contract's append log, in order
    "unl": { "covered": 10, "root": "...", "leaves": [ ["<nf>", "1"], ... ] },   // insertion order = log order
    "at":  { "root": "...", "leaves": [ ["<P(3,tag)>", "<P(2,S)>"], ... ] },
    "trl": { "root": "...", "leaves": [ ["<P(3,tag)>", "1"], ... ] },
    "psl": { "root": "...",
             "entries": [ {          // SMT key = position_id, value = pentry
               "position_id": "1001", "kind": "1",       // 1 liquidation, 2 withdrawal
               "cid": "1337", "block": "...", "idx": "0", "time": "...",
               "asset_a": "2", "amount_a": "100",        // collateral seized / returned
               "asset_b": "1", "amount_b": "2000",       // debt covered / interest earned
               "value": "2000",                          // oracle value of (asset_b, amount_b)
               "pmeta": "...",       // P(11, kind, cid, block, idx)
               "pbody": "...",       // P(asset_a, amount_a, asset_b, amount_b, value)
               "pentry": "...",      // P(pmeta, pbody, time)
               "test_only": { "label": "..." }
             } ] },

    "snapshots": [ {                 // one per pinSnapshot call, in order
      "period": 2027,
      "root_rcl": "...", "root_unl": "...", "root_at": "...", "root_psl": "...",
      "block": "81", "time": "...",  // block and timestamp of the pin transaction
      "leaf_count": 10,              // RLL leaves at the pin: rcl.leaves[0 .. leaf_count-1]
      "nf_count": 10,                // nullifiers in the UNL at the pin: nf_log[0 .. nf_count-1]
      "at_count": 3,                 // AT entries at the pin: at.leaves[0 .. at_count-1]
      "psl_count": 0,                // PSL entries at the pin: psl.entries[0 .. psl_count-1]
      "trl_count": 1
    } ]
  } ],

  "taxpayers": [ {
    "name": "alice", "address": "0x...",          // the owner address of her transactions
    "tags": [ {
      "name": "alice",
      "tag": "...", "S": "...",                    // TEST secrets
      "id_tax": "...",                             // P(1, tag, S)
      "anchor": "...",                             // P(2, S)
      "at_index": "...",                           // P(3, tag): AT and TRL key
      "ta_key_index": 5,                           // which of the 16 keys signed
      "credential": { "R8x": "...", "R8y": "...", "S": "..." },   // EdDSA-Poseidon on P(9, tag)
      "ledgers": [ {                               // one per chain, same order as "chains"
        "cid": "1337", "acaddr": "...",
        "anchored": true,                          // the tag's anchor is in this chain's AT
        "records": [ { "i": "1", "nf": "...", "leaf_index": 0 }, ... ],
        "next_counter": 8,
        "nf_next": "..."                           // NF_{n+1}: must be a NON-member of the UNL
      } ]
    } ]
  } ],

  "expected": [ {                    // informative, see below
    "taxpayer": "alice",
    "filings": [ {                   // one per pinned period, in order
      "period": 2027,
      "start_state":   { "assets": { "1": { "q": "6000", "avg": "1" } }, "counters": { "alice@1337": 4 }, "open": [] },
      "D": { "proceeds": "9600", "cost": "9000", "income": "600" },
      "income_parts": { "rewards": "0", "interest": "0" },
      "closing_state": { "assets": { ... }, "counters": { "<tag>@<cid>": n }, "open": [ "<cid>:<position_id>" ] },
      "merged_sequence": [ { "type": "record", "time", "cid", "block", "idx", "tag", "i" },
                           { "type": "passive", "time", "cid", "block", "idx", "position_id", "kind" } ],
      "integer_average_exact": true
    } ]
  } ],
  "notes": [ "..." ]
}
```

## How to open a ledger from a fixture

For a tag and a chain (one entry of `taxpayers[].tags[].ledgers[]`) and a
snapshot `B` of that chain:

1. `id_tax = P(1, tag, S)`. For `i = 1, 2, ...` the nullifier is
   `P(8, id_tax, cid, acaddr, i)`. The record with that `nf` in
   `chains[].records` is record `i`. The period of a snapshot holds the
   records with `prev.leaf_count <= leaf_index < B.leaf_count`.
2. The leaf opens as `P(P(7, nf, cid, block, idx), P(op, asset_in,
   amount_in, asset_out, amount_out), P(10, value, position_id, time, 0))`
   at position `leaf_index` of the RLL built from
   `rcl.leaves[0 .. B.leaf_count-1]`, whose root is `B.root_rcl`.
3. End of records: with `n` the last counter whose leaf index is below
   `B.leaf_count`, `NF_{n+1}` is a non-member of the UNL built from
   `nf_log[0 .. B.nf_count-1]` (value 1 at each key), whose root is
   `B.root_unl`. For the final snapshot of a file this is `nf_next`.
4. Anchor: `P(2, S)` at key `P(3, tag)` in the AT built from
   `at.leaves[0 .. B.at_count-1]`, root `B.root_at`.
5. Positions: for every pledge record, the PSL built from
   `psl.entries[0 .. B.psl_count-1]` (key `position_id`, value `pentry`),
   root `B.root_psl`, either has no leaf at `position_id` (still open) or
   holds the entry listed there.

## The `expected` block

`expected` is written by `harness/lib/rule_ref.js`, a plain JavaScript
evaluation of the moving-average rules of `SPEC.md` section 6. It is not
the filing circuit and proves nothing. It is there so the filing side has an
independent number to compare with. Its conventions: integer average
`avg' = floor((q*avg + cost)/(q + n))` for a buy of `n` units, disposals beyond the recorded
quantity carry no cost, `income = proceeds - cost + rewards + interest`.
`integer_average_exact` is `true` when no division left a remainder, so the
figures do not depend on a rounding convention. It is `true` in
`example`, `liquidation`, `withdrawal`, `two_chains` and `revoked_repay`.

Expected results in token units:

| Fixture | Period | D = (proceeds, cost, income) | Closing state |
|---|---|---|---|
| `example` | 2026 | (0, 0, 6000) | USDC (6000, 1); counter 4; no open position |
| `example` | 2027 | (9600, 9000, 600) | ETH (100, 30) = 1 ETH at 3000; USDC (5600, 1); counter 7; open position 1001 |
| `liquidation` | 2027 | (11600, 12000, -400) | ETH (0, 30); USDC (5600, 1); counter 7; none open |
| `withdrawal` | 2027 | (9600, 9000, 1320) | ETH (120, 31); USDC (3600, 1); counter 9; none open |
| `two_chains` | 2027 | (9150, 8900, 6250) | ETH (100, 40); USDC (2250, 1); counters (T1,1337) 4, (T1,1338) 1, (T2,1337) 0, (T2,1338) 3; open position 1337:1001 |
| `revoked_repay` | 2027 | (6000, 6000, 6000) | ETH (200, 30); USDC (0, 1); counters tag A 3, tag B 1; none open |
