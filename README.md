# taxtag-defi26

Prototype and benchmark of the TaxTag recording and filing protocol, the
artifact behind Section 5 (Evaluation) of *TaxTag: A Zero-Knowledge Tax
Filing Protocol for Decentralized Finance* (DeFi '26).

It contains two parts.

- **Recording.** One recording circuit, the agency contract in Solidity
  and a set of demo venues. The harness replays the paper's worked example
  and its variants on an in-process EVM with real Groth16 proofs, and
  compares every contract root with an independent implementation.
- **Filing.** A step circuit folded with Nova and CycleFold, a boundary
  circuit proven with Groth16, and a compressing proof that blinds the
  folded instance and compresses it with Groth16. A filing is the
  compressing proof together with the boundary proof. Both carry the same
  two state digests, and the authority command checks both proofs and
  compares the digests.

`REPRODUCE.md` gives the commands in order and maps every number of the
paper to the command that prints it. `RESULTS.md` lists the measured
numbers.

## Layout

```
circuits/rec/        recording circuit (taxtag_rec_common.circom, main
                     components at SMT depth 16, 64 and 128)
circuits/filing/     step circuit c_fstep, boundary circuit Boundary(NT, D)
                     for 2 and 16 tags
contracts/           AgencyContract.sol, demo venues (pools, aggregator,
                     wrapper, lending venue), test helpers
harness/             recording side: build and benchmark, scenario tests,
                     negative tests, gas measurements
fixtures/            ledgers written by the contract in the scenario runs,
                     with their schema
filing/              filing side: reference implementation of the rule
                     program, input generators, end-to-end and negative
                     tests, fold and boundary benchmarks
folding/             fold driver and the one-constraint patch to the
                     folding library (basecase_z0.patch)
folding-runner/      the end-to-end runner: fold, blind, compress, and the
                     authority-side check (setup_filing.sh,
                     prove_filing.sh, verify_filing.sh,
                     measure_filings.sh), the modified copy of the
                     folding library (sonobe-zk/), and the design notes
                     ZK-DECIDER.md, G5-ANALYSIS.md and API-zk-decider.md
SPEC.md              hash layouts, record and state formats, public inputs
```

A note on names: the documents use the paper's terms. The code uses two
other names. The record leaf list (RLL) is `RCL` there (`root_rcl`,
`knownRCL`, `rootRCL`), and the end-of-records check is "end of ledger" in
its comments. They are the same things.

## Requirements

- Node 18 or later, circom 2.x, a Rust toolchain. Measured with Node
  24.14, circom 2.2.3, snarkjs 0.7.6, solc 0.8.36 and rustc 1.94.0.
- A bash shell. On Windows use Git Bash.
- 32 GB of memory for the compressing proof. Its setup commits up to
  14.6 GB and writes about 16.5 GB of files.
- Internet on the first run for npm packages, cargo dependencies, the
  folding library sonobe at revision 9414c45, and the powers-of-tau files
  of the PSE Perpetual Powers of Tau bucket (151 MB and 302 MB, and
  2.4 GB only for the sixteen-tag boundary proof).

## Quick start

```bash
npm install
bash harness/bench_rec.sh      # recording circuit: sizes, setup, proving time
bash harness/run_all.sh        # recording tests on the in-process EVM
node harness/gas_record.js     # gas table
bash filing/run_all.sh         # filing circuits, fold driver, tests, benchmarks
cd folding-runner
bash run_zk_decider.sh build   # the end-to-end runner
bash setup_filing.sh           # one-time setup of the compressing proof
bash measure_filings.sh worked two-tags   # two filings, prover and authority side
```

## Numbers

Reference machine: a Windows 11 laptop with an 8-core AMD Ryzen AI 7 H 350
and 32 GB of memory.

| Item | Value |
|---|---|
| recording circuit | 30,233 / 54,425 / 86,681 constraints at SMT depth 16 / 64 / 128 |
| recording proof at depth 64 | 1.9 to 2.5 s, 1.9 GB, 256 bytes of calldata (snarkjs) |
| `record` call | 1.76M to 1.80M gas, of which 238k is proof verification |
| step circuit | 32,604 constraints |
| fold | 0.9 to 1.0 s per record, about 17 minutes per 1,000 records, 0.8 GB |
| compressing proof | 8,709,770 constraints, 71 to 79 s, 13.5 GB, 5.06 MB, verified in about 0.4 s |
| boundary proof, two tags | 148,697 constraints, 3.7 to 4.2 s, 2.3 GB, verified in 3 ms |
| boundary proof, sixteen tags | 1,155,334 constraints, 22 to 25 s, 11 GB |

Times are ranges over two independent runs of the whole artifact on the
reference machine, kept quiet. The first proof after a start is the slow
end of a range. Memory is the peak working set of the prover. The
compressing proof commits 14.4 GB at its peak.

The fold figure uses the step circuit's witness generator compiled once,
which is the runner's default. With the folding library's own frontend,
which compiles it again at every step, a step takes 1.2 to 1.3 s.

## Scope

- The complete filing statement runs end to end for two tags on two
  chains under the moving-average rule program. A filing over sixteen tags
  is proven as well.
- The rule program takes no input besides the records.
- The average cost is stored as a whole number, so it rounds.
- The demo venues are mocks with fixed prices.
- All Groth16 keys are generated locally without a ceremony. They are
  measurement material, not deployment keys.
- The soundness of the compressing proof rests on the assumptions stated
  in `folding-runner/ZK-DECIDER.md` and `folding-runner/G5-ANALYSIS.md`.

## License

MIT, see `LICENSE`.
