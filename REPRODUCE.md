# Reproducing the TaxTag evaluation

All commands run from the repository root in a bash shell unless a step
says otherwise. On Windows use Git Bash. `bash` started from PowerShell is
WSL on many machines and has no circom or cargo on its path, and the
scripts stop with a message in that case.

Expected values are from the reference machine, a Windows 11 laptop with
an 8-core AMD Ryzen AI 7 H 350 and 32 GB of memory. Constraint counts, gas,
proof sizes and every accept or reject verdict are deterministic. Times
depend on the machine and its state. For timings, run one heavy job at a
time on mains power on an otherwise idle machine, with other programs
closed. On battery the fold ran 2.6 times slower on the reference machine,
and with other programs open and little free memory about 25% slower. The
first proof after a start is slower than the following ones. The benchmark scripts print the
CPU load and the free memory before each timed run. All runs were made on
Windows with Git Bash. The scripts have not been run on Linux or macOS.

## 0. Prerequisites

- Node 18 or later (measured with 24.14)
- circom 2.x on the path (measured with 2.2.3)
- a Rust toolchain (measured with rustc 1.94.0)
- 32 GB of memory and about 20 GB of free disk for step 6
- Internet on the first run. The scripts download npm packages, cargo
  dependencies, the folding library sonobe at revision 9414c45, and
  powers-of-tau files from the PSE Perpetual Powers of Tau bucket
  (`https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/`).
  `ppot_0080_17.ptau` (151 MB) serves the recording circuit and
  `ppot_0080_18.ptau` (302 MB) the two-tag boundary circuit. A local copy
  can be passed with `PTAU_SRC=<file>`. `ppot_0080_21.ptau` (2.4 GB,
  sha256 `b4131202088141088d83fc05d654a142b51117df0960568613069e0719e7645a`)
  is needed only for step 5 and is downloaded by hand.

```bash
npm install
```

## 1. Recording circuit: sizes, setup, proving time

```bash
bash harness/bench_rec.sh            # FORCE=1 rebuilds, RUNS=5 repeats each proof five times
```

Prints the constraint counts at SMT depth 16, 64 and 128 (expect 30,233 /
54,425 / 86,681), then setup, witness, proving and verification times and
the proof size at depth 64 (expect a proof in 1.9 to 2.5 s, 256 bytes of
calldata), and the peak memory of the prover on Windows (expect about
1.9 GB). It writes the Solidity verifier used by the next two steps. All
output lands in `out/rec/`.

```bash
circom circuits/rec/test/c_cred_only.circom --r1cs -o out/rec -l node_modules/circomlib/circuits
```

Counts the credential check alone, check 1 of the recording statement.
Expect 9,153 non-linear constraints, 16.8% of the circuit at depth 64.

## 2. Recording tests

```bash
bash harness/run_all.sh              # 6 to 12 minutes
```

Runs the paper's worked example, the liquidation and withdrawal variants,
the concurrency test, 67 negative cases, two tags on two chains, and a
repay under another tag after a revocation, all with real proofs against
the contract on an in-process EVM. After every transaction the harness
compares every contract root with an independent implementation. Expect
`ALL RECORDING-SIDE TESTS PASSED`. The runs rewrite the ledgers in
`fixtures/`, which step 4 reads.

## 3. Gas

```bash
node harness/gas_record.js           # real proofs: every contract function
node harness/gas_sweep.js 1024       # cost against tree occupancy, about 25 minutes
```

Expect `record` at 1,759,796 to 1,799,689 gas, of which 237,876 is proof
verification. A call that carries a proof varies by a few tens of gas from
run to run, because the proof bytes are random. The sweep fills the trees
up to 1,023 nullifiers and 128 position entries and prints the cost of
`insertNullifiers` and `recordPassive` at each size.

## 4. Filing: circuits, fold driver, tests, benchmarks

```bash
bash filing/run_all.sh               # about 2 hours
```

In order, the script

1. compiles the step circuit and the two-tag boundary circuit and sets up
   the boundary key (`filing/build_circuits.sh`). Expect 32,604 and
   148,697 constraints.
2. clones the folding library at the pinned revision, applies
   `folding/basecase_z0.patch` and builds the fold driver
   (`folding/setup_filing_fold.sh`). `SONOBE_SRC=<clone at rev 9414c45>`
   skips the clone.
3. runs the witness-level tests, the worked example with its liquidation
   and withdrawal variants, two tags on two chains, the ledgers written by
   the recording side, a tag added in a later year, and 20 negative cases,
   each with a real fold and a real boundary proof. For the worked example
   expect `D = (9600, 9000, 600)`.
4. folds 128 and 1,024 steps with both frontends (`bench_fold.sh`) and
   measures the boundary proof (`bench_boundary.sh`). Expect 0.9 to 1.0 s
   per step with `--cached-witness`, 1.2 to 1.3 s without, and a boundary
   proof in 3.7 to 4.2 s.

Logs go to `filing/logs/`. The same, step by step:

```bash
bash filing/build_circuits.sh        # c_fstep (--O0), c_boundary = Boundary(2, 64) (--O2), boundary zkey + vkey, gadget test circuits
bash folding/setup_filing_fold.sh    # applies basecase_z0.patch, builds filing_fold inside folding/sonobe
cd filing
node consts.js --check               # constants hard-coded in c_boundary_core.circom
node test_smt_isold0.js              # path gadgets, isOld0 proof of concept
node test_witness.js all             # every step + boundary witness vs the JS reference (witness level)
node test_fixtures.js                # the recording side's fixtures
node test_edge.js                    # zero-length ledger, new tag, skipped period
node e2e.js worked-open              # worked example, three filings, real proofs
node e2e.js worked-liquidation
node e2e.js worked-withdrawal
node e2e.js two-tags
node e2e.js fixture:two_chains       # real folds of ledgers of the recording side
node e2e.js fixture:revoked_repay
node e2e.js tag-added                # a tag added in a later year, real proofs
node negative.js                     # negative tests
node e2e.js synthetic-100            # 128 steps, end to end
node e2e.js synthetic-1000           # 1024 steps, end to end
bash bench_fold.sh all               # fold timings, 128 and 1024 steps, both frontends
bash bench_boundary.sh sizes         # Boundary(NT, D) constraint counts
bash bench_boundary.sh prove         # boundary setup / witness / prove / verify / memory
../folding/sonobe/target/release/examples/filing_fold build/runs/synthetic-100/f0_fold_input.json \
  --r1cs build/c_fstep.r1cs --wasm build/c_fstep_js/c_fstep.wasm --witness-only 20
bash bench_boundary16.sh compile     # Boundary(16, 64): r1cs + wasm
bash bench_boundary16.sh witness     # 16 tags at witness level + snarkjs wtns check
cd ..
```

The state commitment of the step circuit alone, from `filing/`:

```bash
circom ../circuits/filing/test/state_open.circom --r1cs --O0 -o build/test -l node_modules/circomlib/circuits
circom ../circuits/filing/test/pins_open.circom --r1cs --O0 -o build/test -l node_modules/circomlib/circuits
```

Expect 1,014 non-linear constraints for the two hashes that open and
re-commit the state and 420 for the hash of the pinned values, together
4.4% of the step circuit.

The negative case `fold-starts-elsewhere` compares with a driver built
WITHOUT the start-state constraint if it finds one at
`filing/build/bin/filing_fold_unpatched(.exe)` (or `$FILING_FOLD_UNPATCHED`).
To make it: build the driver once before `basecase_z0.patch` is applied
(comment the `git apply` line of `setup_filing_fold.sh` on a fresh clone)
and copy the binary there. Without that file the case still requires the
patched driver to reject.

`e2e.js <scenario>` writes `build/runs/<scenario>/f<k>_fold_input.json`,
`f<k>_boundary_input.json`, `f<k>_expected.json`, runs
`filing_fold <fold_input> --r1cs .. --wasm .. --out f<k>_fold_output.json`,
proves the boundary circuit with snarkjs and prints the checks. The fold
driver alone, from the repository root:

```bash
folding/sonobe/target/release/examples/filing_fold filing/build/runs/worked-open/f1_fold_input.json \
  --r1cs filing/build/c_fstep.r1cs --wasm filing/build/c_fstep_js/c_fstep.wasm --out out.json
# prints preprocess / per-step / IVC verify times, "steps = 64", "z_0 = ...", "z_n = ...",
# exit code 0 = verified, 2 = IVC verification failed
```

## 5. Boundary proof for sixteen tags

```bash
cd filing
bash bench_boundary16.sh compile
bash bench_boundary16.sh witness
bash bench_boundary16.sh prove <path to ppot_0080_21.ptau>
cd ..
```

Expect 1,155,334 constraints, a setup of about 6 minutes, a proof in 22 to
25 s with an 11 GB peak, and verification in 5 to 6 ms.

## 6. The filing proof end to end

```bash
cd folding-runner
bash run_zk_decider.sh build         # builds the runner into bin/
bash setup_filing.sh                 # one-time setup, about 5 minutes, 14.6 GB peak
bash measure_filings.sh control      # fold speed reference, about 4 minutes
bash measure_filings.sh checks       # circuit equality, tampered folds, 18 tests, about 7 minutes
bash measure_filings.sh worked two-tags sixteen     # about 11 minutes
bash measure_filings.sh synthetic-1000              # about 21 minutes
bash measure_filings.sh negatives    # four filings the authority must reject
cd ..
```

Step 6 reads the fold inputs and boundary proofs that steps 4 and 5 wrote
to `filing/build/`. The filing `sixteen` needs step 5.

For each filing the script runs the prover (`prove_filing.sh`: fold,
check of the folded proof, blinding, compression), then the authority
(`verify_filing.sh`), then `snarkjs groth16 verify` on the boundary proof
as a cross-check. Expect for every filing

- a compressing proof of 5,062,888 bytes in 71 to 79 s with a peak working
  set of 13.5 GB (14.4 GB committed),
- `AUTHORITY: filing ACCEPTED` with the compressing proof verified in
  about 0.4 s and the boundary proof in 2 to 3 ms,
- for the worked example `D = (9600, 9000, 600)`.

The 1,024-step filing folds in about 17 minutes. The runner's default
frontend compiles the step circuit's witness generator once. `FRONTEND=sonobe`
selects the folding library's own frontend, at 1.2 to 1.3 s per step.

A single filing by hand:

```bash
bash prove_filing.sh  <fold_input.json> <out_dir>
bash verify_filing.sh <out_dir> <boundary_proof.json> <boundary_public.json> <boundary_vkey.json>
```

The authority command uses the verification key `keys/fstep_vk_open.bin`
and neither the proving key nor the fold input. It checks both proofs,
the step count and the equality of the two state digests. It does not
compare the other public values of the boundary proof (tags, chain ids,
contract addresses, roots, period) with the authority's own records and
prints a note saying so.

## 7. Where each number of the paper comes from

| Paper item | Step | Printed as |
|---|---|---|
| Table 3, gas per function | 3 | `==== gas table (real proofs) ====`, sweep tables |
| share of proof verification in `record` | 3 | line `proof verification` |
| Table 4, recording circuit | 1 | lines `D=16 non-linear ...` |
| credential check, about 9,200 constraints | 1 | `c_cred_only`, line `non-linear constraints` |
| Table 4, step circuit | 4 | `build_circuits.sh`, `non-linear constraints` |
| state commitment, about 4 percent of the step circuit | 4 | `state_open` and `pins_open`, lines `non-linear constraints` |
| Table 4, boundary circuit | 4 | `bench_boundary.sh sizes` |
| Table 4, compressing circuit | 6 | `setup_filing.sh`, line `LOWMEM matrices` |
| Table 5, recording proof | 1 | section `c_rec, D=64`, `peak MB` lines |
| Table 5, fold per record | 6 | `TIME fold` in `logs/e2e_*_prove.log` |
| Table 5, compressing proof | 6 | `TIME blind + compress`, `MEM after blind + compress` |
| Table 5, boundary proof | 4 | `bench_boundary.sh prove` |
| sixteen-tag boundary proof | 5 | `bench_boundary16.sh prove` |
| proof sizes | 1, 4, 6 | `SIZE` line of the prover, snarkjs proof files |
| verification times | 6 | checks 1 and 3 in `logs/e2e_*_verify.log` |
| worked example totals | 2, 4, 6 | `D = (9600, 9000, 600)` |

`RESULTS.md` gives the measured value for each line.

## Known pitfalls

- The step circuit must be compiled with `--O0`. circom's optimized wire
  map breaks the arkworks circom reader and the folded relation fails
  without an error message.
- The boundary circuit is compiled with `--O2`. With circom's default the
  linear constraints stay in the constraint system and the circuit does
  not fit a 2^18 powers-of-tau file.
- The folding library is pinned at revision 9414c45. Later revisions do
  not build or dropped the circom frontend.
- A failed assertion in the step circuit does not stop the fold. The fold
  runs through and the verification of the folded proof fails at the end,
  so every script verifies it.
- Do not run two provers of the compressing proof at once. Each commits
  14.4 GB.
- The setup of step 6 writes 16.5 GB to `folding-runner/tmp/`. The whole
  directory is scratch and can be deleted.
