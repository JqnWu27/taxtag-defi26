#!/usr/bin/env bash
# Runs every filing-side build, test and benchmark, in order, except the
# Groth16 proof of Boundary(16, 64), which needs a 2^21
# powers-of-tau file: bash filing/bench_boundary16.sh prove <file>.
# Run from Git Bash in the repository root: bash filing/run_all.sh
# Optional: SONOBE_SRC=<sonobe clone at rev 9414c45>, PTAU_SRC=<2^18 ptau file>.
# Logs go to filing/logs/. About 2 hours; for the timings run it alone on an
# otherwise idle machine (the bench scripts print CPU load and free memory).
set -e
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
EX="$ROOT/folding/sonobe/target/release/examples"
bash filing/build_circuits.sh                 # circuits + boundary Groth16 key
bash folding/setup_filing_fold.sh             # start-state patch + fold driver
cd filing
mkdir -p logs
node consts.js --check
node test_smt_isold0.js                 | tee logs/test_smt_isold0.log
node test_witness.js all                | tee logs/test_witness.log
node test_fixtures.js                   | tee logs/test_fixtures.log
node test_edge.js                       | tee logs/test_edge.log
node e2e.js worked-open                 | tee logs/e2e_worked-open.log
node e2e.js worked-liquidation          | tee logs/e2e_worked-liquidation.log
node e2e.js worked-withdrawal           | tee logs/e2e_worked-withdrawal.log
node e2e.js two-tags                    | tee logs/e2e_two-tags.log
node e2e.js fixture:two_chains          | tee logs/e2e_fixture_two_chains.log
node e2e.js fixture:revoked_repay       | tee logs/e2e_fixture_revoked_repay.log
node e2e.js tag-added                   | tee logs/e2e_tag-added.log
node negative.js                        | tee logs/negative.log
node e2e.js synthetic-100               | tee logs/e2e_synthetic-100.log
node e2e.js synthetic-1000              | tee logs/e2e_synthetic-1000.log
bash bench_fold.sh all                  | tee logs/bench_fold.log
bash bench_boundary.sh sizes            | tee logs/boundary_sizes.log
bash bench_boundary.sh prove            | tee logs/boundary_prove.log
"$EX/filing_fold" build/runs/synthetic-100/f0_fold_input.json --r1cs build/c_fstep.r1cs \
  --wasm build/c_fstep_js/c_fstep.wasm --witness-only 20 | tee logs/witness_only.log
bash bench_boundary16.sh compile        | tee logs/boundary16_compile.log
bash bench_boundary16.sh witness        | tee logs/boundary16_witness.log
echo "filing side: all runs done, logs in filing/logs/"
