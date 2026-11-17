#!/usr/bin/env bash
# The end-to-end runs, one job at a time. RUN FROM GIT BASH.
#
#   bash measure_filings.sh                      # the four filings, in order
#   bash measure_filings.sh worked two-tags      # a selection of: worked two-tags sixteen synthetic-1000
#   bash measure_filings.sh checks               # same-r1cs, two tampered-input folds, the 18 tests (FULL, cached frontend)
#   bash measure_filings.sh negatives            # the authority command on four filings it must reject (needs proofs/worked)
#   bash measure_filings.sh control              # speed reference: the filing build's own fold driver (read-only, no
#                                                # output file) and the runner's fold with both frontends, 64 steps each
#
# For each filing <name>:
#   prove_filing.sh  -> proofs/<name>/decider_proof.bin, decider_public.json   log: logs/e2e_<name>_prove.log
#   verify_filing.sh -> exit code and the AUTHORITY lines                      log: logs/e2e_<name>_verify.log
#   and, if SNARKJS_CLI points to snarkjs' cli.cjs (default: the filing build's node_modules), a cross-check of
#   the boundary proof with `snarkjs groth16 verify` (read only)               log: logs/e2e_<name>_snarkjs.log
# Every log starts with the date and ends with `exit=<code>`.
# The fold inputs and boundary proofs are those of the filing build (../filing/build), read only.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$HERE"
. ./filing_env.sh
B="$FILING_BUILD"
: "${SNARKJS_CLI:=$HERE/../filing/node_modules/snarkjs/build/cli.cjs}"
mkdir -p logs proofs tmp

# name -> fold input, boundary proof, boundary public signals, boundary verification key
files_of() {
  case "$1" in
    worked)         echo "$B/runs/worked-open/f1_fold_input.json|$B/runs/worked-open/f1_boundary_proof.json|$B/runs/worked-open/f1_boundary_public.json|$B/c_boundary.vkey.json" ;;
    two-tags)       echo "$B/runs/two-tags-two-chains/f0_fold_input.json|$B/runs/two-tags-two-chains/f0_boundary_proof.json|$B/runs/two-tags-two-chains/f0_boundary_public.json|$B/c_boundary.vkey.json" ;;
    sixteen)        echo "$B/runs/sixteen-tags/fold_input.json|$B/bench16/proof.json|$B/bench16/public.json|$B/bench16/c_boundary16.vkey.json" ;;
    synthetic-1000) echo "$B/runs/synthetic-1000/f0_fold_input.json|$B/runs/synthetic-1000/f0_boundary_proof.json|$B/runs/synthetic-1000/f0_boundary_public.json|$B/c_boundary.vkey.json" ;;
    *) echo ""; ;;
  esac
}

run_logged() { # <log> <command...>
  local log="$1"; shift
  { date "+%Y-%m-%d %H:%M:%S"; echo "\$ $*"; } > "$log"
  "$@" >> "$log" 2>&1
  local code=$?
  echo "exit=$code" >> "$log"
  return $code
}

one_filing() {
  local name="$1" spec; spec="$(files_of "$name")"
  [ -n "$spec" ] || { echo "unknown filing: $name"; return 2; }
  IFS='|' read -r fin bproof bpub bvk <<< "$spec"
  for f in "$fin" "$bproof" "$bpub" "$bvk"; do [ -f "$f" ] || { echo "$name: missing $f"; return 2; }; done
  echo "== $name: prove ($(date +%H:%M:%S))"
  run_logged "logs/e2e_${name}_prove.log" bash prove_filing.sh "$fin" "proofs/$name"
  echo "   exit=$?"; grep -E "^(TIME fold|TIME blind|MEM after|SIZE|MACHINE)" "logs/e2e_${name}_prove.log" | sed 's/^/   /'
  echo "== $name: verify ($(date +%H:%M:%S))"
  run_logged "logs/e2e_${name}_verify.log" bash verify_filing.sh "proofs/$name" "$bproof" "$bpub" "$bvk"
  echo "   exit=$?"; grep -E "^(AUTHORITY|D =|C_y|MACHINE|MEM)" "logs/e2e_${name}_verify.log" | sed 's/^/   /'
  if [ -f "$SNARKJS_CLI" ]; then
    run_logged "logs/e2e_${name}_snarkjs.log" node "$SNARKJS_CLI" groth16 verify "$bvk" "$bpub" "$bproof"
    echo "   snarkjs groth16 verify (boundary proof): exit=$? $(grep -o 'OK!\|Invalid proof' "logs/e2e_${name}_snarkjs.log" | head -1)"
  fi
}

expect_reject() { # <label> <log> <verify args...>
  local label="$1" log="$2"; shift 2
  run_logged "$log" bash verify_filing.sh "$@"
  local code=$?
  local why; why="$(grep -E "FAILED|MALFORMED" "$log" | head -3 | tr '\n' ';')"
  if [ $code -ne 0 ] && grep -q "AUTHORITY: filing REJECTED" "$log"; then
    echo "NEGATIVE ok   (rejected, exit=$code): $label  [$why]"
  else
    echo "NEGATIVE FAIL (exit=$code): $label"; NEG_FAIL=1
  fi
}

negatives() {
  [ -f proofs/worked/decider_proof.bin ] || { echo "run the worked example first: bash measure_filings.sh worked"; return 2; }
  IFS='|' read -r fin bproof bpub bvk <<< "$(files_of worked)"
  IFS='|' read -r fin2 bproof2 bpub2 bvk2 <<< "$(files_of two-tags)"
  NEG_FAIL=0
  mkdir -p tmp/neg/a tmp/neg/c   # files in it are overwritten
  # 1: another filing's (valid) boundary proof with this compressing proof
  expect_reject "boundary proof of another filing (two-tags) with the worked example's compressing proof" \
    logs/e2e_neg1_other_boundary.log proofs/worked "$bproof2" "$bpub2" "$bvk2"
  # 2: one byte of the compressing proof changed (inside the opened witness)
  cp proofs/worked/decider_public.json tmp/neg/a/
  python -c "
import sys
b = bytearray(open(sys.argv[1], 'rb').read()); b[1000000] ^= 1; open(sys.argv[2], 'wb').write(bytes(b))" \
    proofs/worked/decider_proof.bin tmp/neg/a/decider_proof.bin
  expect_reject "one bit of the compressing proof flipped" logs/e2e_neg2_proof_bit.log tmp/neg/a "$bproof" "$bpub" "$bvk"
  # 3: D changed in the boundary public signals (proceeds + 1)
  python -c "
import sys, json
p = json.load(open(sys.argv[1])); L = len(p); p[L-6] = str(int(p[L-6]) + 1); json.dump(p, open(sys.argv[2], 'w'))" \
    "$bpub" tmp/neg/b_public.json
  expect_reject "D (proceeds) increased by 1 in the boundary public signals" logs/e2e_neg3_D_changed.log proofs/worked "$bproof" tmp/neg/b_public.json "$bvk"
  # 4: another step count claimed
  cp proofs/worked/decider_proof.bin tmp/neg/c/
  python -c "
import sys, json
p = json.load(open(sys.argv[1])); p['i'] = str(int(p['i']) * 2); json.dump(p, open(sys.argv[2], 'w'))" \
    proofs/worked/decider_public.json tmp/neg/c/decider_public.json
  expect_reject "step count doubled in the public values" logs/e2e_neg4_step_count.log tmp/neg/c "$bproof" "$bpub" "$bvk"
  [ "$NEG_FAIL" = 0 ] && echo "NEGATIVES: all four rejected" || { echo "NEGATIVES: FAILURE"; return 1; }
}

checks() {
  IFS='|' read -r fin bproof bpub bvk <<< "$(files_of worked)"
  echo "== same-r1cs"
  run_logged logs/e2e_same_r1cs.log "$RUNNER" --mode same-r1cs "${STEP_ARGS[@]}"
  echo "   exit=$?"; grep "^SAME-R1CS" logs/e2e_same_r1cs.log | sed 's/^/   /'
  echo "== tampered-input folds"
  # external input 25 = amount_in of the record of step 0; 5 = the accumulated proceeds of the state opened at step 3
  run_logged logs/e2e_tamper_record_amount.log "$RUNNER" --mode tamper "${STEP_ARGS[@]}" --input "$fin" --tamper-step 0 --tamper-index 25
  echo "   exit=$?"; grep "^TAMPER" logs/e2e_tamper_record_amount.log | sed 's/^/   /'
  run_logged logs/e2e_tamper_state_proceeds.log "$RUNNER" --mode tamper "${STEP_ARGS[@]}" --input "$fin" --tamper-step 3 --tamper-index 5
  echo "   exit=$?"; grep "^TAMPER" logs/e2e_tamper_state_proceeds.log | sed 's/^/   /'
  echo "== the 18 rejection and freshness tests, FULL circuit, cached frontend ($(date +%H:%M:%S))"
  run_logged logs/e2e_tests18_cached.log "$RUNNER" --mode "$FORMAT" "${STEP_ARGS[@]}" --lowmem \
    --matrices "$MATRICES" --keys "$PROVING_KEY" --input "$fin" --boundary-public "$bpub"
  echo "   exit=$?"; grep -E "^(TEST|TESTS|TIME|MEM|MACHINE|LINK)" logs/e2e_tests18_cached.log | sed 's/^/   /'
}

control() {
  IFS='|' read -r fin bproof bpub bvk <<< "$(files_of worked)"
  local drv="$HERE/../folding/sonobe/target/release/examples/filing_fold$EXE"
  if [ -x "$drv" ]; then
    echo "== control: the filing build's own driver, --cached-witness, no output file ($(date +%H:%M:%S))"
    run_logged logs/e2e_control_filing_driver_cached.log "$drv" "$fin" --r1cs "$STEP_R1CS" --wasm "$STEP_WASM" --cached-witness
    echo "   exit=$?"; grep -E "^folded|^IVC|^peak" logs/e2e_control_filing_driver_cached.log | sed 's/^/   /'
  fi
  for fe in cached sonobe; do
    echo "== control: runner, --frontend $fe ($(date +%H:%M:%S))"
    run_logged "logs/e2e_control_runner_${fe}.log" "$RUNNER" --mode fold --ext-len 117 --frontend $fe \
      --r1cs "$STEP_R1CS" --wasm "$STEP_WASM" --params "$NOVA_PARAMS" --input "$fin"
    echo "   exit=$?"; grep -E "^(TIME fold|IVC|MEM|MACHINE)" "logs/e2e_control_runner_${fe}.log" | sed 's/^/   /'
  done
}

[ $# -gt 0 ] || set -- worked two-tags sixteen synthetic-1000
for target in "$@"; do
  case "$target" in
    checks) checks ;;
    negatives) negatives ;;
    control) control ;;
    *) one_filing "$target" ;;
  esac
done
