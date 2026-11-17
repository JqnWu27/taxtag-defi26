#!/usr/bin/env bash
# Boundary(16, 64): the boundary circuit for the full depth-4 ledger tree
# (16 tag slots, 2 chains, SMT depth 64; 1,155,334 constraints with --O2).
#
#   bash filing/bench_boundary16.sh compile
#       r1cs + wasm of circuits/filing/c_boundary16.circom into filing/build
#       (no powers-of-tau file needed)
#   bash filing/bench_boundary16.sh witness
#       the 16-tag scenario at witness level: node test_sixteen.js --fold, then
#       `snarkjs wtns check` of the boundary witness against the R1CS
#       (no powers-of-tau file needed)
#   bash filing/bench_boundary16.sh prove <2^21 powers-of-tau file, phase-2 prepared>
#       Groth16 setup, witness, 3 proofs, verification of the 16-tag scenario;
#       prints time, peak memory, key size and proof size.
#       Needs a 2^21 powers-of-tau file (2^20 = 1,048,576 is below the
#       1,155,334 constraints). Run `witness` first (it writes the input).
#   DRY=1 bash filing/bench_boundary16.sh prove <pot18 file>
#       the same `prove` flow on Boundary(2, 64) and the two-tag scenario, to
#       check this script without the large file.
#
# Measured on the reference laptop, 2026-11-11, machine idle (CPU load 1 %,
# 16.1 GB free), with ppot_0080_21.ptau (2,416,012,434 bytes):
#   setup 334 s, peak 8.0 GB, proving key 732,841,776 bytes;
#   witness 1.5 s, peak 0.27 GB; proof 23.4 to 25.0 s, peak 11.0 GB;
#   verification 5 to 6 ms in process; proof 803 bytes of JSON, 37 public
#   signals. Run it alone: the prover needs 11 GB of free memory.
set -e
cd "$(dirname "$0")"
LIB="-l node_modules/circomlib/circuits -l ../circuits/filing"
SNARKJS="node --max-old-space-size=12288 node_modules/snarkjs/cli.js"

NAME=c_boundary16
RUN=build/runs/sixteen-tags
IN=$RUN/boundary_input.json
OUT=build/bench16
if [ -n "$DRY" ]; then
  NAME=c_boundary
  RUN=build/runs/two-tags-two-chains
  IN=$RUN/f0_boundary_input.json
  OUT=build/bench16_dry
fi

machine() {
  powershell -NoProfile -Command "\$o=Get-CimInstance Win32_OperatingSystem; 'machine: CPU load ' + (Get-CimInstance Win32_Processor).LoadPercentage + ' %, free memory ' + [math]::Round(\$o.FreePhysicalMemory/1024) + ' MB'"
}
# timed <label> <exe> <args...>: wall time of one command, run directly
# (the command's own output goes to build/last_timed.log)
timed() {
  local label=$1; shift
  local t0=$(date +%s%3N)
  "$@" > build/last_timed.log 2>&1 || echo "  ($label: exit code $?)"
  local t1=$(date +%s%3N)
  echo "  $label: $(( t1 - t0 )) ms"
}
# mem <label> <exe> <args...>: peak working set of one command, run under the
# polling wrapper measure_mem.ps1 (its start-up adds about 0.3 s, so times
# are taken with timed, not here)
mem() {
  local label=$1; shift
  powershell -NoProfile -ExecutionPolicy Bypass -File measure_mem.ps1 "$label" "$@" > build/last_mem.log 2>&1 || true
  echo "  $label: peak working set $(grep "peak MB" build/last_mem.log | sed 's/.*peak MB: //') MB"
}

case "$1" in
compile)
  machine
  t0=$(date +%s%3N)
  circom ../circuits/filing/c_boundary16.circom --r1cs --wasm --O2 -o build $LIB \
    | grep -E "non-linear|linear constraints|public inputs|private inputs|wires"
  t1=$(date +%s%3N)
  echo "  compile $(( t1 - t0 )) ms; r1cs $(du -h build/c_boundary16.r1cs | cut -f1), wasm $(du -h build/c_boundary16_js/c_boundary16.wasm | cut -f1)"
  ;;
witness)
  machine
  node test_sixteen.js --fold
  echo "== snarkjs wtns check (every R1CS constraint of Boundary(16, 64) against the witness)"
  t0=$(date +%s%3N)
  mem "wtns check" node --max-old-space-size=12288 node_modules/snarkjs/cli.js wtns check build/c_boundary16.r1cs $RUN/boundary16.wtns
  t1=$(date +%s%3N)
  echo "  wtns check: $(( t1 - t0 )) ms"
  grep -E "WITNESS|ERROR|Error" build/last_mem.log | sed 's/\x1b\[[0-9;]*m//g' | tail -3
  ;;
prove)
  PTAU=$2
  [ -f "$PTAU" ] || { echo "usage: bash filing/bench_boundary16.sh prove <2^21 powers-of-tau file>"; exit 1; }
  [ -f build/$NAME.r1cs ] || { echo "missing build/$NAME.r1cs: run 'compile' first"; exit 1; }
  [ -f $IN ] || { echo "missing $IN: run 'witness' first"; exit 1; }
  mkdir -p $OUT
  machine
  echo "== $NAME: Groth16 setup (development key, no contribution)"
  t0=$(date +%s%3N)
  mem "setup" node --max-old-space-size=12288 node_modules/snarkjs/cli.js groth16 setup build/$NAME.r1cs "$PTAU" $OUT/$NAME.zkey
  t1=$(date +%s%3N)
  echo "  setup: $(( t1 - t0 )) ms (the memory wrapper adds about 0.3 s)"
  [ -f $OUT/$NAME.zkey ] || { echo "setup produced no key:"; tail -5 build/last_mem.log; exit 1; }
  $SNARKJS zkey export verificationkey $OUT/$NAME.zkey $OUT/$NAME.vkey.json > /dev/null
  echo "  proving key: $(wc -c < $OUT/$NAME.zkey) bytes"
  echo "== witness"
  timed "witness" node build/${NAME}_js/generate_witness.js build/${NAME}_js/$NAME.wasm $IN $OUT/$NAME.wtns
  mem "witness" node build/${NAME}_js/generate_witness.js build/${NAME}_js/$NAME.wasm $IN $OUT/$NAME.wtns
  echo "== prove"
  for run in 1 2 3; do
    machine
    timed "prove (run $run)" node --max-old-space-size=12288 node_modules/snarkjs/cli.js groth16 prove $OUT/$NAME.zkey $OUT/$NAME.wtns $OUT/proof.json $OUT/public.json
  done
  mem "prove" node --max-old-space-size=12288 node_modules/snarkjs/cli.js groth16 prove $OUT/$NAME.zkey $OUT/$NAME.wtns $OUT/proof.json $OUT/public.json
  echo "== verify"
  $SNARKJS groth16 verify $OUT/$NAME.vkey.json $OUT/public.json $OUT/proof.json | tail -1
  OUT=$OUT NAME=$NAME node -e '
    const snarkjs = require("snarkjs"); const fs = require("fs");
    const o = process.env.OUT, n = process.env.NAME;
    (async () => {
      const vk = JSON.parse(fs.readFileSync(`${o}/${n}.vkey.json`));
      const pub = JSON.parse(fs.readFileSync(`${o}/public.json`));
      const proof = JSON.parse(fs.readFileSync(`${o}/proof.json`));
      await snarkjs.groth16.verify(vk, pub, proof);
      const ts = [];
      for (let i = 0; i < 5; i++) { const t0 = performance.now(); const ok = await snarkjs.groth16.verify(vk, pub, proof); ts.push(performance.now() - t0); if (!ok) throw new Error("verify false"); }
      console.log("  verify, in process after warm-up: " + ts.map((t) => t.toFixed(1)).join(", ") + " ms -> true");
      console.log("  proof size: " + fs.statSync(`${o}/proof.json`).size + " bytes (json), public signals: " + pub.length);
      process.exit(0);
    })();'
  if [ -z "$DRY" ]; then
    echo "== negative with a real key: one of the 16 tags dropped"
    node --max-old-space-size=12288 test_sixteen.js --forced $OUT/$NAME.zkey $OUT/$NAME.vkey.json | grep -E "^== 3|REJECTED|forced|ALL OK|FAILED"
  fi
  ;;
*)
  echo "usage: bash filing/bench_boundary16.sh compile | witness | prove <ptau>"
  ;;
esac
