#!/usr/bin/env bash
# Boundary circuit measurements (SPEC.md section 9, filing part).
#   bash filing/bench_boundary.sh sizes    constraint counts of Boundary(NT, D)
#                                          for NT in {1,2,4,8,16} at D = 64 and
#                                          NT = 2 at D in {16, 128} (compile only)
#   bash filing/bench_boundary.sh prove    Boundary(2, 64) on the 2026 filing of
#                                          the worked example: setup time and key
#                                          size, then 5 runs each of witness and
#                                          prove (time and peak working set),
#                                          verification, proof size
# Prereq: bash filing/build_circuits.sh, and for `prove` a run of
#         node filing/e2e.js worked-open --gen-only (writes the input).
# Run it alone: the machine state is printed with the timings.
set -e
cd "$(dirname "$0")"
LIB="-l node_modules/circomlib/circuits -l ../circuits/filing"
SNARKJS="node node_modules/snarkjs/cli.js"
PUB="{public [z0, zn, tags, cid, acaddr, root_rcl, root_unl, root_at, root_psl, y, d_proceeds, d_cost, d_income, c_prev, c_y, closing]}"

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

if [ "$1" = "sizes" ]; then
  mkdir -p build/sizes
  for cfg in "1 64" "2 64" "4 64" "8 64" "16 64" "2 16" "2 128"; do
    set -- $cfg; nt=$1; d=$2
    f=build/sizes/c_boundary_nt${nt}_d${d}.circom
    printf 'pragma circom 2.0.0;\ninclude "c_boundary_core.circom";\ncomponent main %s = Boundary(%s, %s);\n' "$PUB" "$nt" "$d" > $f
    out=$(circom $f --r1cs --O2 -o build/sizes $LIB | grep -E "non-linear constraints")
    echo "Boundary(NT=$nt, D=$d): $out"
    rm -f build/sizes/c_boundary_nt${nt}_d${d}.r1cs
  done
  exit 0
fi

if [ "$1" = "prove" ]; then
  IN=build/runs/worked-open/f1_boundary_input.json
  [ -f $IN ] || { echo "missing $IN: run node e2e.js worked-open --gen-only"; exit 1; }
  machine
  echo "== Groth16 setup of Boundary(2, 64) (development key, no contribution)"
  timed "setup" node node_modules/snarkjs/cli.js groth16 setup build/c_boundary.r1cs build/pot18_final.ptau build/c_boundary_bench.zkey
  mem "setup" node node_modules/snarkjs/cli.js groth16 setup build/c_boundary.r1cs build/pot18_final.ptau build/c_boundary_bench.zkey
  echo "  proving key: $(wc -c < build/c_boundary_bench.zkey) bytes; identical to build/c_boundary.zkey: $(cmp -s build/c_boundary_bench.zkey build/c_boundary.zkey && echo yes || echo no)"
  rm -f build/c_boundary_bench.zkey
  echo "== witness generation, 5 runs"
  for run in 1 2 3 4 5; do
    timed "witness (run $run)" node build/c_boundary_js/generate_witness.js build/c_boundary_js/c_boundary.wasm $IN build/c_boundary.wtns
  done
  mem "witness" node build/c_boundary_js/generate_witness.js build/c_boundary_js/c_boundary.wasm $IN build/c_boundary.wtns
  echo "== prove, 5 runs"
  for run in 1 2 3 4 5; do
    timed "prove (run $run)" node node_modules/snarkjs/cli.js groth16 prove build/c_boundary.zkey build/c_boundary.wtns build/c_boundary.proof.json build/c_boundary.public.json
  done
  for run in 1 2 3 4 5; do
    mem "prove (run $run)" node node_modules/snarkjs/cli.js groth16 prove build/c_boundary.zkey build/c_boundary.wtns build/c_boundary.proof.json build/c_boundary.public.json
  done
  machine
  echo "== verify"
  for run in 1 2 3; do
    t0=$(date +%s%3N); $SNARKJS groth16 verify build/c_boundary.vkey.json build/c_boundary.public.json build/c_boundary.proof.json > /dev/null; t1=$(date +%s%3N)
    echo "  verify as a command-line call incl. node start-up (run $run): $(( t1 - t0 )) ms"
  done
  node -e '
    const snarkjs = require("snarkjs"); const fs = require("fs");
    (async () => {
      const vk = JSON.parse(fs.readFileSync("build/c_boundary.vkey.json"));
      const pub = JSON.parse(fs.readFileSync("build/c_boundary.public.json"));
      const proof = JSON.parse(fs.readFileSync("build/c_boundary.proof.json"));
      await snarkjs.groth16.verify(vk, pub, proof);            // warm-up (curve init)
      const ts = [];
      for (let i = 0; i < 5; i++) { const t0 = performance.now(); const ok = await snarkjs.groth16.verify(vk, pub, proof); ts.push(performance.now() - t0); if (!ok) throw new Error("verify false"); }
      console.log("  verify, in process after warm-up (5 runs): " + ts.map((t) => t.toFixed(1)).join(", ") + " ms -> true");
      console.log("  proof size: " + fs.statSync("build/c_boundary.proof.json").size + " bytes (json), public signals: " + pub.length);
      process.exit(0);
    })();'
  echo "  proving key build/c_boundary.zkey: $(wc -c < build/c_boundary.zkey) bytes"
  exit 0
fi
echo "usage: bash filing/bench_boundary.sh sizes|prove"
