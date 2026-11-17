#!/usr/bin/env bash
# Fold timings: the 128-step and the
# 1024-step synthetic runs, each with sonobe's own circom frontend (the
# default) and with the driver's cached witness calculator, ONE RUN AT A TIME.
# The machine state (CPU load, free memory) is printed before and after each.
#   bash filing/bench_fold.sh 128      the two 128-step runs
#   bash filing/bench_fold.sh 1024     the two 1024-step runs
#   bash filing/bench_fold.sh all      all four (about 50 minutes)
# Prereq: build_circuits.sh, setup_filing_fold.sh, and the fold inputs
# (node e2e.js synthetic-100 --gen-only; node e2e.js synthetic-1000 --gen-only).
set -e
cd "$(dirname "$0")"
EXE=""; [ -f ../folding/sonobe/target/release/examples/filing_fold.exe ] && EXE=".exe"
FOLD=../folding/sonobe/target/release/examples/filing_fold$EXE
ARGS="--r1cs build/c_fstep.r1cs --wasm build/c_fstep_js/c_fstep.wasm"
mkdir -p logs

machine() {
  powershell -NoProfile -Command "\$o=Get-CimInstance Win32_OperatingSystem; 'machine: CPU load ' + (Get-CimInstance Win32_Processor).LoadPercentage + ' %, free memory ' + [math]::Round(\$o.FreePhysicalMemory/1024) + ' MB, ' + (Get-Date -Format 'HH:mm:ss')"
}
run() {   # run <scenario> <steps> <stock|cached>
  local sc=$1 n=$2 fe=$3 flag=""
  [ "$fe" = "cached" ] && flag="--cached-witness"
  local in=build/runs/$sc/f0_fold_input.json
  [ -f $in ] || node e2e.js $sc --gen-only > /dev/null
  echo "== fold $n steps, frontend: $fe"
  machine
  $FOLD $in $ARGS --out build/runs/$sc/f0_fold_output_final_$fe.json $flag > logs/fold${n}_$fe.log 2>&1 || echo "  exit code $?"
  grep -E "^(frontend|preprocess|augmented|init|folded|IVC verify|steps =|z_n equals|peak)" logs/fold${n}_$fe.log | sed 's/^/  /'
  machine
}

case "$1" in
128)  run synthetic-100 128 stock; run synthetic-100 128 cached ;;
1024) run synthetic-1000 1024 stock; run synthetic-1000 1024 cached ;;
all)  run synthetic-100 128 stock; run synthetic-100 128 cached
      run synthetic-1000 1024 stock; run synthetic-1000 1024 cached ;;
*)    echo "usage: bash filing/bench_fold.sh 128|1024|all" ;;
esac
