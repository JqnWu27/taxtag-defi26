#!/usr/bin/env bash
# TaxTag recording circuit: build and benchmark (Groth16 / BN254, circom +
# snarkjs). Git-Bash compatible (no /usr/bin/time).
#
#   bash harness/bench_rec.sh            build what is missing, then benchmark
#   FORCE=1 bash harness/bench_rec.sh    recompile and redo the trusted setup
#   RUNS=5  bash harness/bench_rec.sh    number of timed prove runs (default 3)
#   WITH_O2=1 bash harness/bench_rec.sh  also measure the --O2 compilation
#
# Prints: constraint counts at D = 16, 64, 128; setup, witness, prove and
# verify times at D = 64 for a first record and a later record; proof size;
# peak prover memory (Windows only, via measure_mem.ps1).
set -e
cd "$(dirname "$0")/.."
command -v node >/dev/null || { echo "node required"; exit 1; }
command -v circom >/dev/null || [ -d node_modules/circom2 ] || {
  echo "circom not found -- run from GIT BASH (PowerShell's bash is WSL here)"; exit 1; }
[ -d node_modules/snarkjs ] || npm install

PTAU_POWER=17
PTAU=pot${PTAU_POWER}_final.ptau
LIB="-l node_modules/circomlib/circuits -l circuits/rec"
OUT=out/rec
RUNS=${RUNS:-3}
SNARKJS="node node_modules/snarkjs/build/cli.cjs"
if command -v circom >/dev/null; then CIRCOM="circom"; else CIRCOM="npx circom2"; fi
mkdir -p $OUT

now() { date +%s%3N; }
step() {  # step <label> <cmd...>   prints the wall time of one command
  local label=$1; shift
  local t0=$(now)
  "$@" > /dev/null
  local t1=$(now)
  echo "  $label $(( t1 - t0 )) ms"
}

echo "== toolchain: $($CIRCOM --version), snarkjs $(node -p "require('./node_modules/snarkjs/package.json').version"), node $(node --version)"

# 1) compile at the shipped depth (D=64) and count constraints at D=16, 128
if [ -n "$FORCE" ] || [ ! -f $OUT/c_rec.r1cs ] || [ ! -f $OUT/c_rec_js/c_rec.wasm ]; then
  echo "== compiling c_rec (D=64)"
  $CIRCOM circuits/rec/c_rec.circom --r1cs --wasm -o $OUT $LIB > $OUT/compile_d64.txt
fi
echo "== constraint counts (non-linear / linear, circom default optimisation)"
for d in 16 64 128; do
  f=c_rec; [ $d != 64 ] && f=c_rec_d$d
  if [ -n "$FORCE" ] || [ ! -f $OUT/compile_d$d.txt ]; then
    $CIRCOM circuits/rec/$f.circom --r1cs -o $OUT $LIB > $OUT/compile_d$d.txt
  fi
  nl=$(grep "non-linear constraints" $OUT/compile_d$d.txt | grep -o "[0-9]*")
  li=$(grep "^linear constraints" $OUT/compile_d$d.txt | grep -o "[0-9]*")
  echo "  D=$d  non-linear $nl  linear $li"
done

# 2) powers of tau, 2^17: local file, else $PTAU_SRC, else download (151 MB)
#    from the Perpetual Powers of Tau bucket of PSE (round 80).
if [ ! -f $PTAU ]; then
  if [ -n "$PTAU_SRC" ] && [ -f "$PTAU_SRC" ]; then cp "$PTAU_SRC" $PTAU; else
    curl -fL -o $PTAU.tmp \
      https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_${PTAU_POWER}.ptau
    mv $PTAU.tmp $PTAU
  fi
fi

# 3) trusted setup and Solidity verifier (deterministic: no contribution)
if [ -n "$FORCE" ] || [ ! -f $OUT/c_rec.zkey ]; then
  echo "== setup"
  step "setup   " $SNARKJS groth16 setup $OUT/c_rec.r1cs $PTAU $OUT/c_rec.zkey
  $SNARKJS zkey export verificationkey $OUT/c_rec.zkey $OUT/c_rec.vkey.json > /dev/null
  $SNARKJS zkey export solidityverifier $OUT/c_rec.zkey $OUT/Verifier_c_rec.sol > /dev/null
fi
echo "  zkey: $(du -h $OUT/c_rec.zkey | cut -f1)"

# 4) witness inputs (no chain needed)
node harness/gen_input.js

# 5) witness, prove (RUNS times), verify -- timed
for v in first next; do
  echo "== c_rec, D=64, $v record"
  step "witness " node $OUT/c_rec_js/generate_witness.js $OUT/c_rec_js/c_rec.wasm \
       $OUT/input_c_rec_$v.json $OUT/c_rec_$v.wtns
  for r in $(seq 1 $RUNS); do
    step "prove   " $SNARKJS groth16 prove $OUT/c_rec.zkey $OUT/c_rec_$v.wtns \
         $OUT/c_rec_$v.proof.json $OUT/c_rec_$v.public.json
  done
  step "verify  " $SNARKJS groth16 verify $OUT/c_rec.vkey.json \
       $OUT/c_rec_$v.public.json $OUT/c_rec_$v.proof.json
  $SNARKJS groth16 verify $OUT/c_rec.vkey.json $OUT/c_rec_$v.public.json \
       $OUT/c_rec_$v.proof.json | grep -o "OK!" | sed 's/^/  verify result: /'
  echo "  proof size: $(wc -c < $OUT/c_rec_$v.proof.json) bytes (json);" \
       "256 bytes as calldata (8 words), $(( $(grep -o '"[0-9]*"' $OUT/c_rec_$v.public.json | wc -l) )) public inputs"
done

# 6) peak prover memory (working set of the snarkjs prove process)
if command -v powershell >/dev/null && [ -f measure_mem.ps1 ]; then
  echo "== peak memory, groth16 prove, D=64"
  for v in first next; do
    powershell -NoProfile -ExecutionPolicy Bypass -File measure_mem.ps1 "c_rec prove ($v)" node \
      node_modules/snarkjs/build/cli.cjs groth16 prove $OUT/c_rec.zkey $OUT/c_rec_$v.wtns \
      $OUT/mem_proof.json $OUT/mem_public.json | grep "peak MB" | sed 's/^/  /'
  done
fi

# 7) optional: the same circuit compiled with full simplification (--O2)
if [ -n "$WITH_O2" ]; then
  echo "== c_rec, D=64, compiled --O2 (linear constraints eliminated)"
  mkdir -p $OUT/o2
  $CIRCOM circuits/rec/c_rec.circom --O2 --r1cs --wasm -o $OUT/o2 $LIB > $OUT/o2/compile.txt
  echo "  non-linear $(grep 'non-linear constraints' $OUT/o2/compile.txt | grep -o '[0-9]*')" \
       " linear $(grep '^linear constraints' $OUT/o2/compile.txt | grep -o '[0-9]*')"
  step "setup   " $SNARKJS groth16 setup $OUT/o2/c_rec.r1cs $PTAU $OUT/o2/c_rec.zkey
  $SNARKJS zkey export verificationkey $OUT/o2/c_rec.zkey $OUT/o2/c_rec.vkey.json > /dev/null
  echo "  zkey: $(du -h $OUT/o2/c_rec.zkey | cut -f1)"
  step "witness " node $OUT/o2/c_rec_js/generate_witness.js $OUT/o2/c_rec_js/c_rec.wasm \
       $OUT/input_c_rec_next.json $OUT/o2/c_rec_next.wtns
  for r in $(seq 1 $RUNS); do
    step "prove   " $SNARKJS groth16 prove $OUT/o2/c_rec.zkey $OUT/o2/c_rec_next.wtns \
         $OUT/o2/proof.json $OUT/o2/public.json
  done
  $SNARKJS groth16 verify $OUT/o2/c_rec.vkey.json $OUT/o2/public.json $OUT/o2/proof.json \
       | grep -o "OK!" | sed 's/^/  verify result: /'
  if command -v powershell >/dev/null && [ -f measure_mem.ps1 ]; then
    powershell -NoProfile -ExecutionPolicy Bypass -File measure_mem.ps1 "c_rec --O2 prove" node \
      node_modules/snarkjs/build/cli.cjs groth16 prove $OUT/o2/c_rec.zkey $OUT/o2/c_rec_next.wtns \
      $OUT/o2/proof.json $OUT/o2/public.json | grep "peak MB" | sed 's/^/  /'
  fi
fi
echo "done."
