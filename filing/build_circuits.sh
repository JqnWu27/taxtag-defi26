#!/usr/bin/env bash
# Compiles the filing circuits and sets up the boundary circuit's Groth16
# key. Run from Git Bash: bash filing/build_circuits.sh
#   build/c_fstep.r1cs, build/c_fstep_js/        step circuit, --O0 (REQUIRED:
#       circom's simplified wire map breaks the arkworks circom reader)
#   build/c_boundary.r1cs, build/c_boundary_js/  Boundary(NT=2, D=64), --O2
#   build/c_boundary.zkey, build/c_boundary.vkey.json   (development setup,
#       no contribution)
set -e
cd "$(dirname "$0")"
command -v circom >/dev/null || { echo "circom not found -- run from Git Bash"; exit 1; }
[ -d node_modules/snarkjs ] || npm install
mkdir -p build
LIB="-l node_modules/circomlib/circuits -l ../circuits/filing"
SNARKJS="node node_modules/snarkjs/cli.js"

echo "== step circuit c_fstep (--O0)"
circom ../circuits/filing/c_fstep.circom --r1cs --wasm --O0 -o build $LIB \
  | grep -E "non-linear|linear constraints|private inputs|wires"
echo "== boundary circuit c_boundary = Boundary(2, 64) (--O2)"
circom ../circuits/filing/c_boundary.circom --r1cs --wasm --O2 -o build $LIB \
  | grep -E "non-linear|linear constraints|public inputs|wires"
node consts.js --check | tail -1
echo "== gadget test circuits (test_smt_isold0.js)"
mkdir -p build/test
for c in smt_plain smt_bool dualpath; do
  circom ../circuits/filing/test/$c.circom --r1cs --wasm -o build/test $LIB | grep -E "non-linear" | sed "s/^/  $c: /"
done

# powers of tau, 2^18 (the boundary circuit has ~149k constraints)
PTAU=build/pot18_final.ptau
if [ ! -f $PTAU ]; then
  if [ -n "$PTAU_SRC" ] && [ -f "$PTAU_SRC" ]; then
    cp "$PTAU_SRC" $PTAU
  else
    curl -fL -o $PTAU.tmp \
      https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_18.ptau
    mv $PTAU.tmp $PTAU
  fi
fi
if [ ! -f build/c_boundary.zkey ] || [ build/c_boundary.r1cs -nt build/c_boundary.zkey ]; then
  echo "== Groth16 setup of the boundary circuit"
  t0=$(date +%s%3N)
  $SNARKJS groth16 setup build/c_boundary.r1cs $PTAU build/c_boundary.zkey
  t1=$(date +%s%3N)
  echo "  setup $(( t1 - t0 )) ms, zkey $(du -h build/c_boundary.zkey | cut -f1)"
  $SNARKJS zkey export verificationkey build/c_boundary.zkey build/c_boundary.vkey.json
fi
echo "circuits ready"
