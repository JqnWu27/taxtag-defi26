#!/usr/bin/env bash
# TAXPAYER SIDE: the compressing proof of one filing. RUN FROM GIT BASH.
#
#   bash prove_filing.sh <fold_input.json> <out_dir>
#
#   <fold_input.json>  the filing's padded step sequence, written by the filing generator
#                      (`node e2e.js <scenario> --gen-only` in ../filing):
#                      { "n", "z0": ["<start digest>"], "zn": "<end digest>", "steps": [[117 values] x n] }
#   <out_dir>          receives
#                        decider_proof.bin    the compressing proof (format Open: about 5.1 MB)
#                        decider_public.json  its public values: format, i (step count), z_0, z_i
#
# What it does: folds the n steps with Nova + CycleFold (witness generator compiled once),
# checks the folded proof, blinds it with a fresh random satisfying instance, compresses it with
# Groth16 over the FULL decider circuit, and verifies its own proof before writing it.
# Needs the one-time setup (setup_filing.sh). Exit code 0 only if the proof was made and verifies.
# The taxpayer sends the two files together with the boundary proof and its public signals.
set -e
[ $# -eq 2 ] || { sed -n 2,17p "$0"; exit 2; }
IN="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
mkdir -p "$2"; OUT="$(cd "$2" && pwd)"
. "$(dirname "$0")/filing_env.sh"
for f in "$NOVA_PARAMS" "$MATRICES" "$PROVING_KEY"; do
  [ -f "$f" ] || { echo "missing $f -- run: bash setup_filing.sh"; exit 2; }
done
exec "$RUNNER" --mode prove "${STEP_ARGS[@]}" --format "$FORMAT" \
  --matrices "$MATRICES" --keys "$PROVING_KEY" --input "$IN" --out "$OUT"
