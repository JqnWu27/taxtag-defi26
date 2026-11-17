#!/usr/bin/env bash
# AUTHORITY SIDE: checks one filing. RUN FROM GIT BASH.
#
#   bash verify_filing.sh <proof_dir> <boundary_proof.json> <boundary_public.json> <boundary_vkey.json>
#
#   <proof_dir>             the taxpayer's decider_proof.bin and decider_public.json
#   <boundary_proof.json>   the boundary Groth16 proof (snarkjs format)
#   <boundary_public.json>  its public signals: z0, zn, tags, chain ids, contract addresses,
#                           roots, y, D (proceeds, cost, income), C_prev, C_y, closing
#   <boundary_vkey.json>    the verification key of the boundary circuit (the authority's own copy)
#
# Checks, all of which must pass (exit code 0, last line "AUTHORITY: filing ACCEPTED"):
#   1  the compressing proof verifies for (i, z_0, z_i), under the authority's own decider
#      verification key ($DECIDER_VK, written by setup_filing.sh)
#   2  the step count i is a power of two of at least 64
#   3  the boundary proof verifies for its public signals under <boundary_vkey.json>
#   4  z_0 of the compressing proof equals the boundary public signal z0 (start digest)
#   5  z_i of the compressing proof equals the boundary public signal zn (end digest)
# and prints D and C_y from the boundary public signals.
# NOT checked here: that the tag list, chain ids, contract addresses, roots, y and C_prev in the
# boundary public signals are the ones the authority expects (they are printed or left to the
# caller; the command has no source for the authority's own values).
# Uses no proving key and no fold input: the step circuit, the Nova parameters (commitment keys)
# and two verification keys.
set -e
[ $# -eq 4 ] || { sed -n 2,24p "$0"; exit 2; }
abs() { echo "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"; }
PDIR="$(cd "$1" && pwd)"; BP="$(abs "$2")"; BS="$(abs "$3")"; BV="$(abs "$4")"
. "$(dirname "$0")/filing_env.sh"
[ -f "$DECIDER_VK" ] || { echo "missing $DECIDER_VK -- run: bash setup_filing.sh"; exit 2; }
exec "$RUNNER" --mode verify "${STEP_ARGS[@]}" \
  --proof "$PDIR/decider_proof.bin" --public "$PDIR/decider_public.json" --vk "$DECIDER_VK" \
  --boundary-proof "$BP" --boundary-public "$BS" --boundary-vkey "$BV"
