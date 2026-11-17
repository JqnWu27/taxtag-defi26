#!/usr/bin/env bash
# ONE-TIME SETUP of the compressing proof for the filing step circuit (FULL decider circuit).
# RUN FROM GIT BASH.
#
#   bash setup_filing.sh
#
# Creates, unless they exist already (see filing_env.sh for the paths):
#   - the Nova parameters (commitment keys)                       public
#   - the matrices of the decider circuit (about 12.6 GB scratch) prover
#   - the Groth16 proving key (about 3.8 GB)                      prover
#   - the Groth16 verification key (about 1 kB)                   authority
# If parameters, matrices and proving key exist, nothing is regenerated and only the
# verification key file is (re)written from the stored key.
# The Groth16 key generation is a local trusted setup: whoever runs it knows the trapdoor.
# About 5 minutes and 15 GB of memory on the reference machine.
set -e
. "$(dirname "$0")/filing_env.sh"
mkdir -p "$(dirname "$NOVA_PARAMS")" "$(dirname "$MATRICES")" "$(dirname "$PROVING_KEY")" "$(dirname "$DECIDER_VK")"
exec "$RUNNER" --mode setup "${STEP_ARGS[@]}" --format "$FORMAT" \
  --matrices "$MATRICES" --keys "$PROVING_KEY" --vk "$DECIDER_VK"
