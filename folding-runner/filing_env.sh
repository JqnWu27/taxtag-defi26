# Common settings of setup_filing.sh, prove_filing.sh, verify_filing.sh and measure_filings.sh.
# Sourced, not run. Every value can be overridden from the environment.
#
#   FORMAT            final-proof format: open (default) or kzg
#   FRONTEND          cached (default; witness generator compiled once) or sonobe
#   FILING_BUILD      the filing build directory (step circuit, boundary keys, runs)
#   STEP_R1CS, STEP_WASM
#                     the step circuit (default: c_fstep of the filing build)
#   NOVA_PARAMS       Nova parameters = commitment keys (public; prover and authority)
#   MATRICES, PROVING_KEY
#                     scratch matrices and Groth16 proving key of the decider (prover only)
#   DECIDER_VK        Groth16 verification key of the decider (authority)
#   RUNNER            the runner binary (FULL decider circuit)
#   TAXTAG_MEM_CAP_GB memory cap of the runner (it exits with code 99 above it)
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${FORMAT:=open}"
: "${FRONTEND:=cached}"
: "${FILING_BUILD:=$HERE/../filing/build}"
: "${STEP_R1CS:=$FILING_BUILD/c_fstep.r1cs}"
: "${STEP_WASM:=$FILING_BUILD/c_fstep_js/c_fstep.wasm}"
: "${NOVA_PARAMS:=$HERE/tmp/fstep_nova_params.bin}"
: "${MATRICES:=$HERE/tmp/m_fstep_${FORMAT}.bin}"
: "${PROVING_KEY:=$HERE/tmp/fstep_key_${FORMAT}.bin}"
: "${DECIDER_VK:=$HERE/keys/fstep_vk_${FORMAT}.bin}"
EXE=""; case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) EXE=".exe" ;; esac
: "${RUNNER:=$HERE/bin/taxtag_zk_flow_full$EXE}"
: "${TAXTAG_MEM_CAP_GB:=20}"; export TAXTAG_MEM_CAP_GB
[ -x "$RUNNER" ] || { echo "runner binary missing: $RUNNER (build it with: bash run_zk_decider.sh build)"; exit 2; }
# 117 external inputs = the filing step circuit; --require-full refuses a reduced build
STEP_ARGS=(--ext-len 117 --require-full --frontend "$FRONTEND" --r1cs "$STEP_R1CS" --wasm "$STEP_WASM" --params "$NOVA_PARAMS")
