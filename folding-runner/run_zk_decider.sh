#!/usr/bin/env bash
# Builds and tests the runner of the compressing proof (the hiding decider, see ZK-DECIDER.md).
# RUN FROM GIT BASH (PowerShell's `bash` is WSL on many machines and lacks the toolchain).
#
#   bash run_zk_decider.sh build            # build FULL and REDUCED runner binaries into bin/
#   bash run_zk_decider.sh smalltests       # cargo tests on the small step circuit, reduced build
#
# The filing step circuit (the artifact's end-to-end path) has its own scripts: setup_filing.sh,
# prove_filing.sh, verify_filing.sh, measure_filings.sh.
#
# Environment:
#   CARGO_FLAGS        extra cargo flags, e.g. --offline once the dependencies are cached
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
command -v cargo >/dev/null || { echo "cargo not found -- run from Git Bash, not WSL"; exit 1; }
: "${CARGO_FLAGS:=}"

case "$1" in
  build)
    mkdir -p bin
    EXE=""; case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) EXE=".exe" ;; esac
    ( cd sonobe-zk && cargo build --release $CARGO_FLAGS -p taxtag-zk-runner )
    cp sonobe-zk/target/release/taxtag_zk_flow$EXE bin/taxtag_zk_flow_full$EXE
    ( cd sonobe-zk && cargo build --release $CARGO_FLAGS -p taxtag-zk-runner --features light )
    cp sonobe-zk/target/release/taxtag_zk_flow$EXE bin/taxtag_zk_flow_light$EXE
    ;;
  smalltests)
    ( cd sonobe-zk && cargo test --release $CARGO_FLAGS -p taxtag-zk-runner --features light \
        --test zk_decider_small -- --test-threads=1 )
    ;;
  *)
    sed -n 2,12p "$HERE/$(basename "$0")"; exit 2 ;;
esac
