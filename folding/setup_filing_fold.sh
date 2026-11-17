#!/usr/bin/env bash
# Builds the filing fold driver (filing_fold.rs) as an example of sonobe at
# the pinned revision (rev 9414c45), with ONE
# change to sonobe: the base-case start-state constraint (basecase_z0.patch).
#
# The pinned sonobe tree lives in folding/sonobe (git-ignored). If it is
# missing it is taken from $SONOBE_SRC (an existing clone at the pin, e.g. a
# built one, copied as is so its target/ cache is reused) or cloned.
# RUN FROM GIT BASH (PowerShell's `bash` is WSL on the reference machine).
# Usage: bash folding/setup_filing_fold.sh
set -e
command -v cargo >/dev/null || { echo "cargo not found -- run from Git Bash, not WSL"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
DIR="$HERE/sonobe"
REV=9414c45c57cc5063face8b62263344cb4ba63b5f

if [ ! -d "$DIR" ]; then
  if [ -n "$SONOBE_SRC" ] && [ -d "$SONOBE_SRC" ]; then
    cp -a "$SONOBE_SRC" "$DIR"
  else
    git clone -q https://github.com/ethereum/sonobe "$DIR"
  fi
fi
cd "$DIR"
[ "$(git rev-parse HEAD)" = "$REV" ] || git checkout -q $REV
rm -f rust-toolchain rust-toolchain.toml           # repo pins old Rust; use system
# The pinned revision ships no lock file. Use the one the measurements were made
# with, so that a fresh clone resolves the same dependency versions.
[ -f Cargo.lock ] || cp "$HERE/sonobe.Cargo.lock" Cargo.lock

# Start-state fix: the pinned AugmentedFCircuit has no `z_i == z_0` constraint in
# the base case (i = 0), so its IVC verifier accepts a chain that did not start at
# the claimed z_0. One conditional constraint closes it (folding/basecase_z0.patch,
# the same change as in folding-runner/sonobe-zk).
if ! grep -q "TaxTag change" folding-schemes/src/folding/nova/circuits.rs; then
  git apply "$HERE/basecase_z0.patch"
fi

TOML=solidity-verifiers/Cargo.toml
if ! grep -q '^serde_json' $TOML; then
  if grep -q '^\[dev-dependencies\]' $TOML; then
    sed -i 's/^\[dev-dependencies\]/[dev-dependencies]\nserde_json = "1"/' $TOML
  else
    printf '\n[dev-dependencies]\nserde_json = "1"\n' >> $TOML
  fi
fi
# the driver's cached witness calculator uses ark-circom, wasmer and tokio directly
# (all three are already dependencies of experimental-frontends)
for dep in 'ark-circom = { workspace = true }' 'wasmer = { workspace = true }' 'tokio = { workspace = true }'; do
  name=${dep%% *}
  grep -q "^$name = " $TOML || sed -i "s/^\[dev-dependencies\]/[dev-dependencies]\n$dep/" $TOML
done
for ex in filing_fold; do
  cp "$HERE/$ex.rs" examples/$ex.rs
  if ! grep -q "name = \"$ex\"" $TOML; then
    printf '\n[[example]]\nname = "%s"\npath = "../examples/%s.rs"\n' "$ex" "$ex" >> $TOML
  fi
done
cargo build --release -p solidity-verifiers --example filing_fold
echo "built: $DIR/target/release/examples/filing_fold(.exe)"
