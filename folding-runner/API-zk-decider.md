# API note: using the hiding decider with another step circuit

Assumed shape of the step circuit: IVC state of length 1
(`ivc_input[1]`, `ivc_output[1]`), plus a fixed number of `external_inputs`, compiled with
`circom --O0` (ark-circom mishandles the `--O1` wire map).

Nothing in the hiding decider depends on the step circuit beyond its augmented R1CS, which is
derived automatically. A different state length is a type parameter, not a code change in the
decider (sonobe's original decider at the pinned revision was found to fail for state length
> 1; the hiding decider was only run with state length 1).

## 1. With the runner (no Rust needed beyond two constants)

1. Pass the number of external inputs with `--ext-len`. Compiled in: 60 (the default, the
   smaller step circuit `c_step_d1` of ZK-DECIDER.md) and 117 (the filing step circuit `c_fstep`). For another length add two arms to
   the `match` in `main` of `sonobe-zk/taxtag-zk-runner/src/main.rs`
   (`(N, "cached") => dispatch::<CachedCircomFCircuit<N>, N>(args)` and the same with
   `CircomFCircuit<Fr, STATE_LEN, N>` for `"sonobe"`); the state length is the constant
   `STATE_LEN = 1` in the block "STEP CIRCUIT SHAPE".
   `--frontend cached|sonobe` selects the circom frontend of the step circuit. `cached` (the
   default) is `taxtag_zk_runner::cached_frontend::CachedCircomFCircuit<E>`: sonobe's
   `CircomFCircuit` with one change, the wasm witness generator is compiled once instead of at
   every step (ported from the filing build's `folding/filing_fold.rs`). `sonobe` is sonobe's own
   frontend. Both emit the same R1CS (mode `same-r1cs` compares them entry by entry), so Nova
   parameters, matrices and keys are shared between the two.
2. Build the FULL runner from Git Bash:
   `cd folding-runner/sonobe-zk && cargo build --release --offline -p taxtag-zk-runner`
   (`--features light` builds sonobe's reduced test circuit instead: no CycleFold checks, not a
   sound proof; the binary prints which one it is, and `--require-full` refuses a light build).
3. Compile the circuit and produce the input file:
   `circom <step>.circom --r1cs --wasm --O0 -o out -l <circomlib>/circuits`
   The input JSON has the layout
   `{ "z0": ["<decimal>"], "steps": [["<decimal>", ... EXT_INP_LEN entries], ... n rows] }`.
4. Run:
   `taxtag_zk_flow --require-full --input <json> --r1cs out/<step>.r1cs --wasm out/<step>_js/<step>.wasm --mode open --lowmem --matrices tmp/m.bin`
   Modes: `count`, `cfzeros`, `g3`, `sat-baseline | sat-open | sat-kzg`, `baseline`, `open`, `kzg`,
   and the end-to-end path `setup`, `prove`, `verify` (section 3), plus `fold` (fold only, time
   per step), `tamper` (one external input of one step changed; the fold must fail) and
   `same-r1cs` (the two frontends compared).
   - `--boundary-public <json>` (modes `open`, `kzg`): the public signals of the filing's
     boundary Groth16 proof. The runner checks that the decider proof verifies for
     `(i, public[0], public[1])`, that these equal the fold's `z_0`, `z_i`, that `i` is a power
     of two of at least 64, and prints `y`, `D`, `C_prev`, `C_y`, `closing`.
   - If the fold input has a field `"zn"` (the filing generator writes it), the runner checks
     that the folded `z_i` equals it.
   - mode `g3` (no SNARK): `--input A --extra-input B` folds the first steps of B while claiming
     the `z_0` of A and reports that the IVC verifier and the decider reject.
   - `--lowmem --matrices <file>`: run Groth16 through the low-memory driver (needed for the
     FULL circuits on a 32 GB machine; `<file>` plus `<file>.a/.b/.c` are scratch files, about
     13 GB for a full decider circuit).
   - `--params <file>`: store the Nova parameters (KZG and Pedersen keys) in this file, or load
     them if it exists. `--keys <file>` (needs `--lowmem` and `--params`): store the Groth16
     proving key there, or, if it and the matrix files exist, load it and skip matrix extraction
     and key generation. Matrices and keys are only valid for the Nova parameters they were made
     with, because the decider circuit contains the Pedersen generators as constants.
   - `--extra-input <json>`: after the main run, prove and verify a second input file (another
     number of steps) with the same keys.
   - `--skip-tests` skips the built-in rejection tests (two extra proofs).
   - `TAXTAG_MEM_CAP_GB` (default 20): self-imposed cap; the process exits with code 99 when its
     committed memory exceeds it. `TAXTAG_SYS_FLOOR_GB` (default 1.5): it exits with code 98 when
     the whole machine has less commit than that left.

A new step circuit changes the augmented R1CS, hence the commitment keys, the Groth16 keys and
`pp_hash`. Without `--params` / `--keys` all of them are regenerated at every start; with them
they are stored once and reused (delete the files, or use other file names, for a new circuit).

## 2. From Rust

```rust
use folding_schemes::folding::nova::{
    decider_eth_zk::{DeciderZK, Proof},              // setup / prove / verify
    decider_eth_zk_circuit::LinkMode,                // Open | KzgEval
    Nova, PreprocessorParam,
};

type FC  = CircomFCircuit<Fr, STATE_LEN, EXT_INP_LEN>;      // or any `FCircuit<Fr>`
type N   = Nova<G1, G2, FC, KZG<'static, Bn254>, Pedersen<G2>, false>;   // H = false
type DZK = DeciderZK<G1, G2, FC, KZG<'static, Bn254>, Pedersen<G2>, Groth16<Bn254>>;

let nova_params = N::preprocess(rng, &PreprocessorParam::new(poseidon_config, f_circuit.clone()))?;
let (pp, vp)    = DZK::preprocess(rng, nova_params.clone(), f_circuit.state_len(), LinkMode::Open)?;

let mut nova = N::init(&nova_params, f_circuit, z_0)?;
for ext in steps { nova.prove_step(rng, VecF(ext), None)?; }

let proof: Proof<G1, KZG<'static, Bn254>, Groth16<Bn254>> = DZK::prove(rng, &pp, nova.clone())?;
let ok = DZK::verify(&vp, nova.i, &nova.z_0, &nova.z_i, &proof)?;   // Err(..) on rejection
```

- `DZK::preprocess(rng, (nova_pp, nova_vp), state_len, link)`: circuit-specific Groth16 setup.
  Keys are specific to the step circuit AND to `link`.
- `DZK::prove(rng, &pp, nova)`: samples a fresh blinder, folds, checks natively, compresses.
  `nova` must be `Nova<.., false>` after at least 2 steps. `rng` must be a CSPRNG (`OsRng`).
- `DZK::prove_circuit(rng, &pp, circuit)`: compresses a prepared `DeciderEthZKCircuit` without
  any native check (used by the tests to feed malformed witnesses).
- Running the SNARK through another driver (what the runner's `--lowmem` does):
  `DZK::setup_circuit(&nova_params, state_len, link)` gives the circuit to run the setup on,
  `DZK::params_from_keys(nova_params, link, pk, vk)` packs the keys;
  `DZK::link_parts(&pp, &circuit)` gives everything of the proof except the SNARK part, and
  `parts.into_proof::<Groth16<Bn254>>(snark_proof)` assembles it. The driver itself is
  `taxtag_zk_runner::lowmem` (BN254 Groth16 only): `store_matrices(circuit, path)`,
  `setup_from_matrices(path, rng)`, `prove(&pk, path, circuit, rng)`, `save_key` / `load_key`.
  It relies on the vendored `sonobe-zk/vendor/ark-relations` (one added method).
- `DZK::verify(&vp, i, &z_0, &z_i, &proof)`: the verifier. Unlike the original decider it takes
  NO instance commitments; everything it needs beyond the statement is inside `proof`.
- `Proof` implements `CanonicalSerialize` / `CanonicalDeserialize` (one struct for both formats;
  the unused parts are empty vectors).
- `VerifierParam` is a plain struct (`link`, `pp_hash`, `snark_vp`, `cs_vp`, `cs_pk`, `r1cs`).
  The runner's mode `verify` (section 3) builds it from files: the Nova parameters file gives
  `pp_hash`, `cs_vp`, `cs_pk` and (with the step circuit) `r1cs`; the Groth16 verification key
  file gives `snark_vp`. In `Open` mode the verifier needs `cs_pk` (the commitment key) and
  `r1cs`; in `KzgEval` mode it needs `cs_vp` only.
- `taxtag_zk_runner::snarkjs`: `load_vkey`, `load_proof`, `load_public`, `verify` read a snarkjs
  Groth16 verification key, proof and public-signal file (BN254) and verify with arkworks; every
  point is checked to be on the curve and in the subgroup. Used for the boundary proof.

## 3. The filing step circuit: the end-to-end path

Three commands, from Git Bash in `folding-runner/` (paths and defaults in `filing_env.sh`):

```
bash setup_filing.sh                                   # once: Nova parameters, matrices, Groth16 key, verification key
bash prove_filing.sh  <fold_input.json> <out_dir>      # taxpayer: fold, blind, compress
bash verify_filing.sh <out_dir> <boundary_proof.json> <boundary_public.json> <boundary_vkey.json>   # authority
```

They wrap the runner modes `setup`, `prove`, `verify`:

```
C="--ext-len 117 --require-full --frontend cached --r1cs ../filing/build/c_fstep.r1cs --wasm ../filing/build/c_fstep_js/c_fstep.wasm --params tmp/fstep_nova_params.bin"
bin/taxtag_zk_flow_full.exe --mode setup  $C --format open --matrices tmp/m_fstep_open.bin --keys tmp/fstep_key_open.bin --vk keys/fstep_vk_open.bin
bin/taxtag_zk_flow_full.exe --mode prove  $C --format open --matrices tmp/m_fstep_open.bin --keys tmp/fstep_key_open.bin --input <fold_input.json> --out <out_dir>
bin/taxtag_zk_flow_full.exe --mode verify $C --proof <out_dir>/decider_proof.bin --public <out_dir>/decider_public.json --vk keys/fstep_vk_open.bin     --boundary-proof <boundary_proof.json> --boundary-public <boundary_public.json> --boundary-vkey <boundary_vkey.json>
```

- `setup` needs no fold input. If the parameters, the matrices and the key exist it regenerates
  nothing and only rewrites the verification key file.
- `prove` reads the fold input the filing generator writes (`node e2e.js <scenario> --gen-only`
  in `filing/`: `{ "n", "z0": [..], "zn": "..", "steps": [[117 strings] x n] }`), folds, checks
  the folded proof and that `z_i` equals `zn`, blinds, compresses, verifies its own proof, and
  writes `decider_proof.bin` (the serialized `Proof`) and `decider_public.json`
  (`{ "format", "i", "z_0": [..], "z_i": [..] }`, decimal strings). Exit code 0 only on success.
- `verify` uses no proving key, no matrix file and no fold input. It checks (1) the compressing
  proof for `(i, z_0, z_i)` under the verification key written by `setup`, (2) that `i` is a power
  of two of at least 64, (3) the boundary Groth16 proof under the given snarkjs verification key,
  (4) `z_0` = boundary public signal 0, (5) `z_i` = boundary public signal 1; then prints `D`
  (public signals L-6, L-5, L-4 of L) and `C_y` (L-2). Last line `AUTHORITY: filing ACCEPTED`
  and exit code 0 only if all five hold; otherwise `AUTHORITY: filing REJECTED` and exit code 1.
  It does NOT compare the tag list, chain ids, contract addresses, roots, `y` and `C_prev` in the
  boundary public signals with the authority's own values; the caller has to.
- `bash measure_filings.sh [worked two-tags sixteen synthetic-1000 | checks | negatives | control]`
  runs the measured filings and writes `logs/e2e_*.log`.

The fold must be made with THIS copy of sonobe (`sonobe-zk`) or one with the same base-case
constraint (ZK-DECIDER.md G3; the filing build's clone has it through `folding/basecase_z0.patch`):
a fold over another augmented circuit cannot be compressed with keys made here.

## 4. What a caller must not do

- Do not build the runner as an example of the `solidity-verifiers` package (examples of that
  package are compiled with `light-test` switched on, ZK-DECIDER.md F0). Depend on
  `folding-schemes` without that feature.
- Do not reuse a proof's blinder, and do not pass a deterministic RNG to `prove`.
- Do not treat `LinkMode::KzgEval` as a sound proof (ZK-DECIDER.md, gap G2).
