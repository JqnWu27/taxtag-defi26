#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]
//! TaxTag runner for the hiding ("blind-then-compress") Nova decider, next to sonobe's original
//! non-hiding decider, on a circom step circuit of the shape "IVC state length 1 + external
//! inputs".
//!
//! Usage:
//!   taxtag_zk_flow --input <fold_input_d1.json> --r1cs <c_step_d1.r1cs> --wasm <c_step_d1.wasm>
//!                  --mode <count|baseline|open|kzg> [--require-full] [--skip-tests] [--verify-reps <k>]
//!
//!   --require-full  refuse to run if the binary was built with `--features light`
//!   --extra-input <json>
//!                   (modes open, kzg) after the main run, fold the steps of a second input file
//!                   and prove and verify it WITH THE SAME KEYS (the decider does not depend on
//!                   the number of steps)
//!   --ext-len <60|117>
//!                   number of external inputs of the step circuit (default 60;
//!                   117 = the filing step circuit `c_fstep`)
//!   --boundary-public <json>
//!                   (modes open, kzg) public signals of the filing's boundary Groth16 proof:
//!                   the runner checks that the decider proof's `z_0`, `z_i` are its first two
//!                   entries and that `i` is a power of two >= 64, and prints `D`
//!   --params <file> load the Nova parameters (commitment keys) from this file, or create and
//!                   store them there if it does not exist. Needed to reuse matrices and keys
//!                   across runs: the decider circuit contains the Pedersen generators.
//!   --keys <file>   (with --lowmem and --params) load the Groth16 proving key from this file and
//!                   skip matrix extraction and setup, or create and store it there
//!   --lowmem --matrices <file>
//!                   run Groth16 through the low-memory driver of `taxtag_zk_runner::lowmem`
//!                   (needed for the full circuits on a 32 GB machine); `<file>` is a scratch
//!                   file for the R1CS matrices
//!
//!   count     exact constraint counts of the three decider circuits (no SNARK setup)
//!   g3        no SNARK: folds the first steps of `--extra-input` while claiming the `z_0` of
//!             `--input`, and reports whether the IVC verifier and the decider's native check
//!             reject (they must, since the base-case constraint was added)
//!   sat-baseline | sat-open | sat-kzg
//!             synthesize one decider circuit on the honest witness and check that every
//!             constraint is satisfied (no SNARK setup)
//!   baseline  sonobe's DeciderEth (non-hiding): setup, prove, verify, sizes
//!   open      hiding decider, LinkMode::Open:    setup, prove, verify, sizes, tests
//!   kzg       hiding decider, LinkMode::KzgEval: setup, prove, verify, sizes, tests
//!
//! THE END-TO-END PATH OF THE ARTIFACT (wrapped by `folding-runner/setup_filing.sh`,
//! `prove_filing.sh`, `verify_filing.sh`):
//!   setup     one-time: Nova parameters (commitment keys), matrices of the decider circuit,
//!             Groth16 key (--params, --matrices, --keys, [--format open|kzg], [--vk <file>:
//!             the verification key for the authority]); needs no fold input. If parameters,
//!             matrices and key exist, nothing is regenerated and only --vk is rewritten.
//!   prove     taxpayer: folds the steps of --input, blinds, compresses, checks its own proof;
//!             writes <--out>/decider_proof.bin and decider_public.json (format, i, z_0, z_i)
//!             (--input, --params, --matrices, --keys, --out, [--format open|kzg])
//!   verify    authority: checks the compressing proof (--proof, --public, --vk, --params) and,
//!             if given, the boundary proof (--boundary-proof, --boundary-public,
//!             --boundary-vkey: snarkjs Groth16 files), the equality of the start and end
//!             digests and the step-count rule; prints D and C_y; exit code 0 only if every
//!             check passed. Needs no proving key, no matrix file and no fold input.
//!   tamper    no SNARK: external input --tamper-index of step --tamper-step is increased by 1;
//!             the fold must fail (exit code 0 only if it does and the unchanged steps pass)
//!   fold      no SNARK: folds the steps of --input, prints the time per step (mean, min, max)
//!             and the memory, verifies the folded proof (to compare the two frontends)
//!   same-r1cs no SNARK: compares the augmented circuits built by the two frontends, and the
//!             stored Nova parameters under both
//!
//!   --frontend <cached|sonobe>
//!             circom frontend of the step circuit. `cached` (default): the witness generator
//!             (wasm) is compiled once (`taxtag_zk_runner::cached_frontend`, ported from the
//!             filing build's fold driver). `sonobe`: sonobe's own `CircomFCircuit`, which
//!             compiles it again at every step. Both emit the same R1CS.
//!
//! Built WITHOUT `--features light` this is the full decider circuit. With `--features light`
//! sonobe's `light-test` reduction is active (no CycleFold checks): fast, but NOT a sound proof.
//! The binary prints which of the two it is.
//!
//! PLUGGING IN ANOTHER STEP CIRCUIT: change the two constants below to the new circuit's shape
//! and pass its files on the command line. Nothing else in this file depends on the circuit.
//! See `folding-runner/API-zk-decider.md`.
use ark_bn254::{Bn254, Fr, G1Projective as G1};
use ark_ec::{AffineRepr, CurveGroup};
use ark_groth16::Groth16;
use ark_grumpkin::Projective as G2;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::{rand::rngs::OsRng, One, Zero};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Instant;

use experimental_frontends::{circom::CircomFCircuit, utils::VecF};
use folding_schemes::{
    arith::{Arith, ArithRelation},
    commitment::{kzg::KZG, pedersen::Pedersen, CommitmentScheme},
    folding::{
        nova::{
            decider_eth::{
                Decider as DeciderEth, DeciderEthCircuit, Proof as BaseProof,
                VerifierParam as BaseVerifierParam,
            },
            decider_eth_zk::{DeciderZK, Proof as ZKProof},
            decider_eth_zk_circuit::{sample_relaxed_instance, DeciderEthZKCircuit, LinkMode},
            Nova, PreprocessorParam,
        },
        traits::{CommittedInstanceOps, Dummy, WitnessOps},
    },
    frontend::FCircuit,
    transcript::poseidon::poseidon_canonical_config,
    Decider, Error, FoldingScheme,
};
use taxtag_zk_runner::{cached_frontend::CachedCircomFCircuit, lowmem, mem, snarkjs};

// ---------------------------------------------------------------------------------------------
// STEP CIRCUIT SHAPE (the only circuit-specific part of the runner)
// ---------------------------------------------------------------------------------------------
/// length of the IVC state `z` (`ivc_input` / `ivc_output` of the circom circuit)
const STATE_LEN: usize = 1;
/// The length of `external_inputs` of the circom circuit is a const generic parameter `E` of
/// everything below; `main` dispatches on `--ext-len`. To support another step circuit, add its
/// length to the `match` in `main` (currently 60, and 117 = the filing step
/// circuit `c_fstep`).
// ---------------------------------------------------------------------------------------------

/// The frontend of the step circuit: either sonobe's `CircomFCircuit` or the cached one. Both
/// take the paths of the circuit's `.r1cs` and `.wasm` files.
trait StepFrontend<const E: usize>: FCircuit<Fr, ExternalInputs = VecF<Fr, E>> {
    const NAME: &'static str;
    fn make_params(r1cs: &str, wasm: &str) -> Self::Params;
}
impl<const E: usize> StepFrontend<E> for CircomFCircuit<Fr, STATE_LEN, E> {
    const NAME: &'static str =
        "sonobe (CircomFCircuit: the witness generator is compiled at every step)";
    fn make_params(r1cs: &str, wasm: &str) -> Self::Params {
        (PathBuf::from(r1cs).into(), PathBuf::from(wasm).into())
    }
}
impl<const E: usize> StepFrontend<E> for CachedCircomFCircuit<E> {
    const NAME: &'static str =
        "cached (CachedCircomFCircuit: the witness generator is compiled once)";
    fn make_params(r1cs: &str, wasm: &str) -> Self::Params {
        (PathBuf::from(r1cs), PathBuf::from(wasm))
    }
}

type K = KZG<'static, Bn254>;
type N<FC> = Nova<G1, G2, FC, K, Pedersen<G2>, false>;
/// sonobe's original (non-hiding) decider
type DBase<FC> = DeciderEth<G1, G2, FC, K, Pedersen<G2>, Groth16<Bn254>, N<FC>>;
/// the hiding decider
type DZK<FC> = DeciderZK<G1, G2, FC, K, Pedersen<G2>, Groth16<Bn254>>;
type PZK = ZKProof<G1, K, Groth16<Bn254>>;

struct Args {
    input: String,
    r1cs: String,
    wasm: String,
    mode: String,
    skip_tests: bool,
    require_full: bool,
    lowmem: bool,
    matrices: String,
    extra_input: String,
    params: String,
    keys: String,
    ext_len: usize,
    boundary_public: String,
    verify_reps: usize,
    frontend: String,
    format: String,
    out: String,
    proof: String,
    public: String,
    vk: String,
    boundary_proof: String,
    boundary_vkey: String,
    tamper_step: usize,
    tamper_index: usize,
}

fn parse_args() -> Args {
    let mut a = Args {
        input: String::new(),
        r1cs: String::new(),
        wasm: String::new(),
        mode: String::new(),
        skip_tests: false,
        require_full: false,
        lowmem: false,
        matrices: String::new(),
        extra_input: String::new(),
        params: String::new(),
        keys: String::new(),
        ext_len: 60,
        boundary_public: String::new(),
        verify_reps: 10,
        frontend: "cached".to_string(),
        format: "open".to_string(),
        out: String::new(),
        proof: String::new(),
        public: String::new(),
        vk: String::new(),
        boundary_proof: String::new(),
        boundary_vkey: String::new(),
        tamper_step: 0,
        tamper_index: 0,
    };
    let v: Vec<String> = std::env::args().collect();
    let mut k = 1;
    while k < v.len() {
        let next = |k: usize| v.get(k + 1).cloned().unwrap_or_default();
        match v[k].as_str() {
            "--input" => {
                a.input = next(k);
                k += 1
            }
            "--r1cs" => {
                a.r1cs = next(k);
                k += 1
            }
            "--wasm" => {
                a.wasm = next(k);
                k += 1
            }
            "--mode" => {
                a.mode = next(k);
                k += 1
            }
            "--verify-reps" => {
                a.verify_reps = next(k).parse().unwrap_or(10);
                k += 1
            }
            "--skip-tests" => a.skip_tests = true,
            "--require-full" => a.require_full = true,
            "--lowmem" => a.lowmem = true,
            "--extra-input" => {
                a.extra_input = next(k);
                k += 1
            }
            "--params" => {
                a.params = next(k);
                k += 1
            }
            "--keys" => {
                a.keys = next(k);
                k += 1
            }
            "--ext-len" => {
                a.ext_len = next(k).parse().unwrap_or(0);
                k += 1
            }
            "--boundary-public" => {
                a.boundary_public = next(k);
                k += 1
            }
            "--matrices" => {
                a.matrices = next(k);
                k += 1
            }
            "--frontend" => {
                a.frontend = next(k);
                k += 1
            }
            "--format" => {
                a.format = next(k);
                k += 1
            }
            "--out" => {
                a.out = next(k);
                k += 1
            }
            "--proof" => {
                a.proof = next(k);
                k += 1
            }
            "--public" => {
                a.public = next(k);
                k += 1
            }
            "--vk" => {
                a.vk = next(k);
                k += 1
            }
            "--boundary-proof" => {
                a.boundary_proof = next(k);
                k += 1
            }
            "--boundary-vkey" => {
                a.boundary_vkey = next(k);
                k += 1
            }
            "--tamper-step" => {
                a.tamper_step = next(k).parse().unwrap_or(0);
                k += 1
            }
            "--tamper-index" => {
                a.tamper_index = next(k).parse().unwrap_or(0);
                k += 1
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
        k += 1;
    }
    let needs_input = !matches!(a.mode.as_str(), "setup" | "verify" | "same-r1cs");
    if (needs_input && a.input.is_empty()) || a.r1cs.is_empty() || a.wasm.is_empty() || a.mode.is_empty() {
        eprintln!(
            "usage: taxtag_zk_flow --r1cs <file> --wasm <file> --mode <setup|prove|verify|tamper|same-r1cs|count|g3|open|kzg|baseline|sat-..> [--input <json>] [--frontend cached|sonobe] ... (see the head of src/main.rs or API-zk-decider.md)"
        );
        std::process::exit(2);
    }
    if a.verify_reps == 0 {
        a.verify_reps = 1;
    }
    a
}

/// counts constraints and variables without building the matrices
fn count(name: &str, c: impl ConstraintSynthesizer<Fr>) -> Result<usize, Error> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: false,
    });
    c.generate_constraints(cs.clone())?;
    println!(
        "COUNT {name}: constraints {}, public inputs {}, witness variables {}",
        cs.num_constraints(),
        cs.num_instance_variables() - 1,
        cs.num_witness_variables()
    );
    Ok(cs.num_constraints())
}

/// synthesizes the circuit with its witness and reports whether every constraint is satisfied
/// (no SNARK involved)
fn sat(name: &str, c: impl ConstraintSynthesizer<Fr>) -> Result<bool, Error> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    let start = Instant::now();
    c.generate_constraints(cs.clone())?;
    let ok = cs.is_satisfied()?;
    println!(
        "SAT {name}: constraints {}, satisfied = {ok} (synthesis + check {:?})",
        cs.num_constraints(),
        start.elapsed()
    );
    if !ok {
        println!("SAT {name}: first unsatisfied constraint: {:?}", cs.which_is_unsatisfied()?);
    }
    mem::report("after sat");
    Ok(ok)
}

/// Groth16 keys through the low-memory driver: matrix extraction (unless matrices and a stored key
/// exist), key generation, optional storing of the key.
fn lowmem_keys(
    make_circuit: impl FnOnce() -> Box<dyn FnOnce(&std::path::Path) -> Result<(), Error>>,
    mpath: &std::path::Path,
    keys: &str,
) -> Result<
    (
        ark_groth16::ProvingKey<Bn254>,
        ark_groth16::VerifyingKey<Bn254>,
    ),
    Error,
> {
    let kpath = std::path::Path::new(keys);
    if !keys.is_empty() && kpath.exists() && lowmem::matrices_exist(mpath) {
        let start = Instant::now();
        let k = lowmem::load_key(kpath)?;
        println!(
            "LOWMEM reusing the stored matrices and the Groth16 key {} (loaded in {:?})",
            keys,
            start.elapsed()
        );
        return Ok(k);
    }
    let start = Instant::now();
    make_circuit()(mpath)?;
    println!("TIME matrix extraction: {:?}", start.elapsed());
    mem::report("after matrix extraction");
    let start = Instant::now();
    let (pk, vk) = lowmem::setup_from_matrices(mpath, OsRng)?;
    println!("TIME key generation: {:?}", start.elapsed());
    if !keys.is_empty() {
        let start = Instant::now();
        lowmem::save_key(&pk, kpath)?;
        println!("LOWMEM Groth16 key stored in {} ({:?})", keys, start.elapsed());
    }
    Ok((pk, vk))
}

struct Tests {
    passed: usize,
    failed: usize,
}
impl Tests {
    fn check(&mut self, name: &str, ok: bool) {
        if ok {
            self.passed += 1;
            println!("TEST PASS  {name}");
        } else {
            self.failed += 1;
            println!("TEST FAIL  {name}");
        }
    }
}

fn main() -> Result<(), Error> {
    mem::start_guard();
    let args = parse_args();
    let frontend = args.frontend.clone();
    match (args.ext_len, frontend.as_str()) {
        (60, "cached") => dispatch::<CachedCircomFCircuit<60>, 60>(args),
        (60, "sonobe") => dispatch::<CircomFCircuit<Fr, STATE_LEN, 60>, 60>(args),
        (117, "cached") => dispatch::<CachedCircomFCircuit<117>, 117>(args),
        (117, "sonobe") => dispatch::<CircomFCircuit<Fr, STATE_LEN, 117>, 117>(args),
        (60 | 117, other) => {
            eprintln!("unknown --frontend {other} (cached | sonobe)");
            std::process::exit(2);
        }
        (other, _) => {
            eprintln!("--ext-len {other} is not compiled in (add it to the match in main)");
            std::process::exit(2);
        }
    }
}

fn dispatch<FC: StepFrontend<E>, const E: usize>(args: Args) -> Result<(), Error> {
    match args.mode.as_str() {
        "setup" => cmd_setup::<FC, E>(&args),
        "prove" => cmd_prove::<FC, E>(&args),
        "verify" => cmd_verify::<FC, E>(&args),
        "tamper" => cmd_tamper::<FC, E>(&args),
        "fold" => cmd_fold::<FC, E>(&args),
        "same-r1cs" => cmd_same_r1cs::<E>(&args),
        _ => run::<FC, E>(args),
    }
}

fn run<FC: StepFrontend<E>, const E: usize>(args: Args) -> Result<(), Error> {
    banner(&args, FC::NAME);
    if args.lowmem {
        if args.matrices.is_empty() {
            eprintln!("--lowmem needs --matrices <file> (scratch file for the R1CS matrices, several GB for the full circuits)");
            std::process::exit(2);
        }
        println!("SNARK DRIVER: low-memory (R1CS rows streamed to {} once; arkworks Groth16 generator and prover with the R1CS-to-QAP reduction reading the rows from disk; witness-only synthesis at proving; standard verify)", args.matrices);
    } else {
        println!("SNARK DRIVER: standard (Groth16::circuit_specific_setup / prove through the decider API)");
    }
    let mpath = PathBuf::from(&args.matrices);
    if !args.keys.is_empty() && (!args.lowmem || args.params.is_empty()) {
        eprintln!("--keys needs --lowmem and --params (stored keys are only valid for the stored Nova parameters)");
        std::process::exit(2);
    }

    // ---- inputs ----
    let load = |path: &str| -> (Vec<Fr>, Vec<Vec<Fr>>) {
        let raw = std::fs::read_to_string(path).expect("input json missing");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("input json malformed");
        let z_0: Vec<Fr> = v["z0"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| Fr::from_str(x.as_str().unwrap()).unwrap())
            .collect();
        let external_inputs: Vec<Vec<Fr>> = v["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| {
                s.as_array()
                    .unwrap()
                    .iter()
                    .map(|x| Fr::from_str(x.as_str().unwrap()).unwrap())
                    .collect()
            })
            .collect();
        assert_eq!(z_0.len(), STATE_LEN, "z0 length != STATE_LEN");
        assert!(
            external_inputs.iter().all(|e| e.len() == E),
            "a step's external inputs length != --ext-len"
        );
        (z_0, external_inputs)
    };
    let (z_0, external_inputs) = load(&args.input);
    let n = external_inputs.len();
    // optional reference end digest written by the filing generator
    let expected_zn: Option<Fr> = {
        let raw = std::fs::read_to_string(&args.input).expect("input json missing");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("input json malformed");
        v.get("zn")
            .and_then(|x| x.as_str())
            .map(|x| Fr::from_str(x).unwrap())
    };
    println!("STEPS: {n}");

    let f_circuit = FC::new(FC::make_params(&args.r1cs, &args.wasm))?;

    // ---- Nova parameters (commitment keys) ----
    let start = Instant::now();
    let nova_params = if !args.params.is_empty() && std::path::Path::new(&args.params).exists() {
        let bytes = std::fs::read(&args.params)?;
        let mut r = &bytes[..];
        let fc_params = || FC::make_params(&args.r1cs, &args.wasm);
        let pp = N::<FC>::pp_deserialize_with_mode(&mut r, Compress::No, Validate::No, fc_params())?;
        let vp = N::<FC>::vp_deserialize_with_mode(&mut r, Compress::No, Validate::No, fc_params())?;
        println!("NOVA PARAMS: loaded from {}", args.params);
        (pp, vp)
    } else {
        let p = N::<FC>::preprocess(
            OsRng,
            &PreprocessorParam::new(poseidon_canonical_config::<Fr>(), f_circuit.clone()),
        )?;
        if !args.params.is_empty() {
            let mut bytes = vec![];
            p.0.serialize_uncompressed(&mut bytes)?;
            p.1.serialize_uncompressed(&mut bytes)?;
            std::fs::write(&args.params, &bytes)?;
            println!("NOVA PARAMS: created and stored in {}", args.params);
        }
        p
    };
    println!("TIME nova preprocess: {:?}", start.elapsed());
    println!(
        "AUGMENTED CIRCUIT: constraints {}, witnesses {}, public inputs {}; CYCLEFOLD CIRCUIT: constraints {}, witnesses {}",
        nova_params.1.r1cs.n_constraints(),
        nova_params.1.r1cs.n_witnesses(),
        nova_params.1.r1cs.n_public_inputs(),
        nova_params.1.cf_r1cs.n_constraints(),
        nova_params.1.cf_r1cs.n_witnesses(),
    );

    // ---- fold ----
    let fold_with = |z_0: &Vec<Fr>, external_inputs: &Vec<Vec<Fr>>, n_steps: usize| -> Result<N<FC>, Error> {
        mem::machine_state("before fold");
        let k = n_steps.min(external_inputs.len());
        let (nova, st) = fold_timed::<FC, E>(&nova_params, &f_circuit, z_0, &external_inputs[..k])?;
        println!("TIME fold: {}", st.line());
        let start = Instant::now();
        N::<FC>::verify(nova_params.1.clone(), nova.ivc_proof())?;
        println!("IVC verify: OK ({:?})", start.elapsed());
        Ok(nova)
    };
    let fold = |n_steps: usize| fold_with(&z_0, &external_inputs, n_steps);

    match args.mode.as_str() {
        // -------------------------------------------------------------------------------------
        "count" => {
            let nova = fold(2.min(n))?;
            count(
                "baseline DeciderEthCircuit (non-hiding)",
                DeciderEthCircuit::<G1, G2>::try_from(nova.clone())?,
            )?;
            count(
                "hiding DeciderEthZKCircuit, LinkMode::Open",
                DeciderEthZKCircuit::<G1, G2>::from_nova(nova.clone(), LinkMode::Open, OsRng)?.0,
            )?;
            count(
                "hiding DeciderEthZKCircuit, LinkMode::KzgEval",
                DeciderEthZKCircuit::<G1, G2>::from_nova(nova.clone(), LinkMode::KzgEval, OsRng)?
                    .0,
            )?;
            mem::report("after count");
        }
        // -------------------------------------------------------------------------------------
        // G3 regression on the real step circuit: every step is valid, but the chain starts at
        // another state than the claimed z_0
        "g3" => {
            if args.extra_input.is_empty() {
                eprintln!("mode g3 needs --extra-input (the fold input whose steps are folded)");
                std::process::exit(2);
            }
            let (z_0b, extb) = load(&args.extra_input);
            let k = 4.min(extb.len());
            // claim the z_0 of --input, start from the z_0 of --extra-input
            let mut nova = N::<FC>::init(&nova_params, f_circuit.clone(), z_0.clone())?;
            nova.z_i = z_0b.clone();
            for ext in extb.iter().take(k) {
                nova.prove_step(OsRng, VecF(ext.clone()), None)?;
            }
            println!(
                "G3 claimed z_0 = {} (from --input), chain started at {} (from --extra-input), {k} steps folded",
                nova.z_0[0], z_0b[0]
            );
            let ivc_rejected = N::<FC>::verify(nova_params.1.clone(), nova.ivc_proof()).is_err();
            println!(
                "G3 IVC verifier: {}",
                if ivc_rejected { "rejected (as it must be)" } else { "ACCEPTED (ERROR)" }
            );
            let (circuit, aux) =
                DeciderEthZKCircuit::<G1, G2>::from_nova(nova.clone(), LinkMode::Open, OsRng)?;
            let native_rejected = circuit.check_native(&aux).is_err();
            println!(
                "G3 decider native check of the blinded pair: {}",
                if native_rejected { "rejected (as it must be)" } else { "ACCEPTED (ERROR)" }
            );
            // control: the same steps from their own z_0 are accepted
            let control = fold_with(&z_0b, &extb, k).is_ok();
            println!("G3 control (same steps, honest z_0): {}", if control { "accepted" } else { "REJECTED (ERROR)" });
            if !ivc_rejected || !native_rejected || !control {
                std::process::exit(1);
            }
        }
        // -------------------------------------------------------------------------------------
        // diagnostic: where are the zero entries of the honest CycleFold running witness?
        // (the in-circuit Pedersen gadget of the pinned r1cs-std cannot handle a PAIR of zero
        // scalars (2k, 2k+1); see ZK-DECIDER.md)
        "cfzeros" => {
            let nova = fold(n)?;
            for (name, v) in [("E", &nova.cf_W_i.E), ("W", &nova.cf_W_i.W)] {
                let zeros: Vec<usize> = v
                    .iter()
                    .enumerate()
                    .filter(|(_, x)| x.is_zero())
                    .map(|(k, _)| k)
                    .collect();
                let zero_pairs: Vec<usize> = (0..v.len() / 2)
                    .filter(|k| v[2 * k].is_zero() && v[2 * k + 1].is_zero())
                    .map(|k| 2 * k)
                    .collect();
                println!(
                    "CFZEROS cf_W_i.{name}: length {}, zero entries {}, pairs (2k, 2k+1) with both zero {}",
                    v.len(),
                    zeros.len(),
                    zero_pairs.len()
                );
                println!("CFZEROS cf_W_i.{name}: last 12 zero indices {:?}", &zeros[zeros.len().saturating_sub(12)..]);
                println!("CFZEROS cf_W_i.{name}: first 12 double-zero pair starts {:?}", &zero_pairs[..zero_pairs.len().min(12)]);
            }
        }
        // -------------------------------------------------------------------------------------
        // satisfiability of one circuit on the honest witness after all n steps, without a SNARK
        "sat-baseline" => {
            let nova = fold(n)?;
            let ok = sat(
                "baseline DeciderEthCircuit (non-hiding)",
                DeciderEthCircuit::<G1, G2>::try_from(nova)?,
            )?;
            if !ok {
                std::process::exit(1);
            }
        }
        "sat-open" | "sat-kzg" => {
            let link = if args.mode == "sat-open" {
                LinkMode::Open
            } else {
                LinkMode::KzgEval
            };
            let nova = fold(n)?;
            let (circuit, aux) = DeciderEthZKCircuit::<G1, G2>::from_nova(nova, link, OsRng)?;
            circuit.check_native(&aux)?;
            let ok = sat(&format!("hiding DeciderEthZKCircuit, {link:?}"), circuit)?;
            if !ok {
                std::process::exit(1);
            }
        }
        // -------------------------------------------------------------------------------------
        "baseline" => {
            let start = Instant::now();
            let (pp, vp) = if args.lowmem {
                // same circuit and same keys as `DBase::<FC>::preprocess`, through the low-memory driver
                let (nova_pp, nova_vp) = nova_params.clone();
                let make = || -> Box<dyn FnOnce(&std::path::Path) -> Result<(), Error>> {
                    let circuit = DeciderEthCircuit::<G1, G2>::dummy((
                        nova_vp.r1cs.clone(),
                        nova_vp.cf_r1cs.clone(),
                        nova_pp.cf_cs_pp.clone(),
                        nova_pp.poseidon_config.clone(),
                        (),
                        (),
                        STATE_LEN,
                        2,
                    ));
                    Box::new(move |p| Ok(lowmem::store_matrices(circuit, p)?))
                };
                let (pk, vk) = lowmem_keys(make, &mpath, &args.keys)?;
                (
                    (pk, nova_pp.cs_pp.clone()),
                    BaseVerifierParam {
                        pp_hash: nova_vp.pp_hash()?,
                        snark_vp: vk,
                        cs_vp: nova_vp.cs_vp.clone(),
                    },
                )
            } else {
                DBase::<FC>::preprocess(OsRng, (nova_params.clone(), STATE_LEN))?
            };
            println!("TIME decider setup: {:?}", start.elapsed());
            mem::report("after setup");
            println!(
                "KEYS prover: Groth16 proving key {} B uncompressed ({} B compressed), KZG commit key {} B; verifier: Groth16 verifying key {} B, KZG verifier key {} B (compressed)",
                pp.0.serialized_size(Compress::No),
                pp.0.serialized_size(Compress::Yes),
                pp.1.serialized_size(Compress::Yes),
                vp.snark_vp.serialized_size(Compress::Yes),
                vp.cs_vp.serialized_size(Compress::Yes),
            );

            let nova = fold(n)?;
            let start = Instant::now();
            let proof = if args.lowmem {
                // the steps of `DBase::<FC>::prove`, with the SNARK proof from the low-memory driver.
                // The original `Proof` struct has private fields, so it is assembled through its
                // own (de)serialization: fields in declaration order.
                let circuit = DeciderEthCircuit::<G1, G2>::try_from(nova.clone())?;
                let cmT = circuit.proof;
                let r = circuit.randomness;
                let ch = circuit.kzg_challenges.clone();
                let kzg_proofs = circuit
                    .W_i1
                    .get_openings()
                    .iter()
                    .zip(&ch)
                    .map(|((v, _), &c)| {
                        <K as CommitmentScheme<G1>>::prove_with_challenge(
                            &pp.1,
                            c,
                            v,
                            &Fr::zero(),
                            None,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let snark = lowmem::prove(&pp.0, &mpath, circuit, OsRng)?;
                let mut bytes = vec![];
                snark.serialize_compressed(&mut bytes)?;
                kzg_proofs[0].serialize_compressed(&mut bytes)?;
                kzg_proofs[1].serialize_compressed(&mut bytes)?;
                cmT.serialize_compressed(&mut bytes)?;
                r.serialize_compressed(&mut bytes)?;
                ch[0].serialize_compressed(&mut bytes)?;
                ch[1].serialize_compressed(&mut bytes)?;
                BaseProof::<G1, K, Groth16<Bn254>>::deserialize_compressed(&bytes[..])?
            } else {
                DBase::<FC>::prove(OsRng, pp, nova.clone())?
            };
            println!("TIME decider prove: {:?}", start.elapsed());
            mem::report("after prove");

            let running = nova.U_i.get_commitments();
            let incoming = nova.u_i.get_commitments();
            let start = Instant::now();
            let mut outcome = String::new();
            for _ in 0..args.verify_reps {
                outcome = match DBase::<FC>::verify(
                    vp.clone(),
                    nova.i,
                    nova.z_0.clone(),
                    nova.z_i.clone(),
                    &running,
                    &incoming,
                    &proof,
                ) {
                    Ok(true) => "ACCEPTED".to_string(),
                    Ok(false) => "REJECTED (returned false)".to_string(),
                    Err(e) => format!("REJECTED ({e})"),
                };
            }
            println!(
                "TIME decider verify: {:.2} ms (mean of {}) -> honest proof {outcome}",
                start.elapsed().as_secs_f64() * 1000.0 / args.verify_reps as f64,
                args.verify_reps
            );
            let proof_bytes = proof.serialized_size(Compress::Yes);
            let cm_bytes =
                running.serialized_size(Compress::Yes) + incoming.serialized_size(Compress::Yes);
            let stmt_bytes = nova.i.serialized_size(Compress::Yes)
                + nova.z_0.serialized_size(Compress::Yes)
                + nova.z_i.serialized_size(Compress::Yes);
            println!(
                "SIZE proof {proof_bytes} B + instance commitments the verifier must also receive {cm_bytes} B (two vectors of two points, 8 B length prefix each) + statement (i, z_0, z_i) {stmt_bytes} B = {} B",
                proof_bytes + cm_bytes + stmt_bytes
            );
            println!("VERIFIER SEES (beyond the statement): U_i.cmW, U_i.cmE, u_i.cmW, u_i.cmE, cmT, r, 2 KZG challenges, 2 KZG evaluations, 2 KZG opening proofs, Groth16 proof");
        }
        // -------------------------------------------------------------------------------------
        "open" | "kzg" => {
            let link = if args.mode == "open" {
                LinkMode::Open
            } else {
                LinkMode::KzgEval
            };
            let start = Instant::now();
            let (pp, vp) = if args.lowmem {
                let make = || -> Box<dyn FnOnce(&std::path::Path) -> Result<(), Error>> {
                    let circuit = DZK::<FC>::setup_circuit(&nova_params, STATE_LEN, link);
                    Box::new(move |p| Ok(lowmem::store_matrices(circuit, p)?))
                };
                let (pk, vk) = lowmem_keys(make, &mpath, &args.keys)?;
                DZK::<FC>::params_from_keys(nova_params.clone(), link, pk, vk)?
            } else {
                DZK::<FC>::preprocess(OsRng, nova_params.clone(), STATE_LEN, link)?
            };
            println!("TIME decider setup: {:?}", start.elapsed());
            mem::report("after setup");
            println!(
                "KEYS prover: Groth16 proving key {} B uncompressed ({} B compressed), KZG commit key {} B; verifier: Groth16 verifying key {} B, KZG verifier key {} B, and in Open mode also the KZG commit key {} B and the augmented-circuit R1CS {} B (compressed; the R1CS can be regenerated from the step circuit)",
                pp.snark_pk.serialized_size(Compress::No),
                pp.snark_pk.serialized_size(Compress::Yes),
                pp.cs_pk.serialized_size(Compress::Yes),
                vp.snark_vp.serialized_size(Compress::Yes),
                vp.cs_vp.serialized_size(Compress::Yes),
                vp.cs_pk.serialized_size(Compress::Yes),
                vp.r1cs.serialized_size(Compress::Yes),
            );

            let nova = fold(n)?;
            println!(
                "STATEMENT: i = {}, z_0 = {}, z_i = {}",
                nova.i, nova.z_0[0], nova.z_i[0]
            );
            if let Some(zn) = &expected_zn {
                println!(
                    "CHECK z_i equals the `zn` of the fold input: {}",
                    if *zn == nova.z_i[0] { "ok" } else { "MISMATCH" }
                );
                if *zn != nova.z_i[0] {
                    std::process::exit(1);
                }
            }

            // compress a prepared circuit with the selected SNARK driver
            let compress = |circuit: DeciderEthZKCircuit<G1, G2>| -> Result<PZK, Error> {
                if args.lowmem {
                    let parts = DZK::<FC>::link_parts(&pp, &circuit)?;
                    let snark = lowmem::prove(&pp.snark_pk, &mpath, circuit, OsRng)?;
                    Ok(parts.into_proof::<Groth16<Bn254>>(snark))
                } else {
                    DZK::<FC>::prove_circuit(OsRng, &pp, circuit)
                }
            };

            // prove = blind (sample + two folds + five CycleFold folds, native) + compress
            mem::machine_state("before decider prove");
            let start = Instant::now();
            let (circuit, aux) = DeciderEthZKCircuit::<G1, G2>::from_nova(nova.clone(), link, OsRng)?;
            circuit.check_native(&aux)?;
            let t_blind = start.elapsed();
            let proof = compress(circuit)?;
            let t_total = start.elapsed();
            println!(
                "TIME decider prove: {:?} (blinding and native folds {:?}, SNARK and openings {:?})",
                t_total,
                t_blind,
                t_total - t_blind
            );
            mem::report("after prove");

            let verify = |i: Fr, z_0: &[Fr], z_i: &[Fr], p: &PZK| DZK::<FC>::verify(&vp, i, z_0, z_i, p);
            let start = Instant::now();
            let mut outcome = String::new();
            for _ in 0..args.verify_reps {
                outcome = match verify(nova.i, &nova.z_0, &nova.z_i, &proof) {
                    Ok(true) => "ACCEPTED".to_string(),
                    Ok(false) => "REJECTED (returned false)".to_string(),
                    Err(e) => format!("REJECTED ({e})"),
                };
            }
            println!(
                "TIME decider verify: {:.2} ms (mean of {}) -> honest proof {outcome}",
                start.elapsed().as_secs_f64() * 1000.0 / args.verify_reps as f64,
                args.verify_reps
            );
            let proof_bytes = proof.serialized_size(Compress::Yes);
            let stmt_bytes = nova.i.serialized_size(Compress::Yes)
                + nova.z_0.serialized_size(Compress::Yes)
                + nova.z_i.serialized_size(Compress::Yes);
            println!(
                "SIZE proof {proof_bytes} B (Groth16 {} B, 2 commitments {} B, KZG part {} B, opened U_b.u/x {} B, opened W_b {} B) + statement (i, z_0, z_i) {stmt_bytes} B = {} B",
                proof.snark_proof.serialized_size(Compress::Yes),
                proof.U_b_commitments.serialized_size(Compress::Yes),
                proof.kzg_proofs.serialized_size(Compress::Yes)
                    + proof.kzg_challenges.serialized_size(Compress::Yes),
                proof.open_u.serialized_size(Compress::Yes)
                    + proof.open_x.serialized_size(Compress::Yes),
                proof.open_W.serialized_size(Compress::Yes),
                proof_bytes + stmt_bytes
            );
            if !args.boundary_public.is_empty() {
                // link to the filing's boundary proof: its public signals start with z0, zn
                let raw = std::fs::read_to_string(&args.boundary_public)
                    .expect("boundary public json missing");
                let sig: Vec<String> = serde_json::from_str::<Vec<String>>(&raw)
                    .expect("boundary public json malformed");
                let b_z0 = Fr::from_str(&sig[0]).unwrap();
                let b_zn = Fr::from_str(&sig[1]).unwrap();
                let accepted = matches!(verify(nova.i, &[b_z0], &[b_zn], &proof), Ok(true));
                let i_u64 = {
                    use ark_ff::PrimeField;
                    nova.i.into_bigint().0[0]
                };
                let pow2 = i_u64 >= 64 && i_u64.is_power_of_two();
                println!("LINK decider proof verifies for (i = {i_u64}, z_0 = boundary public[0], z_i = boundary public[1]): {}", if accepted { "ok" } else { "FAILED" });
                println!("LINK z_0 = boundary z0: {}; z_i = boundary zn: {}; i is a power of two >= 64: {}",
                    if b_z0 == nova.z_0[0] { "ok" } else { "MISMATCH" },
                    if b_zn == nova.z_i[0] { "ok" } else { "MISMATCH" },
                    if pow2 { "ok" } else { "NO" });
                if sig.len() == 23 {
                    println!(
                        "LINK boundary public signals: y = {}, D = (proceeds {}, cost {}, income {}), C_prev = {}, C_y = {}, closing = {}",
                        sig[16], sig[17], sig[18], sig[19], sig[20], sig[21], sig[22]
                    );
                }
                if !accepted || b_z0 != nova.z_0[0] || b_zn != nova.z_i[0] || !pow2 {
                    std::process::exit(1);
                }
            }
            match link {
                LinkMode::Open => println!("VERIFIER SEES (beyond the statement): U_b = (cmW, cmE, u, x), W_b, Groth16 proof"),
                LinkMode::KzgEval => println!("VERIFIER SEES (beyond the statement): U_b.cmW, U_b.cmE, 2 KZG challenges, 2 KZG evaluations, 2 KZG opening proofs, Groth16 proof"),
            }

            if !args.skip_tests {
                let mut t = Tests {
                    passed: 0,
                    failed: 0,
                };
                let rejected =
                    |i: Fr, z_0: &[Fr], z_i: &[Fr], p: &PZK| verify(i, z_0, z_i, p).is_err();
                let (i, z0, zi) = (nova.i, nova.z_0.clone(), nova.z_i.clone());

                t.check(
                    "honest proof verifies",
                    matches!(verify(i, &z0, &zi, &proof), Ok(true)),
                );

                // wrong statement
                t.check(
                    "wrong step count (i + 1) rejected",
                    rejected(i + Fr::one(), &z0, &zi, &proof),
                );
                t.check(
                    "wrong step count (i - 1) rejected",
                    rejected(i - Fr::one(), &z0, &zi, &proof),
                );
                t.check(
                    "wrong final state rejected",
                    rejected(i, &z0, &[zi[0] + Fr::one()], &proof),
                );
                t.check(
                    "wrong initial state rejected",
                    rejected(i, &[z0[0] + Fr::one()], &zi, &proof),
                );

                // tampered public inputs carried by the proof
                let mut p = proof.clone();
                p.U_b_commitments[0] = p.U_b_commitments[0] + p.U_b_commitments[0];
                t.check("tampered public input U_b.cmW rejected", rejected(i, &z0, &zi, &p));
                let mut p = proof.clone();
                p.U_b_commitments[1] = p.U_b_commitments[1] + p.U_b_commitments[1];
                t.check("tampered public input U_b.cmE rejected", rejected(i, &z0, &zi, &p));
                match link {
                    LinkMode::KzgEval => {
                        let mut p = proof.clone();
                        p.kzg_challenges[0] += Fr::one();
                        t.check("tampered public input c_W rejected", rejected(i, &z0, &zi, &p));
                        let mut p = proof.clone();
                        p.kzg_challenges[1] += Fr::one();
                        t.check("tampered public input c_E rejected", rejected(i, &z0, &zi, &p));
                        let mut p = proof.clone();
                        p.kzg_proofs[0].eval += Fr::one();
                        t.check("tampered public input eval_W rejected", rejected(i, &z0, &zi, &p));
                        let mut p = proof.clone();
                        p.kzg_proofs[1].eval += Fr::one();
                        t.check("tampered public input eval_E rejected", rejected(i, &z0, &zi, &p));
                    }
                    LinkMode::Open => {
                        let mut p = proof.clone();
                        p.open_u[0] += Fr::one();
                        t.check("tampered public input U_b.u rejected", rejected(i, &z0, &zi, &p));
                        let mut p = proof.clone();
                        p.open_x[0] += Fr::one();
                        t.check("tampered public input U_b.x[0] rejected", rejected(i, &z0, &zi, &p));
                        let mut p = proof.clone();
                        p.open_x[1] += Fr::one();
                        t.check("tampered public input U_b.x[1] rejected", rejected(i, &z0, &zi, &p));
                    }
                }

                // tampered proof
                let mut p = proof.clone();
                p.snark_proof.a = (p.snark_proof.a.into_group() + p.snark_proof.a).into_affine();
                t.check("tampered proof (Groth16 A) rejected", rejected(i, &z0, &zi, &p));
                let mut p = proof.clone();
                p.snark_proof.c = (p.snark_proof.c.into_group() + p.snark_proof.c).into_affine();
                t.check("tampered proof (Groth16 C) rejected", rejected(i, &z0, &zi, &p));
                match link {
                    LinkMode::KzgEval => {
                        let mut p = proof.clone();
                        p.kzg_proofs[0].proof = p.kzg_proofs[0].proof + p.kzg_proofs[0].proof;
                        t.check("tampered proof (KZG opening of cmW) rejected", rejected(i, &z0, &zi, &p));
                        let mut p = proof.clone();
                        p.kzg_proofs[1].proof = p.kzg_proofs[1].proof + p.kzg_proofs[1].proof;
                        t.check("tampered proof (KZG opening of cmE) rejected", rejected(i, &z0, &zi, &p));
                    }
                    LinkMode::Open => {
                        let mut p = proof.clone();
                        p.open_W[0] += Fr::one();
                        t.check("tampered proof (opened witness, first entry) rejected", rejected(i, &z0, &zi, &p));
                        let mut p = proof.clone();
                        let last = p.open_W.len() - 1;
                        p.open_W[last] += Fr::one();
                        t.check("tampered proof (opened witness, last entry) rejected", rejected(i, &z0, &zi, &p));
                        let mut p = proof.clone();
                        p.open_W.pop();
                        t.check("tampered proof (opened witness, truncated) rejected", rejected(i, &z0, &zi, &p));
                    }
                }

                // blinding fold with a "random" instance that does NOT satisfy the relation:
                // one entry of its error vector is changed and the commitment recomputed, so all
                // commitments open correctly and only the relation fails.
                let (mut W_r, mut U_r) =
                    sample_relaxed_instance::<G1, K>(&nova.r1cs, &nova.cs_pp, OsRng)?;
                W_r.E[0] += Fr::one();
                U_r.cmE = <K as CommitmentScheme<G1>>::commit(&nova.cs_pp, &W_r.E, &Fr::zero())?;
                let unsat = nova.r1cs.check_relation(&W_r, &U_r).is_err();
                let (bad, bad_aux) = DeciderEthZKCircuit::<G1, G2>::from_nova_with_blinder(
                    nova.clone(),
                    link,
                    W_r,
                    U_r,
                    OsRng,
                )?;
                let native_fails = bad.check_native(&bad_aux).is_err();
                let bad_proof = compress(bad)?;
                t.check(
                    "blinding with a non-satisfying random instance rejected by the verifier",
                    unsat && native_fails && rejected(i, &z0, &zi, &bad_proof),
                );

                // fresh blinding
                let (circuit2, aux2) =
                    DeciderEthZKCircuit::<G1, G2>::from_nova(nova.clone(), link, OsRng)?;
                circuit2.check_native(&aux2)?;
                let proof2 = compress(circuit2)?;
                t.check(
                    "second proof of the same statement verifies",
                    matches!(verify(i, &z0, &zi, &proof2), Ok(true)),
                );
                let mut fresh = proof.snark_proof != proof2.snark_proof
                    && proof.U_b_commitments[0] != proof2.U_b_commitments[0]
                    && proof.U_b_commitments[1] != proof2.U_b_commitments[1];
                match link {
                    LinkMode::KzgEval => {
                        fresh &= proof.kzg_challenges[0] != proof2.kzg_challenges[0]
                            && proof.kzg_challenges[1] != proof2.kzg_challenges[1]
                            && proof.kzg_proofs[0].eval != proof2.kzg_proofs[0].eval
                            && proof.kzg_proofs[1].eval != proof2.kzg_proofs[1].eval
                            && proof.kzg_proofs[0].proof != proof2.kzg_proofs[0].proof
                            && proof.kzg_proofs[1].proof != proof2.kzg_proofs[1].proof;
                    }
                    LinkMode::Open => {
                        fresh &= proof.open_u != proof2.open_u
                            && proof.open_x[0] != proof2.open_x[0]
                            && proof.open_x[1] != proof2.open_x[1]
                            && proof
                                .open_W
                                .iter()
                                .zip(&proof2.open_W)
                                .all(|(a, b)| a != b);
                    }
                }
                t.check(
                    "two proofs of the same statement share no commitment, evaluation, opened value or SNARK element",
                    fresh,
                );

                println!("TESTS: {} passed, {} failed", t.passed, t.failed);
                mem::report("after tests");
                if t.failed > 0 {
                    std::process::exit(1);
                }
            }

            // a second statement with another number of steps, same keys
            if !args.extra_input.is_empty() {
                let (z_0b, extb) = load(&args.extra_input);
                println!("EXTRA: {} steps from {}", extb.len(), args.extra_input);
                let nova_b = fold_with(&z_0b, &extb, extb.len())?;
                println!(
                    "EXTRA STATEMENT: i = {}, z_0 = {}, z_i = {}",
                    nova_b.i, nova_b.z_0[0], nova_b.z_i[0]
                );
                {
                    let raw = std::fs::read_to_string(&args.extra_input).expect("input json missing");
                    let v: serde_json::Value =
                        serde_json::from_str(&raw).expect("input json malformed");
                    if let Some(zn) = v.get("zn").and_then(|x| x.as_str()) {
                        let ok = Fr::from_str(zn).unwrap() == nova_b.z_i[0];
                        println!(
                            "EXTRA CHECK z_i equals the `zn` of the fold input: {}",
                            if ok { "ok" } else { "MISMATCH" }
                        );
                        if !ok {
                            std::process::exit(1);
                        }
                    }
                }
                let start = Instant::now();
                let (circuit_b, aux_b) =
                    DeciderEthZKCircuit::<G1, G2>::from_nova(nova_b.clone(), link, OsRng)?;
                circuit_b.check_native(&aux_b)?;
                let proof_b = compress(circuit_b)?;
                println!("EXTRA TIME decider prove: {:?}", start.elapsed());
                let start = Instant::now();
                let res = verify(nova_b.i, &nova_b.z_0, &nova_b.z_i, &proof_b);
                println!(
                    "EXTRA TIME decider verify: {:.2} ms -> honest proof {}",
                    start.elapsed().as_secs_f64() * 1000.0,
                    match &res {
                        Ok(true) => "ACCEPTED".to_string(),
                        Ok(false) => "REJECTED (returned false)".to_string(),
                        Err(e) => format!("REJECTED ({e})"),
                    }
                );
                // the proof for this statement must not verify for the first statement
                let cross = verify(nova.i, &nova.z_0, &nova.z_i, &proof_b).is_err();
                println!(
                    "EXTRA: proof of the {}-step statement checked against the {}-step statement: {}",
                    extb.len(),
                    n,
                    if cross { "rejected (as it must be)" } else { "ACCEPTED (ERROR)" }
                );
                println!("EXTRA SIZE proof {} B", proof_b.serialized_size(Compress::Yes));
                mem::report("after extra");
                if !matches!(res, Ok(true)) || !cross {
                    std::process::exit(1);
                }
            }
        }
        other => {
            eprintln!("unknown mode: {other}");
            std::process::exit(2);
        }
    }
    // silence "unused" for helpers that only some modes use
    let _ = Fr::zero();
    Ok(())
}

// =============================================================================================
// The end-to-end path of the artifact: `prove` (taxpayer side) and `verify` (authority side),
// plus two checks that need no SNARK (`tamper`, `same-r1cs`).
// =============================================================================================

fn banner(args: &Args, frontend: &str) {
    let light = cfg!(feature = "light");
    println!(
        "BUILD: {}",
        if light {
            "REDUCED decider circuits (sonobe `light-test`: CycleFold checks compiled out; NOT a sound proof)"
        } else {
            "FULL decider circuits"
        }
    );
    if args.require_full && light {
        eprintln!("--require-full given, but this binary was built with `--features light`. Refusing to run.");
        std::process::exit(3);
    }
    println!("MODE: {}", args.mode);
    println!("FRONTEND: {frontend}");
}

fn need(flag: &str, value: &str) {
    if value.is_empty() {
        eprintln!("missing {flag}");
        std::process::exit(2);
    }
}

/// `{ "n", "z0": [..], "zn": "..", "steps": [[E strings] x n] }`
fn load_fold_input<const E: usize>(path: &str) -> (Vec<Fr>, Vec<Vec<Fr>>, Option<Fr>) {
    let raw = std::fs::read_to_string(path).expect("input json missing");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("input json malformed");
    let z_0: Vec<Fr> = v["z0"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| Fr::from_str(x.as_str().unwrap()).unwrap())
        .collect();
    let steps: Vec<Vec<Fr>> = v["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            s.as_array()
                .unwrap()
                .iter()
                .map(|x| Fr::from_str(x.as_str().unwrap()).unwrap())
                .collect()
        })
        .collect();
    assert_eq!(z_0.len(), STATE_LEN, "z0 length != STATE_LEN");
    assert!(
        steps.iter().all(|e| e.len() == E),
        "a step's external inputs length != --ext-len"
    );
    let zn = v
        .get("zn")
        .and_then(|x| x.as_str())
        .map(|x| Fr::from_str(x).unwrap());
    (z_0, steps, zn)
}

type NovaParams<FC> = (
    <N<FC> as FoldingScheme<G1, G2, FC>>::ProverParam,
    <N<FC> as FoldingScheme<G1, G2, FC>>::VerifierParam,
);

/// Loads the stored Nova parameters (they must exist: matrices and keys belong to them).
fn load_nova_params<FC: StepFrontend<E>, const E: usize>(
    args: &Args,
) -> Result<NovaParams<FC>, Error> {
    need("--params", &args.params);
    if !std::path::Path::new(&args.params).exists() {
        eprintln!(
            "{} does not exist: run the setup once (`--mode open --lowmem --matrices .. --params .. --keys ..`)",
            args.params
        );
        std::process::exit(2);
    }
    let bytes = std::fs::read(&args.params)?;
    let mut r = &bytes[..];
    let pp = N::<FC>::pp_deserialize_with_mode(
        &mut r,
        Compress::No,
        Validate::No,
        FC::make_params(&args.r1cs, &args.wasm),
    )?;
    let vp = N::<FC>::vp_deserialize_with_mode(
        &mut r,
        Compress::No,
        Validate::No,
        FC::make_params(&args.r1cs, &args.wasm),
    )?;
    Ok((pp, vp))
}

struct FoldStats {
    total: std::time::Duration,
    min: std::time::Duration,
    max: std::time::Duration,
    n: usize,
}

impl FoldStats {
    fn line(&self) -> String {
        format!(
            "{} steps in {:.1} s: mean {:.3} s per step, min {:.3} s, max {:.3} s",
            self.n,
            self.total.as_secs_f64(),
            self.total.as_secs_f64() / self.n.max(1) as f64,
            self.min.as_secs_f64(),
            self.max.as_secs_f64()
        )
    }
}

/// Folds every step; does NOT verify the IVC proof (the caller does).
fn fold_timed<FC: StepFrontend<E>, const E: usize>(
    nova_params: &NovaParams<FC>,
    f_circuit: &FC,
    z_0: &[Fr],
    steps: &[Vec<Fr>],
) -> Result<(N<FC>, FoldStats), Error> {
    let mut nova = N::<FC>::init(nova_params, f_circuit.clone(), z_0.to_vec())?;
    let mut st = FoldStats {
        total: std::time::Duration::ZERO,
        min: std::time::Duration::MAX,
        max: std::time::Duration::ZERO,
        n: steps.len(),
    };
    for ext in steps {
        let t = Instant::now();
        nova.prove_step(OsRng, VecF(ext.clone()), None)?;
        let dt = t.elapsed();
        st.total += dt;
        st.min = st.min.min(dt);
        st.max = st.max.max(dt);
    }
    Ok((nova, st))
}

fn u64_of(x: &Fr) -> Option<u64> {
    use ark_ff::PrimeField;
    let b = x.into_bigint().0;
    if b[1..].iter().all(|l| *l == 0) {
        Some(b[0])
    } else {
        None
    }
}

fn link_of(format: &str) -> LinkMode {
    match format {
        "open" => LinkMode::Open,
        "kzg" => LinkMode::KzgEval,
        other => {
            eprintln!("unknown --format {other} (open | kzg)");
            std::process::exit(2);
        }
    }
}

/// One-time setup for one final-proof format: Nova parameters (commitment keys; loaded if the
/// file exists), the matrices of the decider circuit, the Groth16 key. No fold input needed.
fn cmd_setup<FC: StepFrontend<E>, const E: usize>(args: &Args) -> Result<(), Error> {
    banner(args, FC::NAME);
    need("--params", &args.params);
    need("--matrices", &args.matrices);
    need("--keys", &args.keys);
    let link = link_of(&args.format);
    let mpath = PathBuf::from(&args.matrices);
    let kpath = PathBuf::from(&args.keys);
    let write_vk = |vk: &ark_groth16::VerifyingKey<Bn254>| -> Result<(), Error> {
        if !args.vk.is_empty() {
            let mut vk_bytes = vec![];
            vk.serialize_compressed(&mut vk_bytes)?;
            std::fs::write(&args.vk, &vk_bytes)?;
            println!(
                "decider verification key ({} B) written to {}",
                vk_bytes.len(),
                args.vk
            );
        }
        Ok(())
    };
    if std::path::Path::new(&args.params).exists()
        && kpath.exists()
        && lowmem::matrices_exist(&mpath)
    {
        println!(
            "SETUP: {}, {} and {} exist already; nothing is regenerated (delete them to start from scratch)",
            args.params, args.matrices, args.keys
        );
        let (_, vk) = lowmem::load_key(&kpath)?;
        write_vk(&vk)?;
        return Ok(());
    }
    mem::machine_state("before setup");
    let t0 = Instant::now();

    let t = Instant::now();
    let nova_params: NovaParams<FC> = if std::path::Path::new(&args.params).exists() {
        let p = load_nova_params::<FC, E>(args)?;
        println!("NOVA PARAMS: loaded from {} ({:?})", args.params, t.elapsed());
        p
    } else {
        let f_circuit = FC::new(FC::make_params(&args.r1cs, &args.wasm))?;
        let p = N::<FC>::preprocess(
            OsRng,
            &PreprocessorParam::new(poseidon_canonical_config::<Fr>(), f_circuit),
        )?;
        let mut bytes = vec![];
        p.0.serialize_uncompressed(&mut bytes)?;
        p.1.serialize_uncompressed(&mut bytes)?;
        std::fs::write(&args.params, &bytes)?;
        println!(
            "NOVA PARAMS: created and stored in {} ({} B, {:?})",
            args.params,
            bytes.len(),
            t.elapsed()
        );
        p
    };
    println!(
        "AUGMENTED CIRCUIT: constraints {}, witnesses {}; CYCLEFOLD CIRCUIT: constraints {}",
        nova_params.1.r1cs.n_constraints(),
        nova_params.1.r1cs.n_witnesses(),
        nova_params.1.cf_r1cs.n_constraints()
    );

    let t = Instant::now();
    let circuit = DZK::<FC>::setup_circuit(&nova_params, STATE_LEN, link);
    lowmem::store_matrices(circuit, &mpath)?;
    println!("TIME matrix extraction: {:.1} s", t.elapsed().as_secs_f64());
    mem::report("after matrix extraction");
    mem::machine_state("before key generation");
    let t = Instant::now();
    let (pk, vk) = lowmem::setup_from_matrices(&mpath, OsRng)?;
    println!("TIME key generation: {:.1} s", t.elapsed().as_secs_f64());
    let t = Instant::now();
    lowmem::save_key(&pk, &kpath)?;
    println!("TIME storing the key: {:.1} s", t.elapsed().as_secs_f64());
    println!(
        "TIME setup total: {:.1} s",
        t0.elapsed().as_secs_f64()
    );
    println!(
        "KEYS Groth16 proving key {} B uncompressed (file {}), Groth16 verification key {} B compressed, KZG commit key {} B, KZG verifier key {} B",
        pk.serialized_size(Compress::No),
        args.keys,
        vk.serialized_size(Compress::Yes),
        nova_params.0.cs_pp.serialized_size(Compress::Yes),
        nova_params.1.cs_vp.serialized_size(Compress::Yes),
    );
    write_vk(&vk)?;
    mem::report("after setup");
    Ok(())
}

/// Taxpayer side: fold the steps of one filing, blind, compress, and write the compressing proof,
/// its public values and the decider's verification key into `--out`.
fn cmd_prove<FC: StepFrontend<E>, const E: usize>(args: &Args) -> Result<(), Error> {
    banner(args, FC::NAME);
    need("--input", &args.input);
    need("--matrices", &args.matrices);
    need("--keys", &args.keys);
    need("--out", &args.out);
    let link = link_of(&args.format);
    let mpath = PathBuf::from(&args.matrices);
    let kpath = PathBuf::from(&args.keys);
    if !kpath.exists() || !lowmem::matrices_exist(&mpath) {
        eprintln!("the Groth16 key or the matrix files are missing: run the setup once (`--mode open|kzg --lowmem --matrices .. --params .. --keys ..`)");
        std::process::exit(2);
    }
    let (z_0, steps, expected_zn) = load_fold_input::<E>(&args.input);
    println!("INPUT: {} ({} steps)", args.input, steps.len());

    let f_circuit = FC::new(FC::make_params(&args.r1cs, &args.wasm))?;
    let nova_params = load_nova_params::<FC, E>(args)?;
    println!(
        "AUGMENTED CIRCUIT: constraints {}, witnesses {}",
        nova_params.1.r1cs.n_constraints(),
        nova_params.1.r1cs.n_witnesses()
    );

    // ---- fold (the proving key is not loaded yet, so the memory figure is the fold's) ----
    mem::machine_state("before fold");
    let (nova, st) = fold_timed::<FC, E>(&nova_params, &f_circuit, &z_0, &steps)?;
    println!("TIME fold: {}", st.line());
    let t = Instant::now();
    N::<FC>::verify(nova_params.1.clone(), nova.ivc_proof())?;
    println!("IVC verify: OK ({:?})", t.elapsed());
    mem::report("after fold (Nova parameters and fold only; no proving key loaded yet)");
    println!(
        "STATEMENT: i = {}, z_0 = {}, z_i = {}",
        nova.i, nova.z_0[0], nova.z_i[0]
    );
    if let Some(zn) = expected_zn {
        let ok = zn == nova.z_i[0];
        println!(
            "CHECK z_i equals the `zn` of the fold input: {}",
            if ok { "ok" } else { "MISMATCH" }
        );
        if !ok {
            std::process::exit(1);
        }
    }

    // ---- key ----
    let t = Instant::now();
    let (pk, vk) = lowmem::load_key(&kpath)?;
    println!("TIME load proving key: {:?}", t.elapsed());
    let (pp, vp) = DZK::<FC>::params_from_keys(nova_params.clone(), link, pk, vk)?;

    // ---- blind + compress ----
    mem::machine_state("before blinding and compression");
    let t = Instant::now();
    let (circuit, aux) = DeciderEthZKCircuit::<G1, G2>::from_nova(nova.clone(), link, OsRng)?;
    circuit.check_native(&aux)?;
    let t_blind = t.elapsed();
    let parts = DZK::<FC>::link_parts(&pp, &circuit)?;
    let snark = lowmem::prove(&pp.snark_pk, &mpath, circuit, OsRng)?;
    let proof: PZK = parts.into_proof::<Groth16<Bn254>>(snark);
    let t_total = t.elapsed();
    println!(
        "TIME blind + compress: {:.1} s (blinding and native folds {:.2} s, SNARK {:.1} s)",
        t_total.as_secs_f64(),
        t_blind.as_secs_f64(),
        (t_total - t_blind).as_secs_f64()
    );
    mem::report("after blind + compress (whole process)");

    // ---- prover's own check ----
    let t = Instant::now();
    let mut ok = true;
    for _ in 0..args.verify_reps {
        ok &= matches!(
            DZK::<FC>::verify(&vp, nova.i, &nova.z_0, &nova.z_i, &proof),
            Ok(true)
        );
    }
    println!(
        "TIME verify (prover's own check): {:.1} ms (mean of {}) -> {}",
        t.elapsed().as_secs_f64() * 1000.0 / args.verify_reps as f64,
        args.verify_reps,
        if ok { "ACCEPTED" } else { "REJECTED" }
    );

    // ---- output ----
    std::fs::create_dir_all(&args.out)?;
    let mut bytes = vec![];
    proof.serialize_compressed(&mut bytes)?;
    let proof_path = format!("{}/decider_proof.bin", args.out);
    std::fs::write(&proof_path, &bytes)?;
    let public = serde_json::json!({
        "format": args.format,
        "i": nova.i.to_string(),
        "z_0": nova.z_0.iter().map(|x| x.to_string()).collect::<Vec<_>>(),
        "z_i": nova.z_i.iter().map(|x| x.to_string()).collect::<Vec<_>>(),
    });
    let public_path = format!("{}/decider_public.json", args.out);
    std::fs::write(&public_path, serde_json::to_string_pretty(&public).unwrap())?;
    println!(
        "SIZE proof {} B (file {proof_path}); public values (format, i, z_0, z_i) in {public_path}",
        bytes.len()
    );
    if !ok {
        std::process::exit(1);
    }
    Ok(())
}

/// Authority side: checks the compressing proof and, if given, the boundary proof and the link
/// between the two. Needs no proving key and no matrix files.
fn cmd_verify<FC: StepFrontend<E>, const E: usize>(args: &Args) -> Result<(), Error> {
    banner(args, FC::NAME);
    need("--proof", &args.proof);
    need("--public", &args.public);
    need("--vk", &args.vk);
    mem::machine_state("before verification");

    // the authority's own material: step circuit, commitment parameters, decider verification key
    let t = Instant::now();
    let nova_params = load_nova_params::<FC, E>(args)?;
    let vk = ark_groth16::VerifyingKey::<Bn254>::deserialize_compressed(
        &std::fs::read(&args.vk)?[..],
    )?;
    println!("TIME load verifier material (step circuit, commitment key, verification key): {:?}", t.elapsed());

    // what the taxpayer sent
    let raw = std::fs::read_to_string(&args.public)?;
    let public: serde_json::Value = serde_json::from_str(&raw).expect("public json malformed");
    let fr = |v: &serde_json::Value| Fr::from_str(v.as_str().expect("decimal string")).expect("field element");
    let i = fr(&public["i"]);
    let z_0: Vec<Fr> = public["z_0"].as_array().expect("z_0").iter().map(fr).collect();
    let z_i: Vec<Fr> = public["z_i"].as_array().expect("z_i").iter().map(fr).collect();
    let link = match public["format"].as_str() {
        Some("kzg") => LinkMode::KzgEval,
        _ => LinkMode::Open,
    };
    let proof_bytes = std::fs::read(&args.proof)?;
    let proof = match PZK::deserialize_compressed(&proof_bytes[..]) {
        Ok(p) => p,
        Err(e) => {
            println!("AUTHORITY check 1, compressing proof: MALFORMED ({e})");
            println!("AUTHORITY: filing REJECTED");
            std::process::exit(1);
        }
    };
    println!(
        "RECEIVED: compressing proof {} B, statement i = {}, z_0 = {}, z_i = {}",
        proof_bytes.len(),
        i,
        z_0[0],
        z_i[0]
    );

    let vp = folding_schemes::folding::nova::decider_eth_zk::VerifierParam {
        link,
        pp_hash: nova_params.1.pp_hash()?,
        snark_vp: vk,
        cs_vp: nova_params.1.cs_vp.clone(),
        cs_pk: nova_params.0.cs_pp.clone(),
        r1cs: nova_params.1.r1cs.clone(),
    };
    let t = Instant::now();
    let mut c1 = true;
    let mut err = String::new();
    for _ in 0..args.verify_reps {
        match DZK::<FC>::verify(&vp, i, &z_0, &z_i, &proof) {
            Ok(true) => {}
            Ok(false) => c1 = false,
            Err(e) => {
                c1 = false;
                err = format!(" ({e})");
            }
        }
    }
    println!(
        "AUTHORITY check 1, compressing proof verifies for (i, z_0, z_i): {}{err}   [{:.1} ms, mean of {}]",
        if c1 { "ok" } else { "FAILED" },
        t.elapsed().as_secs_f64() * 1000.0 / args.verify_reps as f64,
        args.verify_reps
    );

    // step-count rule of the filing statement
    let c2 = u64_of(&i).map(|n| n >= 64 && n.is_power_of_two()).unwrap_or(false);
    println!(
        "AUTHORITY check 2, step count is a power of two of at least 64: {}",
        if c2 { "ok" } else { "FAILED" }
    );

    let mut all = c1 && c2;
    if !args.boundary_proof.is_empty() {
        need("--boundary-public", &args.boundary_public);
        need("--boundary-vkey", &args.boundary_vkey);
        fn fail<T>(what: String) -> T {
            println!("AUTHORITY check 3, boundary proof: MALFORMED ({what})");
            println!("AUTHORITY: filing REJECTED");
            std::process::exit(1)
        }
        let bvk = snarkjs::load_vkey(&args.boundary_vkey).unwrap_or_else(fail);
        let bproof = snarkjs::load_proof(&args.boundary_proof).unwrap_or_else(fail);
        let (sig, sig_fr) = snarkjs::load_public(&args.boundary_public).unwrap_or_else(fail);
        let t = Instant::now();
        let mut c3 = true;
        for _ in 0..args.verify_reps {
            c3 &= snarkjs::verify(&bvk, &sig_fr, &bproof).unwrap_or(false);
        }
        println!(
            "AUTHORITY check 3, boundary Groth16 proof verifies under the given key ({} public signals): {}   [{:.1} ms, mean of {}]",
            sig.len(),
            if c3 { "ok" } else { "FAILED" },
            t.elapsed().as_secs_f64() * 1000.0 / args.verify_reps as f64,
            args.verify_reps
        );
        let c4 = sig_fr.len() >= 23 && sig_fr[0] == z_0[0];
        let c5 = sig_fr.len() >= 23 && sig_fr[1] == z_i[0];
        println!(
            "AUTHORITY check 4, start digest: z_0 of the compressing proof = boundary public signal z0: {}",
            if c4 { "ok" } else { "FAILED" }
        );
        println!(
            "AUTHORITY check 5, end digest: z_i of the compressing proof = boundary public signal zn: {}",
            if c5 { "ok" } else { "FAILED" }
        );
        all = all && c3 && c4 && c5;
        if sig.len() >= 23 {
            // layout: z0, zn, tags[NT], cid[2], acaddr[2], root_rcl[2], root_unl[2], root_at[2],
            // root_psl[2], y, d_proceeds, d_cost, d_income, c_prev, c_y, closing
            let l = sig.len();
            println!(
                "BOUNDARY PUBLIC SIGNALS: {} tag slots, y = {}, C_prev = {}, closing = {}",
                l - 21,
                sig[l - 7],
                sig[l - 3],
                sig[l - 1]
            );
            println!(
                "NOTE: the authority must also compare the tag list, chain ids, contract addresses, roots, y and C_prev in these signals with its own values (not done by this command)."
            );
            if all {
                println!(
                    "D = (proceeds {}, cost {}, income {})",
                    sig[l - 6],
                    sig[l - 5],
                    sig[l - 4]
                );
                println!("C_y = {}", sig[l - 2]);
            }
        }
    } else {
        println!("(no boundary proof given: only the compressing proof was checked)");
    }
    mem::report("after verification");
    if all {
        println!("AUTHORITY: filing ACCEPTED");
        Ok(())
    } else {
        println!("AUTHORITY: filing REJECTED");
        std::process::exit(1);
    }
}

/// No SNARK: one external input of one step is changed; the fold must not verify.
fn cmd_tamper<FC: StepFrontend<E>, const E: usize>(args: &Args) -> Result<(), Error> {
    banner(args, FC::NAME);
    need("--input", &args.input);
    let (z_0, mut steps, _) = load_fold_input::<E>(&args.input);
    let f_circuit = FC::new(FC::make_params(&args.r1cs, &args.wasm))?;
    let nova_params = if args.params.is_empty() {
        N::<FC>::preprocess(
            OsRng,
            &PreprocessorParam::new(poseidon_canonical_config::<Fr>(), f_circuit.clone()),
        )?
    } else {
        load_nova_params::<FC, E>(args)?
    };
    let s = args.tamper_step.min(steps.len() - 1);
    let j = args.tamper_index.min(E - 1);
    let k = (s + 3).min(steps.len());
    let honest: Vec<Vec<Fr>> = steps[..k].to_vec();
    steps[s][j] += Fr::one();
    println!(
        "TAMPER: external input {j} of step {s} increased by 1; folding the first {k} steps of {}",
        args.input
    );

    let rejected = match fold_timed::<FC, E>(&nova_params, &f_circuit, &z_0, &steps[..k]) {
        Err(e) => {
            println!("TAMPER fold: stopped by an error in prove_step ({e})");
            true
        }
        Ok((nova, st)) => {
            println!("TAMPER fold: {}", st.line());
            let ivc = N::<FC>::verify(nova_params.1.clone(), nova.ivc_proof());
            println!(
                "TAMPER IVC verifier: {}",
                match &ivc {
                    Err(e) => format!("rejected ({e})"),
                    Ok(()) => "ACCEPTED (ERROR)".to_string(),
                }
            );
            let native =
                DeciderEthZKCircuit::<G1, G2>::from_nova(nova.clone(), LinkMode::Open, OsRng)
                    .and_then(|(circuit, aux)| circuit.check_native(&aux));
            println!(
                "TAMPER decider, native check of the blinded pair: {}",
                if native.is_err() { "rejected" } else { "ACCEPTED (ERROR)" }
            );
            ivc.is_err() && native.is_err()
        }
    };
    // control: the same steps without the change
    let (nova, _) = fold_timed::<FC, E>(&nova_params, &f_circuit, &z_0, &honest)?;
    let control = N::<FC>::verify(nova_params.1.clone(), nova.ivc_proof()).is_ok();
    println!(
        "TAMPER control (same {k} steps, unchanged): {}",
        if control { "accepted" } else { "REJECTED (ERROR)" }
    );
    println!(
        "TAMPER result: {}",
        if rejected && control { "the tampered fold fails, as it must" } else { "ERROR" }
    );
    if !(rejected && control) {
        std::process::exit(1);
    }
    Ok(())
}

/// Do the two frontends give the same augmented circuit, and do stored parameters and the hash
/// of the public parameters agree for both?
fn cmd_same_r1cs<const E: usize>(args: &Args) -> Result<(), Error> {
    banner(args, "both (comparison)");
    use folding_schemes::folding::nova::get_r1cs;
    let cfg = poseidon_canonical_config::<Fr>();
    let a = <CircomFCircuit<Fr, STATE_LEN, E> as FCircuit<Fr>>::new(<CircomFCircuit<
        Fr,
        STATE_LEN,
        E,
    > as StepFrontend<E>>::make_params(
        &args.r1cs, &args.wasm
    ))?;
    let b = <CachedCircomFCircuit<E> as FCircuit<Fr>>::new(
        <CachedCircomFCircuit<E> as StepFrontend<E>>::make_params(&args.r1cs, &args.wasm),
    )?;
    let (ra, cfa) = get_r1cs::<G1, G2, _>(&cfg, a)?;
    let (rb, cfb) = get_r1cs::<G1, G2, _>(&cfg, b)?;
    println!(
        "SAME-R1CS sonobe frontend: augmented circuit {} constraints, {} witnesses; cached frontend: {} constraints, {} witnesses",
        ra.n_constraints(),
        ra.n_witnesses(),
        rb.n_constraints(),
        rb.n_witnesses()
    );
    let same = ra == rb;
    let same_cf = cfa == cfb;
    println!(
        "SAME-R1CS augmented circuit matrices A, B, C identical entry by entry: {}",
        if same { "yes" } else { "NO" }
    );
    println!(
        "SAME-R1CS CycleFold circuit identical: {}",
        if same_cf { "yes" } else { "NO" }
    );
    let mut ok = same && same_cf;
    if !args.params.is_empty() && std::path::Path::new(&args.params).exists() {
        let pa = load_nova_params::<CircomFCircuit<Fr, STATE_LEN, E>, E>(args)?;
        let pb = load_nova_params::<CachedCircomFCircuit<E>, E>(args)?;
        let (ha, hb) = (pa.1.pp_hash()?, pb.1.pp_hash()?);
        let stored_same = pa.1.r1cs == ra && pb.1.r1cs == rb;
        println!(
            "SAME-R1CS stored Nova parameters {}: pp_hash with the sonobe frontend = {}, with the cached frontend = {}: {}",
            args.params,
            ha,
            hb,
            if ha == hb { "equal" } else { "DIFFERENT" }
        );
        println!(
            "SAME-R1CS augmented circuit rebuilt from the stored parameters equals the fresh one: {}",
            if stored_same { "yes" } else { "NO" }
        );
        ok = ok && ha == hb && stored_same;
    }
    if !ok {
        std::process::exit(1);
    }
    Ok(())
}

/// No SNARK: the fold alone, with its time per step and memory.
fn cmd_fold<FC: StepFrontend<E>, const E: usize>(args: &Args) -> Result<(), Error> {
    banner(args, FC::NAME);
    need("--input", &args.input);
    let (z_0, steps, expected_zn) = load_fold_input::<E>(&args.input);
    println!("INPUT: {} ({} steps)", args.input, steps.len());
    let t = Instant::now();
    let f_circuit = FC::new(FC::make_params(&args.r1cs, &args.wasm))?;
    println!("TIME frontend construction: {:?}", t.elapsed());
    let nova_params = if args.params.is_empty() {
        N::<FC>::preprocess(
            OsRng,
            &PreprocessorParam::new(poseidon_canonical_config::<Fr>(), f_circuit.clone()),
        )?
    } else {
        load_nova_params::<FC, E>(args)?
    };
    mem::machine_state("before fold");
    let (nova, st) = fold_timed::<FC, E>(&nova_params, &f_circuit, &z_0, &steps)?;
    println!("TIME fold: {}", st.line());
    let t = Instant::now();
    N::<FC>::verify(nova_params.1.clone(), nova.ivc_proof())?;
    println!("IVC verify: OK ({:?})", t.elapsed());
    mem::report("after fold");
    if let Some(zn) = expected_zn {
        let ok = zn == nova.z_i[0];
        println!(
            "CHECK z_i equals the `zn` of the fold input: {}",
            if ok { "ok" } else { "MISMATCH" }
        );
        if !ok {
            std::process::exit(1);
        }
    }
    Ok(())
}
