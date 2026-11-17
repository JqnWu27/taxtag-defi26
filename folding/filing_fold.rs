#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]
// TaxTag filing fold driver. Folds the padded step sequence of
// circuits/filing/c_fstep.circom with Nova + CycleFold (sonobe pinned at
// 9414c45, circom frontend, state length 1, 117 external inputs), verifies
// the IVC proof, and exposes the start and end state digests and the step
// count, the three values the boundary proof and the decider share.
//
// Built as an example of the pinned sonobe clone (folding/setup_filing_fold.sh).
// The clone carries one change to
// sonobe, folding/basecase_z0.patch: the augmented circuit enforces
// z_i = z_0 at step 0, so the chain provably starts at the claimed z_0.
//
// Usage:
//   filing_fold <fold_input.json> [--r1cs <c_fstep.r1cs>] [--wasm <c_fstep.wasm>]
//               [--out <fold_output.json>] [--cached-witness] [--witness-only <K>]
//   fold_input.json = { "n": steps, "z0": ["<digest>"], "zn": "<expected>",
//                       "steps": [[117 field elements as decimal strings], ...] }
//   optional "claimed_z0": "<digest>" (negative test): the proof claims this
//   start digest while the chain is run from "z0"; a sound IVC must reject it
//   default            sonobe's own CircomFCircuit (compiles the wasm module
//                      again at every step)
//   --cached-witness   CachedCircomFCircuit below: the same R1CS and the same
//                      constraints, the wasm module compiled once
//   --witness-only K   no folding; times sonobe's step witness generation
//                      alone on the first K steps
// Exit code 0: IVC verified and z_n equals the expected digest. 2: IVC
// verification failed (a step of the sequence does not satisfy the circuit).
// 3: verified but z_n differs from the expected digest.
use ark_bn254::{Bn254, Fr, G1Projective as G1};
use ark_circom::{
    circom::{r1cs_reader, R1CS as CircomR1CS},
    WitnessCalculator,
};
use ark_ff::PrimeField;
use ark_grumpkin::Projective as G2;
use ark_r1cs_std::{
    fields::fp::{AllocatedFp, FpVar},
    R1CSVar,
};
use ark_relations::{
    lc,
    r1cs::{ConstraintSystemRef, SynthesisError, Variable},
};
use num_bigint::{BigInt, BigUint};
use wasmer::{Module, Store};

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use experimental_frontends::{
    circom::CircomFCircuit,
    utils::{VecF, VecFpVar},
};
use folding_schemes::arith::ArithRelation;
use folding_schemes::frontend::FCircuit;
use folding_schemes::{
    commitment::{kzg::KZG, pedersen::Pedersen},
    folding::{
        nova::{Nova, PreprocessorParam},
        traits::CommittedInstanceOps,
    },
    transcript::poseidon::poseidon_canonical_config,
    Error, FoldingScheme,
};

const STATE_LEN: usize = 1;
const EXT_INP_LEN: usize = 117;

fn dec(x: &Fr) -> String {
    x.into_bigint().to_string()
}

// ---------------------------------------------------------------------------
// CachedCircomFCircuit: sonobe's CircomFCircuit (experimental-frontends/src/
// circom/mod.rs at rev 9414c45, MIT) with ONE change: the wasm module is
// compiled and instantiated once, in `new`, and the same witness calculator
// is reused at every step. sonobe's own wrapper builds a new wasmer store
// and compiles the module again inside every `generate_step_constraints`.
// The R1CS, the variable layout and the constraints are identical.
// ---------------------------------------------------------------------------
#[derive(Clone)]
pub struct CachedCircomFCircuit {
    r1cs: CircomR1CS<Fr>,
    calc: Arc<Mutex<(Store, WitnessCalculator)>>,
    // the wasm runtime of ark-circom expects a Tokio context (sonobe's wrapper
    // creates a runtime per call); one runtime is kept for the calculator
    rt: Arc<tokio::runtime::Runtime>,
}

impl std::fmt::Debug for CachedCircomFCircuit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CachedCircomFCircuit({} constraints)", self.r1cs.constraints.len())
    }
}

impl CachedCircomFCircuit {
    fn witness(&self, inputs: Vec<(String, Vec<BigInt>)>) -> Result<Vec<Fr>, Error> {
        let _ctx = self.rt.enter();
        let mut guard = self.calc.lock().unwrap();
        let (store, calc) = &mut *guard;
        let w = calc
            .calculate_witness(store, inputs, true)
            .map_err(|e| Error::WitnessCalculationError(format!("{e}")))?;
        w.into_iter()
            .map(|b| {
                b.to_biguint().map(Fr::from).ok_or_else(|| {
                    Error::ConversionError("BigInt".into(), "BigUint".into(), "negative".into())
                })
            })
            .collect()
    }

    fn fpvars_to_bigints(fpvars: &[FpVar<Fr>]) -> Vec<BigInt> {
        fpvars
            .value()
            .unwrap_or(vec![Fr::from(0u32); fpvars.len()])
            .into_iter()
            .map(Into::<BigUint>::into)
            .map(BigInt::from)
            .collect()
    }
}

impl FCircuit<Fr> for CachedCircomFCircuit {
    /// (r1cs_path, wasm_path)
    type Params = (PathBuf, PathBuf);
    type ExternalInputs = VecF<Fr, EXT_INP_LEN>;
    type ExternalInputsVar = VecFpVar<Fr, EXT_INP_LEN>;

    fn new(params: Self::Params) -> Result<Self, Error> {
        let (r1cs_path, wasm_path) = params;
        let r1cs_bytes = std::fs::read(r1cs_path)?;
        let wasm_bytes = std::fs::read(wasm_path)?;
        let r1cs_file = r1cs_reader::R1CSFile::new(std::io::Cursor::new(&r1cs_bytes))?;
        let mut r1cs = r1cs_reader::R1CS::from(r1cs_file);
        r1cs.wire_mapping = None;
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let _ctx = rt.enter();
        let mut store = Store::default();
        let module = Module::new(&store, &wasm_bytes)
            .map_err(|e| Error::WitnessCalculationError(format!("wasm module: {e}")))?;
        let calc = WitnessCalculator::from_module(&mut store, module)
            .map_err(|e| Error::WitnessCalculationError(format!("witness calculator: {e}")))?;
        drop(_ctx);
        Ok(Self { r1cs, calc: Arc::new(Mutex::new((store, calc))), rt: Arc::new(rt) })
    }

    fn state_len(&self) -> usize {
        STATE_LEN
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<Fr>,
        _i: usize,
        z_i: Vec<FpVar<Fr>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
        let inputs_map = vec![
            ("ivc_input".to_string(), Self::fpvars_to_bigints(&z_i)),
            ("external_inputs".to_string(), Self::fpvars_to_bigints(&external_inputs.0)),
        ];
        // witness layout: [1, z_{i+1} (outputs), z_i, external_inputs, aux]
        let witness = self.witness(inputs_map).map_err(|_| SynthesisError::AssignmentMissing)?;

        let mut circom_index_to_cs_index = vec![Variable::One];
        let mut z_i1 = vec![];
        for &w in witness.iter().skip(1).take(STATE_LEN) {
            let v = cs.new_witness_variable(|| Ok(w))?;
            circom_index_to_cs_index.push(v);
            z_i1.push(FpVar::Var(AllocatedFp::new(Some(w), v, cs.clone())));
        }
        for v in z_i.iter().chain(&external_inputs.0) {
            match v {
                FpVar::Var(v) => circom_index_to_cs_index.push(v.variable),
                _ => unreachable!(),
            };
        }
        for w in witness.into_iter().skip(circom_index_to_cs_index.len()) {
            circom_index_to_cs_index.push(cs.new_witness_variable(|| Ok(w))?);
        }
        let fold_lc = |lc, &(i, coeff)| lc + (coeff, circom_index_to_cs_index[i]);
        for (a, b, c) in &self.r1cs.constraints {
            cs.enforce_constraint(
                a.iter().fold(lc!(), fold_lc),
                b.iter().fold(lc!(), fold_lc),
                c.iter().fold(lc!(), fold_lc),
            )?;
        }
        Ok(z_i1)
    }
}

#[cfg(windows)]
fn peak_working_set_mb() -> Option<u64> {
    #[repr(C)]
    struct Pmc {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> *mut core::ffi::c_void;
        fn K32GetProcessMemoryInfo(h: *mut core::ffi::c_void, p: *mut Pmc, cb: u32) -> i32;
    }
    unsafe {
        let mut pmc: Pmc = core::mem::zeroed();
        pmc.cb = core::mem::size_of::<Pmc>() as u32;
        if K32GetProcessMemoryInfo(GetCurrentProcess(), &mut pmc, pmc.cb) != 0 {
            Some(pmc.peak_working_set_size as u64 / (1024 * 1024))
        } else {
            None
        }
    }
}

#[cfg(not(windows))]
fn peak_working_set_mb() -> Option<u64> {
    // VmHWM in /proc/self/status, in kB
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let kb: u64 = rest.trim().trim_end_matches("kB").trim().parse().ok()?;
            return Some(kb / 1024);
        }
    }
    None
}

fn arg_after(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|p| args.get(p + 1).cloned())
}

struct Job {
    z_0: Vec<Fr>,
    steps: Vec<Vec<Fr>>,
    expected_zn: Option<Fr>,
    // negative test only: the z_0 the prover CLAIMS while the chain is
    // started at job.z_0 (fold input field "claimed_z0")
    claimed_z0: Option<Fr>,
    out_path: Option<String>,
    frontend: &'static str,
}

// One fold run for a given FCircuit type (the two frontends differ only in
// how the witness is computed).
macro_rules! define_fold {
    ($name:ident, $fc:ty) => {
        fn $name(f_circuit: $fc, job: Job) -> Result<i32, Error> {
            type N = Nova<G1, G2, $fc, KZG<'static, Bn254>, Pedersen<G2>, false>;
            let n = job.steps.len();
            let poseidon_config = poseidon_canonical_config::<Fr>();
            let mut rng = ark_std::rand::rngs::OsRng;

            let t = Instant::now();
            let nova_preprocess_params = PreprocessorParam::new(poseidon_config, f_circuit.clone());
            let nova_params = N::preprocess(&mut rng, &nova_preprocess_params)?;
            let preprocess = t.elapsed();
            println!("frontend: {}", job.frontend);
            println!("preprocess: {:?}", preprocess);
            println!("augmented step R1CS: {} constraints, {} variables; CycleFold R1CS: {} constraints",
                nova_params.1.r1cs.A.n_rows, nova_params.1.r1cs.A.n_cols, nova_params.1.cf_r1cs.A.n_rows);

            let t = Instant::now();
            let start = job.claimed_z0.map(|c| vec![c]).unwrap_or_else(|| job.z_0.clone());
            let mut nova = N::init(&nova_params, f_circuit.clone(), start)?;
            if job.claimed_z0.is_some() {
                // a dishonest prover: every step is valid, but the chain runs
                // from job.z_0 while the proof claims another start digest
                nova.z_i = job.z_0.clone();
                println!("claimed z_0 = {}, chain started at {}", dec(&nova.z_0[0]), dec(&job.z_0[0]));
            }
            let init = t.elapsed();
            println!("init: {:?}", init);

            let mut total = Duration::ZERO;
            let mut min = Duration::MAX;
            let mut max = Duration::ZERO;
            for (k, ext) in job.steps.iter().enumerate() {
                let t = Instant::now();
                nova.prove_step(rng, VecF(ext.clone()), None)?;
                let dt = t.elapsed();
                total += dt;
                if dt < min { min = dt; }
                if dt > max { max = dt; }
                if k < 3 || k == n - 1 || (k + 1) % 128 == 0 {
                    println!("  step {k}: {dt:?}");
                }
            }
            let avg = total / n as u32;
            println!("folded {n} steps: total {:?}, avg/step {:?}, min {:?}, max {:?}", total, avg, min, max);

            let t = Instant::now();
            let ivc_proof = nova.ivc_proof();
            let verified = match N::verify(nova_params.1.clone(), ivc_proof) {
                Ok(()) => true,
                Err(e) => {
                    println!("IVC verify error: {e:?}");
                    let p = nova.ivc_proof();
                    println!("  check_incoming(u_i): {:?}", p.u_i.check_incoming());
                    println!("  r1cs(w_i, u_i): {:?}", nova_params.1.r1cs.check_relation(&p.w_i, &p.u_i));
                    println!("  r1cs(W_i, U_i): {:?}", nova_params.1.r1cs.check_relation(&p.W_i, &p.U_i));
                    println!("  cf_r1cs(cf_W_i, cf_U_i): {:?}",
                        nova_params.1.cf_r1cs.check_relation(&p.cf_W_i, &p.cf_U_i));
                    false
                }
            };
            let ivc_verify = t.elapsed();
            if verified {
                println!("IVC verify: OK in {:?}", ivc_verify);
            } else {
                println!("IVC verify: FAILED in {:?}", ivc_verify);
            }

            let zn = nova.z_i[0];
            let zn_ok = job.expected_zn.map(|e| e == zn);
            println!("steps = {}", nova.i);
            println!("z_0 = {}", dec(&nova.z_0[0]));
            println!("z_n = {}", dec(&zn));
            match zn_ok {
                Some(true) => println!("z_n equals the reference digest: yes"),
                Some(false) => println!("z_n equals the reference digest: NO"),
                None => {}
            }
            let peak = peak_working_set_mb();
            if let Some(mb) = peak {
                println!("peak working set: {} MB", mb);
            }

            if let Some(p) = &job.out_path {
                let out = serde_json::json!({
                    "frontend": job.frontend,
                    "steps": n,
                    "z0": dec(&nova.z_0[0]),
                    "zn": dec(&zn),
                    "ivc_verified": verified,
                    "zn_matches_reference": zn_ok,
                    "preprocess_ms": preprocess.as_millis() as u64,
                    "init_ms": init.as_millis() as u64,
                    "fold_total_ms": total.as_millis() as u64,
                    "fold_avg_ms": avg.as_millis() as u64,
                    "fold_min_ms": min.as_millis() as u64,
                    "fold_max_ms": max.as_millis() as u64,
                    "ivc_verify_ms": ivc_verify.as_millis() as u64,
                    "peak_working_set_mb": peak,
                });
                std::fs::write(p, serde_json::to_string_pretty(&out).unwrap()).expect("write output");
            }
            Ok(if !verified { 2 } else if zn_ok == Some(false) { 3 } else { 0 })
        }
    };
}

define_fold!(fold_stock, CircomFCircuit<Fr, STATE_LEN, EXT_INP_LEN>);
define_fold!(fold_cached, CachedCircomFCircuit);

fn main() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().collect();
    let input_path = args.get(1).cloned().expect(
        "usage: filing_fold <fold_input.json> [--r1cs p] [--wasm p] [--out p] [--cached-witness] [--witness-only K]");
    let r1cs_path = PathBuf::from(
        arg_after(&args, "--r1cs").unwrap_or_else(|| "build/c_fstep.r1cs".into()),
    );
    let wasm_path = PathBuf::from(
        arg_after(&args, "--wasm").unwrap_or_else(|| "build/c_fstep_js/c_fstep.wasm".into()),
    );
    let out_path = arg_after(&args, "--out");
    let cached = args.iter().any(|a| a == "--cached-witness");

    let raw = std::fs::read_to_string(&input_path).expect("fold input missing");
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let z_0: Vec<Fr> = v["z0"].as_array().unwrap().iter()
        .map(|x| Fr::from_str(x.as_str().unwrap()).unwrap()).collect();
    let steps: Vec<Vec<Fr>> = v["steps"].as_array().unwrap().iter()
        .map(|s| s.as_array().unwrap().iter()
            .map(|x| Fr::from_str(x.as_str().unwrap()).unwrap()).collect())
        .collect();
    let expected_zn: Option<Fr> = v["zn"].as_str().map(|s| Fr::from_str(s).unwrap());
    let claimed_z0: Option<Fr> = v["claimed_z0"].as_str().map(|s| Fr::from_str(s).unwrap());
    let n = steps.len();
    assert_eq!(z_0.len(), STATE_LEN, "z0 length");
    assert!(n > 0, "no steps");
    for s in &steps {
        assert_eq!(s.len(), EXT_INP_LEN, "external input length");
    }

    // --witness-only K: time the step witness generation alone (the circom
    // wasm run through sonobe's CircomWrapper, exactly what the stock
    // frontend calls inside prove_step, or through the cached calculator)
    // on the first K steps, without folding.
    if let Some(k) = arg_after(&args, "--witness-only") {
        use experimental_frontends::circom::utils::CircomWrapper;
        let k: usize = k.parse().expect("--witness-only <steps>");
        let done = k.min(n);
        let to_bi = |x: &Fr| BigInt::from(BigUint::from(*x));
        let inputs_of = |z: &Fr, ext: &Vec<Fr>| vec![
            ("ivc_input".to_string(), vec![to_bi(z)]),
            ("external_inputs".to_string(), ext.iter().map(to_bi).collect::<Vec<_>>()),
        ];
        let wrapper = CircomWrapper::new(r1cs_path.clone().into(), wasm_path.clone().into())?;
        let mut z = z_0[0];
        let mut total = Duration::ZERO;
        let mut wires = 0usize;
        for ext in steps.iter().take(done) {
            let t = Instant::now();
            let w: Vec<Fr> = wrapper.extract_witness(inputs_of(&z, ext))?;
            total += t.elapsed();
            wires = w.len();
            z = w[1];
        }
        println!("witness generation alone, sonobe's wrapper (module compiled at every step): {} steps, avg {:?} per step, {} wires",
            done, total / done as u32, wires);
        let z_stock = z;

        let t = Instant::now();
        let cachedc = CachedCircomFCircuit::new((r1cs_path.clone(), wasm_path.clone()))?;
        let setup = t.elapsed();
        let mut z = z_0[0];
        let mut total = Duration::ZERO;
        for ext in steps.iter().take(done) {
            let t = Instant::now();
            let w = cachedc.witness(inputs_of(&z, ext))?;
            total += t.elapsed();
            z = w[1];
        }
        println!("witness generation alone, cached calculator (module compiled once, {:?}): {} steps, avg {:?} per step",
            setup, done, total / done as u32);
        println!("z after {} steps = {} (both ways equal: {})", done, dec(&z), z == z_stock);
        return Ok(());
    }

    let job = Job { z_0, steps, expected_zn, claimed_z0, out_path,
                    frontend: if cached { "cached witness calculator" } else { "sonobe CircomFCircuit" } };
    let code = if cached {
        fold_cached(CachedCircomFCircuit::new((r1cs_path, wasm_path))?, job)?
    } else {
        type FC = CircomFCircuit<Fr, STATE_LEN, EXT_INP_LEN>;
        fold_stock(FC::new((r1cs_path.into(), wasm_path.into()))?, job)?
    };
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}
