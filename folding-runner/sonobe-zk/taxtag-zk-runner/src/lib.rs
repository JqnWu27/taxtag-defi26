//! Small helpers shared by the runner binary and the tests.

/// Process memory accounting and a self-imposed memory cap.
///
/// The decider circuits are large (the full ones are around ten million constraints) and this
/// machine is shared with other jobs. Every heavy entry point of this crate therefore starts
/// `mem::start_guard`, which makes the process EXIT (code 99) as soon as its own committed memory
/// exceeds a cap, instead of pushing the whole machine into swap or into allocation failures.
/// Cap: environment variable `TAXTAG_MEM_CAP_GB` (default 20). The guard also exits (code 98) when
/// the whole machine has less than `TAXTAG_SYS_FLOOR_GB` (default 1.5) of commit left.
pub mod mem {
    #[cfg(windows)]
    mod sys {
        #[repr(C)]
        #[allow(non_snake_case)]
        pub struct ProcessMemoryCounters {
            pub cb: u32,
            pub PageFaultCount: u32,
            pub PeakWorkingSetSize: usize,
            pub WorkingSetSize: usize,
            pub QuotaPeakPagedPoolUsage: usize,
            pub QuotaPagedPoolUsage: usize,
            pub QuotaPeakNonPagedPoolUsage: usize,
            pub QuotaNonPagedPoolUsage: usize,
            pub PagefileUsage: usize,
            pub PeakPagefileUsage: usize,
        }
        #[repr(C)]
        #[allow(non_snake_case)]
        pub struct MemoryStatusEx {
            pub dwLength: u32,
            pub dwMemoryLoad: u32,
            pub ullTotalPhys: u64,
            pub ullAvailPhys: u64,
            pub ullTotalPageFile: u64,
            pub ullAvailPageFile: u64,
            pub ullTotalVirtual: u64,
            pub ullAvailVirtual: u64,
            pub ullAvailExtendedVirtual: u64,
        }
        #[link(name = "kernel32")]
        extern "system" {
            pub fn GetCurrentProcess() -> isize;
            pub fn K32GetProcessMemoryInfo(
                process: isize,
                counters: *mut ProcessMemoryCounters,
                cb: u32,
            ) -> i32;
            pub fn GlobalMemoryStatusEx(status: *mut MemoryStatusEx) -> i32;
            pub fn GetSystemTimes(idle: *mut u64, kernel: *mut u64, user: *mut u64) -> i32;
        }
    }

    /// (free physical memory, free commit) of the machine, in bytes.
    #[cfg(windows)]
    pub fn system_free() -> Option<(u64, u64)> {
        let mut st = std::mem::MaybeUninit::<sys::MemoryStatusEx>::zeroed();
        // SAFETY: as in `system_available_commit`.
        unsafe {
            (*st.as_mut_ptr()).dwLength = std::mem::size_of::<sys::MemoryStatusEx>() as u32;
            if sys::GlobalMemoryStatusEx(st.as_mut_ptr()) == 0 {
                return None;
            }
            let st = st.assume_init();
            Some((st.ullAvailPhys, st.ullAvailPageFile))
        }
    }

    #[cfg(not(windows))]
    pub fn system_free() -> Option<(u64, u64)> {
        None
    }

    /// CPU load of the whole machine in percent, averaged over half a second.
    #[cfg(windows)]
    pub fn cpu_load_percent() -> Option<f64> {
        // FILETIME is two u32 (low, high): read as one little-endian u64 of 100 ns units
        let sample = || -> Option<(u64, u64, u64)> {
            let (mut idle, mut kernel, mut user) = (0u64, 0u64, 0u64);
            // SAFETY: three writable 8-byte locations, the layout of FILETIME.
            let ok = unsafe { sys::GetSystemTimes(&mut idle, &mut kernel, &mut user) };
            if ok == 0 {
                None
            } else {
                Some((idle, kernel, user))
            }
        };
        let a = sample()?;
        std::thread::sleep(std::time::Duration::from_millis(500));
        let b = sample()?;
        let idle = (b.0 - a.0) as f64;
        // kernel time includes idle time
        let total = ((b.1 - a.1) + (b.2 - a.2)) as f64;
        if total <= 0.0 {
            return None;
        }
        Some(100.0 * (1.0 - idle / total))
    }

    #[cfg(not(windows))]
    pub fn cpu_load_percent() -> Option<f64> {
        None
    }

    /// One line with the state of the machine: CPU load and free memory. Printed before every
    /// timed phase so that each timing carries the conditions it was taken under. Note that the
    /// load includes whatever this process itself is doing in other threads at that moment.
    pub fn machine_state(label: &str) {
        let cpu = cpu_load_percent();
        let free = system_free();
        match (cpu, free) {
            (Some(c), Some((phys, commit))) => println!(
                "MACHINE {label}: CPU load {:.0} %, free physical memory {:.1} GB, free commit {:.1} GB",
                c,
                gb(phys),
                gb(commit)
            ),
            _ => println!("MACHINE {label}: not available on this platform"),
        }
    }

    /// System-wide commit charge still available (what any process on the machine can still
    /// allocate), in bytes.
    #[cfg(windows)]
    pub fn system_available_commit() -> Option<u64> {
        let mut st = std::mem::MaybeUninit::<sys::MemoryStatusEx>::zeroed();
        // SAFETY: `st` is a writable MEMORYSTATUSEX; dwLength is set before the call as the API
        // requires.
        unsafe {
            (*st.as_mut_ptr()).dwLength = std::mem::size_of::<sys::MemoryStatusEx>() as u32;
            if sys::GlobalMemoryStatusEx(st.as_mut_ptr()) == 0 {
                return None;
            }
            Some(st.assume_init().ullAvailPageFile)
        }
    }

    #[cfg(not(windows))]
    pub fn system_available_commit() -> Option<u64> {
        None
    }

    /// Memory figures of the current process, in bytes.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct Usage {
        /// peak working set (physical memory) so far
        pub peak_working_set: u64,
        /// peak committed (private) memory so far
        pub peak_commit: u64,
        /// committed (private) memory now
        pub commit: u64,
    }

    #[cfg(windows)]
    pub fn usage() -> Option<Usage> {
        let mut c = std::mem::MaybeUninit::<sys::ProcessMemoryCounters>::zeroed();
        let cb = std::mem::size_of::<sys::ProcessMemoryCounters>() as u32;
        // SAFETY: `c` is a properly sized, writable PROCESS_MEMORY_COUNTERS and the pseudo handle
        // returned by GetCurrentProcess is always valid for the calling process.
        let ok = unsafe { sys::K32GetProcessMemoryInfo(sys::GetCurrentProcess(), c.as_mut_ptr(), cb) };
        if ok == 0 {
            return None;
        }
        // SAFETY: the call succeeded, so the struct has been filled in.
        let c = unsafe { c.assume_init() };
        Some(Usage {
            peak_working_set: c.PeakWorkingSetSize as u64,
            peak_commit: c.PeakPagefileUsage as u64,
            commit: c.PagefileUsage as u64,
        })
    }

    #[cfg(not(windows))]
    pub fn usage() -> Option<Usage> {
        None
    }

    pub fn gb(bytes: u64) -> f64 {
        bytes as f64 / (1u64 << 30) as f64
    }

    /// One-line report, e.g. after a phase of the runner.
    pub fn report(label: &str) {
        match usage() {
            Some(u) => println!(
                "MEM {label}: peak working set {:.2} GB, peak commit {:.2} GB (cumulative since process start)",
                gb(u.peak_working_set),
                gb(u.peak_commit)
            ),
            None => println!("MEM {label}: not available on this platform"),
        }
    }

    /// Starts (once per process) a background thread that exits the process when its committed
    /// memory exceeds the cap.
    pub fn start_guard() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let cap_gb: f64 = std::env::var("TAXTAG_MEM_CAP_GB")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(20.0);
            let floor_gb: f64 = std::env::var("TAXTAG_SYS_FLOOR_GB")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1.5);
            std::thread::spawn(move || loop {
                if let Some(u) = usage() {
                    if gb(u.commit) > cap_gb {
                        eprintln!(
                            "MEMORY CAP EXCEEDED: committed {:.1} GB > cap {:.1} GB (TAXTAG_MEM_CAP_GB). Exiting with code 99.",
                            gb(u.commit),
                            cap_gb
                        );
                        std::process::exit(99);
                    }
                    // be a good neighbour: if the whole machine is about to run out of commit
                    // and this process is a large consumer, leave instead of starving the others
                    if let Some(avail) = system_available_commit() {
                        if gb(avail) < floor_gb && gb(u.commit) > 2.0 {
                            eprintln!(
                                "SYSTEM MEMORY FLOOR REACHED: {:.1} GB of commit left on the machine (< {:.1} GB, TAXTAG_SYS_FLOOR_GB) while this process holds {:.1} GB. Exiting with code 98.",
                                gb(avail),
                                floor_gb,
                                gb(u.commit)
                            );
                            std::process::exit(98);
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            });
        });
    }
}

/// Low-memory driver for Groth16 over BN254 on very large circuits.
///
/// Why it exists. The full decider circuits have about nine million constraints AND about 310
/// million non-zero matrix entries (the in-circuit Pedersen commitment of the pinned r1cs-std
/// keeps intermediate curve points as linear combinations, so its rows are long). The standard
/// arkworks path holds the whole constraint system, its inlined rows and a copy of the matrices
/// in memory, during setup and again during proving, next to a proving key of several GB. Three
/// attempts on this 32 GB machine stopped above 19, 20.7 and 23 GB.
///
/// What it does. It never holds the matrices in memory:
///
/// - `store_matrices`: synthesizes the real circuit once in setup mode and writes the rows of its
///   R1CS matrices to three files as they are produced (through the one method added to the
///   vendored ark-relations, see `sonobe-zk/vendor/ark-relations/Cargo.toml`);
/// - `StreamQAP`: an implementation of ark-groth16's `R1CSToQAP` trait (the R1CS-to-QAP reduction
///   is a type parameter of `Groth16`). It performs the same arithmetic as arkworks'
///   `LibsnarkReduction`, with every loop over matrix rows replaced by a pass over the files;
/// - `setup`: arkworks' `Groth16::<Bn254, StreamQAP>::generate_random_parameters_with_reduction`
///   on `ShapeCircuit`, a circuit with the right numbers of variables and constraints and no
///   content (the generator takes the content from the reduction);
/// - `prove`: synthesizes the real circuit for its witness only (`construct_matrices: false`) and
///   calls arkworks' `Groth16::<Bn254, StreamQAP>::create_proof_with_reduction_and_matrices` with
///   fresh `r`, `s`.
///
/// What it does not change: the sampling of the setup randomness, the computation of every key
/// element from the QAP evaluations, the assembly of the proof from the quotient polynomial, and
/// the verifier (`Groth16::<Bn254>::verify`, unmodified). A mistake in this driver would make
/// honest proofs fail to verify; it cannot make the verifier accept more.
pub mod lowmem {
    use ark_bn254::{Bn254, Fr};
    use ark_ff::PrimeField;
    use ark_groth16::{
        r1cs_to_qap::{LibsnarkReduction, R1CSToQAP},
        Groth16, Proof, ProvingKey, VerifyingKey,
    };
    use ark_poly::EvaluationDomain;
    use ark_relations::{
        lc,
        r1cs::{
            ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef,
            OptimizationGoal, SynthesisError, SynthesisMode,
        },
    };
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::{
        rand::{CryptoRng, RngCore},
        UniformRand,
    };
    use rayon::prelude::*;
    use std::fs::File;
    use std::io::{BufReader, BufWriter, Write};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    /// rows are processed in batches of this many
    const BATCH: usize = 1 << 13;

    fn io_err(e: impl std::fmt::Display) -> SynthesisError {
        eprintln!("lowmem: {e}");
        SynthesisError::AssignmentMissing
    }

    fn part(path: &Path, suffix: &str) -> PathBuf {
        let mut s = path.as_os_str().to_owned();
        s.push(suffix);
        PathBuf::from(s)
    }

    /// `[instance variables, witness variables, constraints, nnz A, nnz B, nnz C]`
    pub fn read_dims(path: &Path) -> Result<Vec<u64>, SynthesisError> {
        let mut r = BufReader::new(File::open(path).map_err(io_err)?);
        let dims = Vec::<u64>::deserialize_uncompressed_unchecked(&mut r).map_err(io_err)?;
        if dims.len() != 6 {
            return Err(io_err("malformed matrix file"));
        }
        Ok(dims)
    }

    pub fn matrices_exist(path: &Path) -> bool {
        path.exists()
            && part(path, ".a").exists()
            && part(path, ".b").exists()
            && part(path, ".c").exists()
    }

    /// Calls `f(first_row_index, rows)` for consecutive batches of rows of one matrix file.
    fn for_each_batch<F: PrimeField>(
        path: &Path,
        suffix: &str,
        n_rows: usize,
        mut f: impl FnMut(usize, &[Vec<(F, usize)>]),
    ) -> Result<(), SynthesisError> {
        let mut r = BufReader::with_capacity(
            1 << 24,
            File::open(part(path, suffix)).map_err(io_err)?,
        );
        // length prefix of the serialized `Vec<Row>`
        let len = u64::deserialize_uncompressed_unchecked(&mut r).map_err(io_err)? as usize;
        if len != n_rows {
            return Err(io_err("matrix file does not match its header"));
        }
        let mut batch = Vec::with_capacity(BATCH);
        let mut first = 0;
        for i in 0..n_rows {
            batch.push(
                Vec::<(F, usize)>::deserialize_uncompressed_unchecked(&mut r).map_err(io_err)?,
            );
            if batch.len() == BATCH || i + 1 == n_rows {
                f(first, &batch);
                first = i + 1;
                batch.clear();
            }
        }
        Ok(())
    }

    /// Synthesizes `circuit` in setup mode and writes its R1CS matrices to `path` (+ `.a`, `.b`,
    /// `.c`), row by row.
    ///
    /// The rows are produced by `ConstraintSystem::stream_inlined_constraint_rows`, the one method
    /// added to the vendored ark-relations: it yields exactly the rows of `to_matrices()`, but one
    /// at a time and while freeing the constraint system, so the peak memory of this step is that
    /// of the synthesis itself.
    pub fn store_matrices<C: ConstraintSynthesizer<Fr>>(
        circuit: C,
        path: &Path,
    ) -> Result<(), SynthesisError> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Setup);
        circuit.generate_constraints(cs.clone())?;
        let n_inst = cs.num_instance_variables();
        let n_wit = cs.num_witness_variables();
        let n_cons = cs.num_constraints();

        // each file is the serialization of a `Vec<Row>`: row count first, then the rows
        let mut writers = Vec::with_capacity(3);
        for suffix in [".a", ".b", ".c"] {
            let mut w = BufWriter::with_capacity(
                1 << 24,
                File::create(part(path, suffix)).map_err(io_err)?,
            );
            (n_cons as u64).serialize_uncompressed(&mut w).map_err(io_err)?;
            writers.push(w);
        }
        let mut nnz = [0usize; 3];
        let mut failed = false;
        let emitted = {
            let mut inner = cs.borrow_mut().ok_or(SynthesisError::MissingCS)?;
            inner.stream_inlined_constraint_rows(&mut |k, row| {
                nnz[k as usize] += row.len();
                if row.serialize_uncompressed(&mut writers[k as usize]).is_err() {
                    failed = true;
                }
            })
        };
        drop(cs);
        if failed || emitted != Some([n_cons; 3]) {
            return Err(io_err("writing the matrix rows failed"));
        }
        for mut w in writers {
            w.flush().map_err(io_err)?;
        }
        let dims: Vec<u64> = vec![
            n_inst as u64,
            n_wit as u64,
            n_cons as u64,
            nnz[0] as u64,
            nnz[1] as u64,
            nnz[2] as u64,
        ];
        let mut w = BufWriter::new(File::create(path).map_err(io_err)?);
        dims.serialize_uncompressed(&mut w).map_err(io_err)?;
        w.flush().map_err(io_err)?;
        println!(
            "LOWMEM matrices: {} constraints, {} instance variables, {} witness variables, non-zeros A {} B {} C {}",
            n_cons, n_inst, n_wit, nnz[0], nnz[1], nnz[2]
        );
        Ok(())
    }

    /// The matrix files that `StreamQAP` reads. The trait's functions are static, so the location
    /// is process-global; `setup` and `prove` set it.
    static MATRIX_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);

    fn set_path(path: &Path) {
        *MATRIX_PATH.lock().unwrap() = Some(path.to_path_buf());
    }

    fn current_path() -> Result<PathBuf, SynthesisError> {
        MATRIX_PATH
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| io_err("matrix path not set"))
    }

    /// ark-groth16's `LibsnarkReduction` with the matrix rows read from disk.
    pub struct StreamQAP;

    impl R1CSToQAP for StreamQAP {
        /// Same computation as `LibsnarkReduction::instance_map_with_evaluation`: for every
        /// variable `j`, `a[j] = sum_i u_i · A[i][j]` (likewise `b`, `c`), where `u_i` are the
        /// Lagrange coefficients at `t`.
        #[allow(clippy::type_complexity)]
        fn instance_map_with_evaluation<F: PrimeField, D: EvaluationDomain<F>>(
            cs: ConstraintSystemRef<F>,
            t: &F,
        ) -> Result<(Vec<F>, Vec<F>, Vec<F>, F, usize, usize), SynthesisError> {
            let path = current_path()?;
            let dims = read_dims(&path)?;
            let (n_inst, n_wit, n_cons) = (dims[0] as usize, dims[1] as usize, dims[2] as usize);
            // the circuit handed to the generator must have the shape of the stored matrices
            if cs.num_instance_variables() != n_inst
                || cs.num_witness_variables() != n_wit
                || cs.num_constraints() != n_cons
            {
                return Err(io_err("circuit shape differs from the stored matrices"));
            }
            drop(cs);

            let domain_size = n_cons + n_inst;
            let domain = D::new(domain_size).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
            let domain_size = domain.size();
            let zt = domain.evaluate_vanishing_polynomial(*t);
            let u = domain.evaluate_all_lagrange_coefficients(*t);

            let qap_num_variables = (n_inst - 1) + n_wit;
            let mut a = vec![F::zero(); qap_num_variables + 1];
            let mut b = vec![F::zero(); qap_num_variables + 1];
            let mut c = vec![F::zero(); qap_num_variables + 1];
            a[0..n_inst].copy_from_slice(&u[n_cons..(n_cons + n_inst)]);

            // one pass per file; the three passes run concurrently
            let pass = |suffix: &str, m: &mut Vec<F>| -> Result<(), SynthesisError> {
                for_each_batch::<F>(&path, suffix, n_cons, |first, rows| {
                    for (k, row) in rows.iter().enumerate() {
                        let u_i = u[first + k];
                        for (coeff, index) in row {
                            m[*index] += u_i * coeff;
                        }
                    }
                })
            };
            let (ra, (rb, rc)) = rayon::join(
                || pass(".a", &mut a),
                || rayon::join(|| pass(".b", &mut b), || pass(".c", &mut c)),
            );
            ra?;
            rb?;
            rc?;

            Ok((a, b, c, zt, qap_num_variables, domain_size))
        }

        /// Same computation as `LibsnarkReduction::witness_map_from_matrices`; the argument
        /// `matrices` is ignored (it is empty), the rows come from the files.
        fn witness_map_from_matrices<F: PrimeField, D: EvaluationDomain<F>>(
            _matrices: &ConstraintMatrices<F>,
            num_inputs: usize,
            num_constraints: usize,
            full_assignment: &[F],
        ) -> Result<Vec<F>, SynthesisError> {
            let path = current_path()?;
            let dims = read_dims(&path)?;
            if dims[0] as usize != num_inputs
                || dims[2] as usize != num_constraints
                || (dims[0] + dims[1]) as usize != full_assignment.len()
            {
                return Err(io_err("witness does not match the stored matrices"));
            }

            let domain = D::new(num_constraints + num_inputs)
                .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
            let domain_size = domain.size();
            let zero = F::zero();

            // out[i] = <row i, full_assignment>
            let eval = |suffix: &str, out: &mut Vec<F>| -> Result<(), SynthesisError> {
                for_each_batch::<F>(&path, suffix, num_constraints, |first, rows| {
                    out[first..first + rows.len()]
                        .par_iter_mut()
                        .zip(rows.par_iter())
                        .for_each(|(o, row)| {
                            let mut acc = F::zero();
                            for (coeff, index) in row {
                                let val = full_assignment[*index];
                                if coeff.is_one() {
                                    acc += val;
                                } else {
                                    acc += val * coeff;
                                }
                            }
                            *o = acc;
                        });
                })
            };

            let mut a = vec![zero; domain_size];
            let mut b = vec![zero; domain_size];
            eval(".a", &mut a)?;
            eval(".b", &mut b)?;
            a[num_constraints..(num_constraints + num_inputs)]
                .clone_from_slice(&full_assignment[..num_inputs]);

            domain.ifft_in_place(&mut a);
            domain.ifft_in_place(&mut b);

            let coset_domain = domain.get_coset(F::GENERATOR).unwrap();

            coset_domain.fft_in_place(&mut a);
            coset_domain.fft_in_place(&mut b);

            let mut ab = domain.mul_polynomials_in_evaluation_domain(&a, &b);
            drop(a);
            drop(b);

            let mut c = vec![zero; domain_size];
            eval(".c", &mut c)?;

            domain.ifft_in_place(&mut c);
            coset_domain.fft_in_place(&mut c);

            let vanishing_polynomial_over_coset = domain
                .evaluate_vanishing_polynomial(F::GENERATOR)
                .inverse()
                .unwrap();
            ab.par_iter_mut().zip(c).for_each(|(ab_i, c_i)| {
                *ab_i -= &c_i;
                *ab_i *= &vanishing_polynomial_over_coset;
            });

            coset_domain.ifft_in_place(&mut ab);

            Ok(ab)
        }

        fn h_query_scalars<F: PrimeField, D: EvaluationDomain<F>>(
            max_power: usize,
            t: F,
            zt: F,
            delta_inverse: F,
        ) -> Result<Vec<F>, SynthesisError> {
            LibsnarkReduction::h_query_scalars::<F, D>(max_power, t, zt, delta_inverse)
        }
    }

    /// A circuit with the given numbers of instance variables, witness variables and constraints
    /// and no content. Given to arkworks' generator together with `StreamQAP`, which supplies the
    /// content from the stored matrices (and checks that the shapes agree).
    pub struct ShapeCircuit {
        n_inst: usize,
        n_wit: usize,
        n_cons: usize,
    }

    impl ShapeCircuit {
        pub fn from_matrices(path: &Path) -> Result<Self, SynthesisError> {
            let dims = read_dims(path)?;
            Ok(Self {
                n_inst: dims[0] as usize,
                n_wit: dims[1] as usize,
                n_cons: dims[2] as usize,
            })
        }
    }

    impl ConstraintSynthesizer<Fr> for ShapeCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            if !cs.is_in_setup_mode() {
                // this circuit carries no witness; it exists for key generation only
                return Err(SynthesisError::AssignmentMissing);
            }
            // variable 0 of the instance is the constant one, already allocated
            for _ in 1..self.n_inst {
                cs.new_input_variable(|| Err(SynthesisError::AssignmentMissing))?;
            }
            for _ in 0..self.n_wit {
                cs.new_witness_variable(|| Err(SynthesisError::AssignmentMissing))?;
            }
            for _ in 0..self.n_cons {
                cs.enforce_constraint(lc!(), lc!(), lc!())?;
            }
            Ok(())
        }
    }

    /// Groth16 circuit-specific setup for the circuit whose matrices are stored at `path`.
    pub fn setup_from_matrices(
        path: &Path,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), SynthesisError> {
        set_path(path);
        let pk = Groth16::<Bn254, StreamQAP>::generate_random_parameters_with_reduction(
            ShapeCircuit::from_matrices(path)?,
            &mut rng,
        )?;
        let vk = pk.vk.clone();
        Ok((pk, vk))
    }

    /// `store_matrices` followed by `setup_from_matrices`.
    pub fn setup<C: ConstraintSynthesizer<Fr>>(
        circuit: C,
        path: &Path,
        rng: impl RngCore + CryptoRng,
    ) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), SynthesisError> {
        store_matrices(circuit, path)?;
        setup_from_matrices(path, rng)
    }

    /// Writes the proving key (which contains the verifying key) to a file, uncompressed.
    pub fn save_key(pk: &ProvingKey<Bn254>, file: &Path) -> Result<(), SynthesisError> {
        let mut w = BufWriter::with_capacity(1 << 24, File::create(file).map_err(io_err)?);
        pk.serialize_uncompressed(&mut w).map_err(io_err)?;
        w.flush().map_err(io_err)
    }

    /// Reads a proving key written by `save_key` (no validity checks: the file is trusted).
    pub fn load_key(file: &Path) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), SynthesisError> {
        let mut r = BufReader::with_capacity(1 << 24, File::open(file).map_err(io_err)?);
        let pk = ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(&mut r).map_err(io_err)?;
        let vk = pk.vk.clone();
        Ok((pk, vk))
    }

    /// Groth16 proof for `circuit`, using the matrices stored at `path`.
    pub fn prove<C: ConstraintSynthesizer<Fr>>(
        pk: &ProvingKey<Bn254>,
        path: &Path,
        circuit: C,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<Proof<Bn254>, SynthesisError> {
        // witness-only synthesis
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: false,
        });
        circuit.generate_constraints(cs.clone())?;
        cs.finalize();
        let (num_inputs, num_constraints, full_assignment) = {
            let inner = cs.borrow().ok_or(SynthesisError::MissingCS)?;
            (
                inner.num_instance_variables,
                inner.num_constraints,
                [
                    inner.instance_assignment.as_slice(),
                    inner.witness_assignment.as_slice(),
                ]
                .concat(),
            )
        };
        // free the constraint system before the quotient polynomial is computed
        drop(cs);

        set_path(path);
        let dims = read_dims(path)?;
        let empty = ConstraintMatrices::<Fr> {
            num_instance_variables: dims[0] as usize,
            num_witness_variables: dims[1] as usize,
            num_constraints: dims[2] as usize,
            a_num_non_zero: dims[3] as usize,
            b_num_non_zero: dims[4] as usize,
            c_num_non_zero: dims[5] as usize,
            a: vec![],
            b: vec![],
            c: vec![],
        };
        let r = Fr::rand(&mut rng);
        let s = Fr::rand(&mut rng);
        Groth16::<Bn254, StreamQAP>::create_proof_with_reduction_and_matrices(
            pk,
            r,
            s,
            &empty,
            num_inputs,
            num_constraints,
            &full_assignment,
        )
    }
}

/// Circom step-circuit frontend with the witness generator compiled once.
///
/// PORTED from the filing build's fold driver, `folding/filing_fold.rs`
/// (`CachedCircomFCircuit`), which is itself sonobe's `CircomFCircuit`
/// (experimental-frontends/src/circom/mod.rs at rev 9414c45, MIT) with ONE change: the wasm
/// module of the step circuit is compiled and instantiated once, in `new`, and the same witness
/// calculator is reused at every step. sonobe's own wrapper builds a new wasmer store and
/// compiles the module again inside every `generate_step_constraints`.
/// The R1CS, the variable layout and the constraints are identical (the runner's mode
/// `same-r1cs` compares the two augmented circuits entry by entry).
/// Changes made in the port, none of which matters for 117 inputs: their number is a const generic
/// (and they are only passed on when it is non-zero); `new` returns an error instead of panicking.
pub mod cached_frontend {
    use ark_bn254::Fr;
    use ark_circom::{
        circom::{r1cs_reader, R1CS as CircomR1CS},
        WitnessCalculator,
    };
    use ark_r1cs_std::{
        fields::fp::{AllocatedFp, FpVar},
        R1CSVar,
    };
    use ark_relations::{
        lc,
        r1cs::{ConstraintSystemRef, SynthesisError, Variable},
    };
    use experimental_frontends::utils::{VecF, VecFpVar};
    use folding_schemes::{frontend::FCircuit, Error};
    use num_bigint::{BigInt, BigUint};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use wasmer::{Module, Store};

    /// length of the IVC state
    pub const STATE_LEN: usize = 1;

    #[derive(Clone)]
    pub struct CachedCircomFCircuit<const E: usize> {
        r1cs: CircomR1CS<Fr>,
        calc: Arc<Mutex<(Store, WitnessCalculator)>>,
        // the wasm runtime of ark-circom expects a Tokio context (sonobe's wrapper creates a
        // runtime per call); one runtime is kept for the calculator
        rt: Arc<tokio::runtime::Runtime>,
    }

    impl<const E: usize> std::fmt::Debug for CachedCircomFCircuit<E> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "CachedCircomFCircuit({} constraints)",
                self.r1cs.constraints.len()
            )
        }
    }

    impl<const E: usize> CachedCircomFCircuit<E> {
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

    impl<const E: usize> FCircuit<Fr> for CachedCircomFCircuit<E> {
        /// (r1cs_path, wasm_path)
        type Params = (PathBuf, PathBuf);
        type ExternalInputs = VecF<Fr, E>;
        type ExternalInputsVar = VecFpVar<Fr, E>;

        fn new(params: Self::Params) -> Result<Self, Error> {
            let (r1cs_path, wasm_path) = params;
            let r1cs_bytes = std::fs::read(r1cs_path)?;
            let wasm_bytes = std::fs::read(wasm_path)?;
            let r1cs_file = r1cs_reader::R1CSFile::new(std::io::Cursor::new(&r1cs_bytes))?;
            let mut r1cs = r1cs_reader::R1CS::from(r1cs_file);
            r1cs.wire_mapping = None;
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .map_err(|e| Error::WitnessCalculationError(format!("tokio runtime: {e}")))?;
            let _ctx = rt.enter();
            let mut store = Store::default();
            let module = Module::new(&store, &wasm_bytes)
                .map_err(|e| Error::WitnessCalculationError(format!("wasm module: {e}")))?;
            let calc = WitnessCalculator::from_module(&mut store, module)
                .map_err(|e| Error::WitnessCalculationError(format!("witness calculator: {e}")))?;
            drop(_ctx);
            Ok(Self {
                r1cs,
                calc: Arc::new(Mutex::new((store, calc))),
                rt: Arc::new(rt),
            })
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
            let mut inputs_map = vec![("ivc_input".to_string(), Self::fpvars_to_bigints(&z_i))];
            if E > 0 {
                inputs_map.push((
                    "external_inputs".to_string(),
                    Self::fpvars_to_bigints(&external_inputs.0),
                ));
            }
            // witness layout: [1, z_{i+1} (outputs), z_i, external_inputs, aux]
            let witness = self
                .witness(inputs_map)
                .map_err(|_| SynthesisError::AssignmentMissing)?;

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
                    // `z_i` and `external_inputs` are allocated as witnesses by the augmented
                    // circuit, never as constants
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
}

/// Verification of a snarkjs Groth16 proof (BN254) with arkworks, for the authority-side
/// command: reads snarkjs' `verification_key.json`, `proof.json` and `public.json`.
///
/// Conventions of the snarkjs JSON files: field elements are decimal strings; a G1 point is
/// `[x, y, "1"]`; a G2 point is `[[x.c0, x.c1], [y.c0, y.c1], ["1", "0"]]`. Every point is checked
/// to be on the curve and in the prime-order subgroup before use.
pub mod snarkjs {
    use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
    use ark_groth16::{Groth16, Proof, VerifyingKey};
    use ark_snark::SNARK;
    use serde_json::Value;
    use std::str::FromStr;

    fn fq(v: &Value) -> Result<Fq, String> {
        let s = v.as_str().ok_or("expected a decimal string")?;
        Fq::from_str(s).map_err(|_| format!("not a field element: {s}"))
    }

    fn g1(v: &Value) -> Result<G1Affine, String> {
        let a = v.as_array().ok_or("G1 point: expected an array")?;
        if a.len() != 3 || a[2].as_str() != Some("1") {
            return Err("G1 point: expected [x, y, \"1\"]".into());
        }
        let p = G1Affine::new_unchecked(fq(&a[0])?, fq(&a[1])?);
        if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
            return Err("G1 point is not on the curve".into());
        }
        Ok(p)
    }

    fn fq2(v: &Value) -> Result<Fq2, String> {
        let a = v.as_array().ok_or("Fq2 element: expected an array")?;
        if a.len() != 2 {
            return Err("Fq2 element: expected [c0, c1]".into());
        }
        Ok(Fq2::new(fq(&a[0])?, fq(&a[1])?))
    }

    fn g2(v: &Value) -> Result<G2Affine, String> {
        let a = v.as_array().ok_or("G2 point: expected an array")?;
        if a.len() != 3 {
            return Err("G2 point: expected three coordinates".into());
        }
        let z = a[2].as_array().ok_or("G2 point: bad z")?;
        if z.len() != 2 || z[0].as_str() != Some("1") || z[1].as_str() != Some("0") {
            return Err("G2 point: expected z = [\"1\", \"0\"]".into());
        }
        let p = G2Affine::new_unchecked(fq2(&a[0])?, fq2(&a[1])?);
        if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
            return Err("G2 point is not on the curve or not in the subgroup".into());
        }
        Ok(p)
    }

    fn read(path: &str) -> Result<Value, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        serde_json::from_str(&raw).map_err(|e| format!("{path}: {e}"))
    }

    fn check_kind(v: &Value, path: &str) -> Result<(), String> {
        if v["protocol"].as_str() != Some("groth16") || v["curve"].as_str() != Some("bn128") {
            return Err(format!("{path}: not a groth16 / bn128 file"));
        }
        Ok(())
    }

    pub fn load_vkey(path: &str) -> Result<VerifyingKey<Bn254>, String> {
        let v = read(path)?;
        check_kind(&v, path)?;
        let ic = v["IC"].as_array().ok_or("vkey: IC missing")?;
        Ok(VerifyingKey {
            alpha_g1: g1(&v["vk_alpha_1"])?,
            beta_g2: g2(&v["vk_beta_2"])?,
            gamma_g2: g2(&v["vk_gamma_2"])?,
            delta_g2: g2(&v["vk_delta_2"])?,
            gamma_abc_g1: ic.iter().map(g1).collect::<Result<Vec<_>, _>>()?,
        })
    }

    pub fn load_proof(path: &str) -> Result<Proof<Bn254>, String> {
        let v = read(path)?;
        check_kind(&v, path)?;
        Ok(Proof {
            a: g1(&v["pi_a"])?,
            b: g2(&v["pi_b"])?,
            c: g1(&v["pi_c"])?,
        })
    }

    /// the public signals as decimal strings and as field elements
    pub fn load_public(path: &str) -> Result<(Vec<String>, Vec<Fr>), String> {
        let v = read(path)?;
        let a = v.as_array().ok_or("public signals: expected an array")?;
        let strings = a
            .iter()
            .map(|x| x.as_str().map(|s| s.to_string()).ok_or("public signal: expected a string"))
            .collect::<Result<Vec<_>, _>>()?;
        let frs = strings
            .iter()
            .map(|s| Fr::from_str(s).map_err(|_| format!("not a field element: {s}")))
            .collect::<Result<Vec<_>, _>>()?;
        Ok((strings, frs))
    }

    /// Groth16 verification with arkworks' verifier.
    pub fn verify(
        vk: &VerifyingKey<Bn254>,
        public: &[Fr],
        proof: &Proof<Bn254>,
    ) -> Result<bool, String> {
        if public.len() + 1 != vk.gamma_abc_g1.len() {
            return Err(format!(
                "{} public signals, the verification key expects {}",
                public.len(),
                vk.gamma_abc_g1.len() - 1
            ));
        }
        Groth16::<Bn254>::verify(vk, public, proof).map_err(|e| e.to_string())
    }
}
