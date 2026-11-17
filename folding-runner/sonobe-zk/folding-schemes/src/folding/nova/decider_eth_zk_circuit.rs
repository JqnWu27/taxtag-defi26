/// Hiding ("blind-then-compress") variant of Nova's onchain decider circuit.
///
/// This file is an ADDITION to sonobe (pinned at 9414c45) made for the TaxTag artifact; the
/// original non-hiding decider (`decider_eth.rs`, `decider_eth_circuit.rs`,
/// `circuits/decider/on_chain.rs`) is left untouched for comparison.
/// The construction, its soundness argument, its zero-knowledge argument and every known gap are
/// written up in `folding-runner/ZK-DECIDER.md`; the summary is:
///
/// 1. fold A: `(U_f, W_f) = NIFS.P((U_i, W_i), (u_i, w_i))` with cross-term commitment `cmT`
///    (the same fold the non-hiding decider performs);
/// 2. sample a uniformly random SATISFYING relaxed R1CS pair `(U_r, W_r)`;
/// 3. fold B: `(U_b, W_b) = NIFS.P((U_f, W_f), (U_r, W_r))` with cross-term commitment `cmT_r`.
///    `U_r` (with both commitments) and `cmT_r` are absorbed into the transcript BEFORE the
///    challenge `r_2` of this fold is squeezed;
/// 4. the group (commitment) part of both folds is NOT done by the verifier (which would force
///    the prover to reveal `U_i`, `u_i`, `cmT`, `U_r`, `cmT_r`). Instead it is delegated to five
///    CycleFold instances which are folded, inside this circuit, into the CycleFold running
///    instance exactly as `AugmentedFCircuit` does at every IVC step;
/// 5. the circuit checks the final CycleFold instance (Pedersen openings + relaxed R1CS);
/// 6. the satisfiability of the blinded pair `(U_b, W_b)` is established in one of two ways
///    (`LinkMode`):
///    - `Open`: `U_b` is a public input in full and the prover reveals `W_b` (a uniformly random
///      vector); the verifier checks the relation and the two commitments natively;
///    - `KzgEval`: `W_b` stays private; the circuit checks the relation and links `W_b.W`,
///      `W_b.E` to the two public commitments by evaluation at transcript challenges, exactly as
///      sonobe's original decider does (and with the same weakness, see ZK-DECIDER.md, gap G2).
use ark_crypto_primitives::sponge::{
    constraints::{AbsorbGadget, CryptographicSpongeVar},
    poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig, PoseidonSponge},
    CryptographicSponge,
};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar, prelude::CurveVar,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::{rand::RngCore, One, UniformRand, Zero};

use super::{
    decider_eth_circuit::WitnessVar,
    nifs::{
        nova::NIFS,
        nova_circuits::{CommittedInstanceVar, NIFSGadget},
        NIFSGadgetTrait, NIFSTrait,
    },
    CommittedInstance, Nova, NovaCycleFoldCircuit, NovaCycleFoldConfig, Witness,
};
use crate::arith::{
    r1cs::{circuits::R1CSMatricesVar, R1CS},
    Arith, ArithRelation, ArithRelationGadget,
};
use crate::commitment::{pedersen::Params as PedersenParams, CommitmentScheme};
use crate::folding::{
    circuits::{
        cyclefold::{
            fold_cyclefold_circuit, CycleFoldChallengeGadget, CycleFoldCommittedInstance,
            CycleFoldCommittedInstanceVar, CycleFoldWitness, NIFSFullGadget,
        },
        decider::{EvalGadget, KZGChallengesGadget},
        nonnative::{affine::NonNativeAffineVar, uint::NonNativeUintVar},
        CF1,
    },
    traits::{CommittedInstanceOps, CommittedInstanceVarOps, Dummy, WitnessOps, WitnessVarOps},
};
use crate::frontend::FCircuit;
use crate::transcript::AbsorbNonNativeGadget;
use crate::{Curve, Error};

/// Number of CycleFold instances that the hiding decider folds into the CycleFold running
/// instance: 2 for fold A (`cmW`, `cmE`) and 3 for fold B (`cmW`, and `cmE` in two steps because
/// the random instance has a non-zero `cmE`).
pub const N_CF_FOLDS: usize = 5;

/// How the satisfiability of the blinded folded pair `(U_b, W_b)` reaches the verifier.
/// This is a circuit-shape parameter: SNARK keys are specific to its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkMode {
    /// The prover reveals `W_b` (uniformly random, see ZK-DECIDER.md); `U_b` is fully public; the
    /// verifier recomputes the two commitments and checks the relaxed R1CS relation itself.
    /// Proof size is linear in the size of the augmented step circuit (constant in the number of
    /// folded steps).
    Open,
    /// `W_b` stays private. The circuit checks the relaxed R1CS relation and links the in-circuit
    /// vectors to the public KZG commitments by evaluation at transcript challenges, as sonobe's
    /// original decider does. Constant-size proof, but the link inherits gap G2 of ZK-DECIDER.md
    /// (the challenges do not depend on the in-circuit vectors).
    KzgEval,
}

/// Samples a uniformly random pair `(W_r, U_r)` that satisfies the relaxed R1CS relation of
/// `r1cs` (Construction 5 of HyperNova, eprint 2023/573): `u`, `x` and `W` are uniform and the
/// error vector is DEFINED as `E = Az ∘ Bz - u·Cz`.
///
/// `ArithSampler::sample_witness_instance` in sonobe does the same but demands a hiding
/// commitment scheme (`CommitmentScheme<C, true>`), which sonobe's KZG does not implement.
/// Here the commitments are the plain (non-hiding) ones; this is sufficient because the committed
/// vectors themselves are uniformly random (see ZK-DECIDER.md, section "Zero knowledge").
pub fn sample_relaxed_instance<C: Curve, CS: CommitmentScheme<C, false>>(
    r1cs: &R1CS<CF1<C>>,
    params: &CS::ProverParams,
    mut rng: impl RngCore,
) -> Result<(Witness<C>, CommittedInstance<C>), Error> {
    let u = C::ScalarField::rand(&mut rng);
    let x: Vec<C::ScalarField> = (0..r1cs.n_public_inputs())
        .map(|_| C::ScalarField::rand(&mut rng))
        .collect();
    let W: Vec<C::ScalarField> = (0..r1cs.n_witnesses())
        .map(|_| C::ScalarField::rand(&mut rng))
        .collect();
    let mut z = vec![u];
    z.extend(&x);
    z.extend(&W);
    let E = r1cs.eval_at_z(&z)?;

    let zero = C::ScalarField::zero();
    let cmE = CS::commit(params, &E, &zero)?;
    let cmW = CS::commit(params, &W, &zero)?;
    Ok((
        Witness {
            E,
            rE: zero,
            W,
            rW: zero,
        },
        CommittedInstance { cmE, u, cmW, x },
    ))
}

/// The hiding decider circuit. All fields are public so that tests can build malformed witnesses.
#[derive(Debug, Clone)]
pub struct DeciderEthZKCircuit<C1: Curve, C2: Curve> {
    /// R1CS of the Augmented Function circuit
    pub arith: R1CS<CF1<C1>>,
    /// R1CS of the CycleFold circuit
    pub cf_arith: R1CS<CF1<C2>>,
    /// CycleFold PedersenParams over C2
    pub cf_pedersen_params: PedersenParams<C2>,
    pub poseidon_config: PoseidonConfig<CF1<C1>>,
    pub link: LinkMode,

    // ---- public inputs ----
    /// public params hash
    pub pp_hash: CF1<C1>,
    pub i: CF1<C1>,
    /// initial state
    pub z_0: Vec<CF1<C1>>,
    /// current i-th state
    pub z_i: Vec<CF1<C1>>,
    /// The blinded folded instance. Its two commitments are always public inputs; `u` and `x`
    /// are public inputs in `LinkMode::Open` only.
    pub U_b: CommittedInstance<C1>,
    /// KZG challenges and evaluations (public inputs in `LinkMode::KzgEval`, empty otherwise)
    pub kzg_challenges: Vec<CF1<C1>>,
    pub kzg_evaluations: Vec<CF1<C1>>,

    // ---- witness ----
    /// running instance and incoming instance of the IVC
    pub U_i: CommittedInstance<C1>,
    pub u_i: CommittedInstance<C1>,
    /// cross-term commitment of fold A
    pub cmT: C1,
    /// commitments of `U_f = NIFS.V(U_i, u_i)`
    pub U_f_cmW: C1,
    pub U_f_cmE: C1,
    /// the random satisfying relaxed instance used for blinding
    pub U_r: CommittedInstance<C1>,
    /// cross-term commitment of fold B
    pub cmT_r: C1,
    /// `cmT_r + r_2 · U_r.cmE`
    pub cmE_aux: C1,
    /// witness of `U_b`. A circuit witness in `LinkMode::KzgEval`; in `LinkMode::Open` it is not
    /// used by the circuit at all (the prover sends it to the verifier).
    pub W_b: Witness<C1>,
    /// CycleFold running instance of the IVC (before the decider's folds)
    pub cf_U_i: CycleFoldCommittedInstance<C2>,
    /// `cmW` of the `N_CF_FOLDS` CycleFold instances folded by the decider
    pub cf_u_cmW: Vec<C2>,
    /// cross-term commitments of the `N_CF_FOLDS` CycleFold folds
    pub cf_cmT: Vec<C2>,
    /// witness of the final CycleFold running instance (after the decider's folds)
    pub cf_W_final: CycleFoldWitness<C2>,
}

impl<C1: Curve, C2: Curve>
    Dummy<(
        R1CS<CF1<C1>>,
        R1CS<CF1<C2>>,
        PedersenParams<C2>,
        PoseidonConfig<CF1<C1>>,
        usize,
        LinkMode,
    )> for DeciderEthZKCircuit<C1, C2>
{
    fn dummy(
        (arith, cf_arith, cf_pedersen_params, poseidon_config, state_len, link): (
            R1CS<CF1<C1>>,
            R1CS<CF1<C2>>,
            PedersenParams<C2>,
            PoseidonConfig<CF1<C1>>,
            usize,
            LinkMode,
        ),
    ) -> Self {
        let n_kzg = match link {
            LinkMode::KzgEval => 2,
            LinkMode::Open => 0,
        };
        Self {
            cf_pedersen_params,
            poseidon_config,
            link,
            pp_hash: Zero::zero(),
            i: Zero::zero(),
            z_0: vec![Zero::zero(); state_len],
            z_i: vec![Zero::zero(); state_len],
            U_b: CommittedInstance::dummy(&arith),
            kzg_challenges: vec![Zero::zero(); n_kzg],
            kzg_evaluations: vec![Zero::zero(); n_kzg],
            U_i: CommittedInstance::dummy(&arith),
            u_i: CommittedInstance::dummy(&arith),
            cmT: C1::zero(),
            U_f_cmW: C1::zero(),
            U_f_cmE: C1::zero(),
            U_r: CommittedInstance::dummy(&arith),
            cmT_r: C1::zero(),
            cmE_aux: C1::zero(),
            W_b: Witness::dummy(&arith),
            cf_U_i: CycleFoldCommittedInstance::dummy(&cf_arith),
            cf_u_cmW: vec![C2::zero(); N_CF_FOLDS],
            cf_cmT: vec![C2::zero(); N_CF_FOLDS],
            cf_W_final: CycleFoldWitness::dummy(&cf_arith),
            arith,
            cf_arith,
        }
    }
}

/// Values the prover computes natively that never leave it. Returned next to the circuit so that
/// tests can inspect them.
#[derive(Debug, Clone)]
pub struct BlindedFoldAux<C1: Curve, C2: Curve> {
    /// `U_f = NIFS.V(U_i, u_i)`
    pub U_f: CommittedInstance<C1>,
    /// final CycleFold running instance
    pub cf_U_final: CycleFoldCommittedInstance<C2>,
}

impl<C1, C2> DeciderEthZKCircuit<C1, C2>
where
    C1: Curve<BaseField = C2::ScalarField, ScalarField = C2::BaseField>,
    C2: Curve,
{
    /// Builds the circuit (with all its witness values) from a Nova instance, sampling a fresh
    /// random satisfying relaxed instance for the blinding fold.
    pub fn from_nova<FC, CS1, CS2>(
        nova: Nova<C1, C2, FC, CS1, CS2, false>,
        link: LinkMode,
        mut rng: impl RngCore,
    ) -> Result<(Self, BlindedFoldAux<C1, C2>), Error>
    where
        FC: FCircuit<C1::ScalarField>,
        CS1: CommitmentScheme<C1, false>,
        CS2: CommitmentScheme<C2, false, ProverParams = PedersenParams<C2>>,
    {
        let (W_r, U_r) = sample_relaxed_instance::<C1, CS1>(&nova.r1cs, &nova.cs_pp, &mut rng)?;
        Self::from_nova_with_blinder(nova, link, W_r, U_r, rng)
    }

    /// Same as `from_nova`, but with the blinding pair `(W_r, U_r)` chosen by the caller.
    /// This method performs NO satisfiability check on the pair (nor on the Nova instance):
    /// soundness must come from the verifier, and the tests use this entry point to feed
    /// a non-satisfying "random" instance.
    pub fn from_nova_with_blinder<FC, CS1, CS2>(
        nova: Nova<C1, C2, FC, CS1, CS2, false>,
        link: LinkMode,
        W_r: Witness<C1>,
        U_r: CommittedInstance<C1>,
        mut rng: impl RngCore,
    ) -> Result<(Self, BlindedFoldAux<C1, C2>), Error>
    where
        FC: FCircuit<C1::ScalarField>,
        CS1: CommitmentScheme<C1, false>,
        CS2: CommitmentScheme<C2, false, ProverParams = PedersenParams<C2>>,
    {
        let mut transcript = PoseidonSponge::<C1::ScalarField>::new(&nova.poseidon_config);

        // ---- fold A: (U_f, W_f) = NIFS.P((U_i, W_i), (u_i, w_i)) ----
        // the transcript absorbs pp_hash, U_i, u_i, cmT and then squeezes r_1
        let (W_f, U_f, cmT, r1_bits) =
            NIFS::<C1, CS1, PoseidonSponge<C1::ScalarField>, false>::prove(
                &nova.cs_pp,
                &nova.r1cs,
                &mut transcript,
                nova.pp_hash,
                &nova.W_i,
                &nova.U_i,
                &nova.w_i,
                &nova.u_i,
            )?;

        let mut cf_W = nova.cf_W_i.clone();
        let mut cf_U = nova.cf_U_i.clone();
        let mut cf_u_cmW = Vec::with_capacity(N_CF_FOLDS);
        let mut cf_cmT = Vec::with_capacity(N_CF_FOLDS);

        // folds one CycleFold instance (computing p0 + r·p1) into the CycleFold running instance
        macro_rules! fold_cf {
            ($r_bits:expr, $p0:expr, $p1:expr) => {{
                let cf_circuit = NovaCycleFoldCircuit::<C1> {
                    r_bits: Some($r_bits.clone()),
                    points: Some(vec![$p0, $p1]),
                };
                let (cf_u_k, cf_W_k, cf_U_k, cf_cmT_k) =
                    fold_cyclefold_circuit::<NovaCycleFoldConfig<C1>, C2, CS2, false>(
                        &mut transcript,
                        nova.cf_r1cs.clone(),
                        nova.cf_cs_pp.clone(),
                        nova.pp_hash,
                        cf_W.clone(),
                        cf_U.clone(),
                        cf_circuit,
                        &mut rng,
                    )?;
                cf_u_cmW.push(cf_u_k.cmW);
                cf_cmT.push(cf_cmT_k);
                cf_W = cf_W_k;
                cf_U = cf_U_k;
            }};
        }

        // CycleFold instances of fold A, in the same order as in `Nova::prove_step`
        // U_f.cmW = U_i.cmW + r_1 · u_i.cmW
        fold_cf!(r1_bits, nova.U_i.cmW, nova.u_i.cmW);
        // U_f.cmE = U_i.cmE + r_1 · cmT
        fold_cf!(r1_bits, nova.U_i.cmE, cmT);

        // ---- fold B: (U_b, W_b) = NIFS.P((U_f, W_f), (U_r, W_r)) ----
        // the transcript absorbs pp_hash, U_f, U_r (u, x, cmE, cmW), cmT_r and then squeezes r_2
        let (W_b, U_b, cmT_r, r2_bits) =
            NIFS::<C1, CS1, PoseidonSponge<C1::ScalarField>, false>::prove(
                &nova.cs_pp,
                &nova.r1cs,
                &mut transcript,
                nova.pp_hash,
                &W_f,
                &U_f,
                &W_r,
                &U_r,
            )?;
        let r2 = C1::ScalarField::from_bigint(BigInteger::from_bits_le(&r2_bits))
            .ok_or(Error::OutOfBounds)?;
        let cmE_aux = cmT_r + U_r.cmE.mul(r2);

        // U_b.cmW = U_f.cmW + r_2 · U_r.cmW
        fold_cf!(r2_bits, U_f.cmW, U_r.cmW);
        // cmE_aux = cmT_r + r_2 · U_r.cmE
        fold_cf!(r2_bits, cmT_r, U_r.cmE);
        // U_b.cmE = U_f.cmE + r_2 · cmE_aux  (= U_f.cmE + r_2 · cmT_r + r_2^2 · U_r.cmE)
        fold_cf!(r2_bits, U_f.cmE, cmE_aux);

        // ---- link between the blinded pair and the verifier ----
        let (kzg_challenges, kzg_evaluations) = match link {
            LinkMode::Open => (vec![], vec![]),
            LinkMode::KzgEval => {
                let kzg_challenges =
                    KZGChallengesGadget::get_challenges_native(&mut transcript, &U_b);
                let kzg_evaluations = W_b
                    .get_openings()
                    .iter()
                    .zip(&kzg_challenges)
                    .map(|((v, _), &c)| EvalGadget::evaluate_native(v, c))
                    .collect::<Result<Vec<_>, _>>()?;
                (kzg_challenges, kzg_evaluations)
            }
        };

        Ok((
            Self {
                arith: nova.r1cs,
                cf_arith: nova.cf_r1cs,
                cf_pedersen_params: nova.cf_cs_pp,
                poseidon_config: nova.poseidon_config,
                link,
                pp_hash: nova.pp_hash,
                i: nova.i,
                z_0: nova.z_0,
                z_i: nova.z_i,
                U_b,
                kzg_challenges,
                kzg_evaluations,
                U_i: nova.U_i,
                u_i: nova.u_i,
                cmT,
                U_f_cmW: U_f.cmW,
                U_f_cmE: U_f.cmE,
                U_r,
                cmT_r,
                cmE_aux,
                W_b,
                cf_U_i: nova.cf_U_i,
                cf_u_cmW,
                cf_cmT,
                cf_W_final: cf_W,
            },
            BlindedFoldAux {
                U_f,
                cf_U_final: cf_U,
            },
        ))
    }

    /// Native sanity check of the two relations that have to hold for the folded pairs.
    /// Used by the honest prover to fail early; NOT part of the verifier.
    pub fn check_native(&self, aux: &BlindedFoldAux<C1, C2>) -> Result<(), Error> {
        self.arith.check_relation(&self.W_b, &self.U_b)?;
        self.cf_arith
            .check_relation(&self.cf_W_final, &aux.cf_U_final)?;
        Ok(())
    }
}

impl<C1, C2> ConstraintSynthesizer<CF1<C1>> for DeciderEthZKCircuit<C1, C2>
where
    C1: Curve<BaseField = C2::ScalarField, ScalarField = C2::BaseField>,
    C2: Curve,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<CF1<C1>>) -> Result<(), SynthesisError> {
        if self.cf_u_cmW.len() != N_CF_FOLDS || self.cf_cmT.len() != N_CF_FOLDS {
            return Err(SynthesisError::Unsatisfiable);
        }
        let link = self.link;

        // ---- public inputs, in the order in which the verifier lays them out ----
        // common part: [pp_hash, i, z_0, z_i, U_b.cmW, U_b.cmE]
        let pp_hash = FpVar::new_input(cs.clone(), || Ok(self.pp_hash))?;
        let i = FpVar::new_input(cs.clone(), || Ok(self.i))?;
        let z_0 = Vec::new_input(cs.clone(), || Ok(self.z_0))?;
        let z_i = Vec::new_input(cs.clone(), || Ok(self.z_i))?;
        let U_b_commitments =
            Vec::<NonNativeAffineVar<C1>>::new_input(cs.clone(), || {
                Ok(self.U_b.get_commitments())
            })?;
        // mode-specific part:
        // - Open:    [U_b.u, U_b.x]
        // - KzgEval: [c_W, c_E, eval_W, eval_E]
        let (U_b_u_x, kzg) = match link {
            LinkMode::Open => {
                let u = FpVar::new_input(cs.clone(), || Ok(self.U_b.u))?;
                let x = Vec::<FpVar<CF1<C1>>>::new_input(cs.clone(), || Ok(self.U_b.x.clone()))?;
                (Some((u, x)), None)
            }
            LinkMode::KzgEval => {
                if self.kzg_challenges.len() != 2 || self.kzg_evaluations.len() != 2 {
                    return Err(SynthesisError::Unsatisfiable);
                }
                let c = Vec::<FpVar<CF1<C1>>>::new_input(cs.clone(), || {
                    Ok(self.kzg_challenges.clone())
                })?;
                let e = Vec::<FpVar<CF1<C1>>>::new_input(cs.clone(), || {
                    Ok(self.kzg_evaluations.clone())
                })?;
                (None, Some((c, e)))
            }
        };

        // ---- witnesses ----
        let u_i = CommittedInstanceVar::<C1>::new_witness(cs.clone(), || Ok(self.u_i))?;
        let U_i = CommittedInstanceVar::<C1>::new_witness(cs.clone(), || Ok(self.U_i))?;
        let cmT = NonNativeAffineVar::<C1>::new_witness(cs.clone(), || Ok(self.cmT))?;
        let U_f_cmW = NonNativeAffineVar::<C1>::new_witness(cs.clone(), || Ok(self.U_f_cmW))?;
        let U_f_cmE = NonNativeAffineVar::<C1>::new_witness(cs.clone(), || Ok(self.U_f_cmE))?;
        let U_r = CommittedInstanceVar::<C1>::new_witness(cs.clone(), || Ok(self.U_r))?;
        let cmT_r = NonNativeAffineVar::<C1>::new_witness(cs.clone(), || Ok(self.cmT_r))?;
        let cmE_aux = NonNativeAffineVar::<C1>::new_witness(cs.clone(), || Ok(self.cmE_aux))?;
        let cf_U_i =
            CycleFoldCommittedInstanceVar::<C2>::new_witness(cs.clone(), || Ok(self.cf_U_i))?;
        let cf_u_cmW = self
            .cf_u_cmW
            .iter()
            .map(|p| C2::Var::new_witness(cs.clone(), || Ok(*p)))
            .collect::<Result<Vec<_>, _>>()?;
        let cf_cmT = self
            .cf_cmT
            .iter()
            .map(|p| C2::Var::new_witness(cs.clone(), || Ok(*p)))
            .collect::<Result<Vec<_>, _>>()?;

        // `sponge` is for digest computation.
        let sponge = PoseidonSpongeVar::new(cs.clone(), &self.poseidon_config);
        // `transcript` is for challenge generation.
        let mut transcript = sponge.clone();

        // 1. `u_i` is an incoming instance (u = 1, cmE = 0)
        u_i.enforce_incoming()?;

        // 2. u_i.x[0] == H(i, z_0, z_i, U_i), u_i.x[1] == H(cf_U_i)
        let (u_i_x, U_i_vec) = U_i.hash(&sponge, &pp_hash, &i, &z_0, &z_i)?;
        let (cf_u_i_x, cf_U_i_vec) = cf_U_i.hash(&sponge, pp_hash.clone())?;
        u_i.get_public_inputs().enforce_equal(&[u_i_x, cf_u_i_x])?;

        // 3. fold A, field part: U_f.{u, x} = NIFS.V(U_i, u_i), with
        //    r_1 = H(transcript; pp_hash, U_i, u_i, cmT) computed in-circuit.
        //    The group part (U_f.cmW, U_f.cmE) is a witness whose correctness is delegated to
        //    CycleFold (step 4).
        let (mut U_f, r1_bits) = NIFSGadget::<
            C1,
            PoseidonSponge<C1::ScalarField>,
            PoseidonSpongeVar<C1::ScalarField>,
        >::verify(
            &mut transcript,
            pp_hash.clone(),
            U_i.clone(),
            U_i_vec,
            u_i.clone(),
            Some(cmT.clone()),
        )?;
        U_f.cmW = U_f_cmW;
        U_f.cmE = U_f_cmE;
        let r1_nonnat = bits_to_nonnative::<C1>(r1_bits);

        // 4. CycleFold instances of fold A, folded into the CycleFold running instance.
        let mut cf_fold_idx = 0;
        let mut cf_U = cf_U_i;
        let mut cf_U_vec = cf_U_i_vec;
        // folds the CycleFold instance with x = [r, p0, p1, p_out] (claiming p_out = p0 + r·p1)
        let mut fold_cf = |transcript: &mut PoseidonSpongeVar<CF1<C1>>,
                           cf_U: &mut CycleFoldCommittedInstanceVar<C2>,
                           cf_U_vec: &mut Vec<FpVar<CF1<C1>>>,
                           r_nonnat: &NonNativeUintVar<CF1<C1>>,
                           p0: &NonNativeAffineVar<C1>,
                           p1: &NonNativeAffineVar<C1>,
                           p_out: &NonNativeAffineVar<C1>|
         -> Result<(), SynthesisError> {
            let cf_u = CycleFoldCommittedInstanceVar::<C2> {
                // cf_u.cmE = 0
                cmE: C2::Var::zero(),
                // cf_u.u = 1
                u: NonNativeUintVar::new_constant(cs.clone(), C1::BaseField::one())?,
                // cf_u.cmW is provided by the prover as witness
                cmW: cf_u_cmW[cf_fold_idx].clone(),
                x: vec![
                    r_nonnat.clone(),
                    p0.x.clone(),
                    p0.y.clone(),
                    p1.x.clone(),
                    p1.y.clone(),
                    p_out.x.clone(),
                    p_out.y.clone(),
                ],
            };
            let cf_r_bits = CycleFoldChallengeGadget::<C2>::get_challenge_gadget(
                transcript,
                pp_hash.clone(),
                cf_U_vec.clone(),
                cf_u.clone(),
                cf_cmT[cf_fold_idx].clone(),
            )?;
            *cf_U = NIFSFullGadget::<C2>::fold_committed_instance(
                cf_r_bits,
                cf_cmT[cf_fold_idx].clone(),
                cf_U.clone(),
                cf_u,
            )?;
            *cf_U_vec = cf_U.to_native_sponge_field_elements()?;
            cf_fold_idx += 1;
            Ok(())
        };
        // U_f.cmW = U_i.cmW + r_1 · u_i.cmW
        fold_cf(
            &mut transcript,
            &mut cf_U,
            &mut cf_U_vec,
            &r1_nonnat,
            &U_i.cmW,
            &u_i.cmW,
            &U_f.cmW,
        )?;
        // U_f.cmE = U_i.cmE + r_1 · cmT
        fold_cf(
            &mut transcript,
            &mut cf_U,
            &mut cf_U_vec,
            &r1_nonnat,
            &U_i.cmE,
            &cmT,
            &U_f.cmE,
        )?;

        // 5. fold B (blinding), field part: U_b.{u, x} = NIFS.V(U_f, U_r), with
        //    r_2 = H(transcript; pp_hash, U_f, U_r, cmT_r) computed in-circuit: the random
        //    instance (u, x, cmE, cmW) and the cross-term commitment are absorbed BEFORE the
        //    challenge is squeezed.
        let U_f_vec = U_f.to_sponge_field_elements()?;
        let (mut U_b, r2_bits) = NIFSGadget::<
            C1,
            PoseidonSponge<C1::ScalarField>,
            PoseidonSpongeVar<C1::ScalarField>,
        >::verify(
            &mut transcript,
            pp_hash.clone(),
            U_f.clone(),
            U_f_vec,
            U_r.clone(),
            Some(cmT_r.clone()),
        )?;
        // the commitments of U_b are the public inputs
        U_b.cmW = U_b_commitments[0].clone();
        U_b.cmE = U_b_commitments[1].clone();
        let r2_nonnat = bits_to_nonnative::<C1>(r2_bits);

        // 6. CycleFold instances of fold B.
        // U_b.cmW = U_f.cmW + r_2 · U_r.cmW
        fold_cf(
            &mut transcript,
            &mut cf_U,
            &mut cf_U_vec,
            &r2_nonnat,
            &U_f.cmW,
            &U_r.cmW,
            &U_b.cmW,
        )?;
        // cmE_aux = cmT_r + r_2 · U_r.cmE
        fold_cf(
            &mut transcript,
            &mut cf_U,
            &mut cf_U_vec,
            &r2_nonnat,
            &cmT_r,
            &U_r.cmE,
            &cmE_aux,
        )?;
        // U_b.cmE = U_f.cmE + r_2 · cmE_aux
        fold_cf(
            &mut transcript,
            &mut cf_U,
            &mut cf_U_vec,
            &r2_nonnat,
            &U_f.cmE,
            &cmE_aux,
            &U_b.cmE,
        )?;

        #[cfg(feature = "light-test")]
        log::warn!("[WARNING]: Running with the 'light-test' feature, skipping the CycleFold checks of the DeciderEthZKCircuit.\n           Only for testing purposes: the resulting proof is NOT sound.");

        // 7. and 8. are disabled with the 'light-test' feature, exactly as checks 4. and 5. of
        // the original decider circuit (they account for millions of constraints).
        #[cfg(not(feature = "light-test"))]
        {
            use crate::{
                commitment::pedersen::PedersenGadget,
                folding::circuits::{cyclefold::CycleFoldWitnessVar, CF2},
            };
            use ark_ff::Field;
            use ark_r1cs_std::convert::ToBitsGadget;
            let cf_W =
                CycleFoldWitnessVar::<C2>::new_witness(cs.clone(), || Ok(self.cf_W_final))?;
            // 7. check the Pedersen commitments of the FINAL CycleFold instance (after the five
            //    folds of this circuit)
            let H = C2::Var::constant(self.cf_pedersen_params.h);
            let G = self
                .cf_pedersen_params
                .generators
                .iter()
                .map(|&g| C2::Var::constant(g.into()))
                .collect::<Vec<_>>();
            let cf_W_E_bits = cf_W
                .E
                .iter()
                .map(|E_i| E_i.to_bits_le())
                .collect::<Result<Vec<_>, _>>()?;
            let cf_W_W_bits = cf_W
                .W
                .iter()
                .map(|W_i| W_i.to_bits_le())
                .collect::<Result<Vec<_>, _>>()?;
            // The in-circuit commitment below differs from the original decider's direct call of
            // `PedersenGadget::commit` in two ways (the original circuit is unchanged):
            //
            // (a) every entry is covered. The gadget sums the entries in pairs and, as written
            //     at the pinned revision, leaves entries `n-3` and `n-2` out when the length `n`
            //     is odd (the CycleFold error vector has odd length). Here the gadget is applied
            //     to the first `m = n - (n mod 2)` entries, an even count that it covers
            //     completely, and a trailing entry is added with a single `scalar_mul_le`.
            //
            // (b) pairs of zero scalars are supported. With the pinned r1cs-std
            //     (yelhousni/r1cs-std@440ca3) `joint_scalar_mul_be` uses incomplete additions and
            //     its constraints cannot be satisfied when BOTH scalars of a pair are 0. Honest
            //     CycleFold error vectors contain such pairs (the error entries of the linear
            //     rows of the CycleFold circuit are always 0). Therefore every paired scalar gets
            //     a constant 1 appended as an extra most-significant bit, i.e. the gadget
            //     computes sum_j (v_j + 2^w) G_j, and the constant 2^w · sum_j G_j is subtracted
            //     afterwards (`w` = bit width of the scalars). `scalar_mul_le`, used for the
            //     trailing entry, is complete and needs no offset.
            let no_blind: Vec<Boolean<CF1<C1>>> = vec![];
            let commit_all =
                |v: &[Vec<Boolean<CF1<C1>>>]| -> Result<C2::Var, SynthesisError> {
                    let n = v.len();
                    if n < 2 || n > G.len() {
                        return Err(SynthesisError::Unsatisfiable);
                    }
                    let w = v[0].len();
                    if w == 0 || v.iter().any(|b| b.len() != w) {
                        return Err(SynthesisError::Unsatisfiable);
                    }
                    let m = n - (n % 2);
                    let shifted = v[..m]
                        .iter()
                        .map(|bits| {
                            let mut bits = bits.clone();
                            bits.push(Boolean::TRUE);
                            bits
                        })
                        .collect::<Vec<_>>();
                    // sum_{j<m} (v_j + 2^w) G_j
                    let mut res = PedersenGadget::<C2>::commit(&H, &G[..m], &shifted, &no_blind)?;
                    // minus 2^w · sum_{j<m} G_j (a constant of the circuit)
                    let two_w = C2::ScalarField::from(2u64).pow([w as u64]);
                    let offset: C2 = self.cf_pedersen_params.generators[..m]
                        .iter()
                        .map(|g| Into::<C2>::into(*g))
                        .sum::<C2>()
                        * two_w;
                    res += C2::Var::constant(-offset);
                    if n % 2 == 1 {
                        res += G[n - 1].scalar_mul_le(v[n - 1].iter())?;
                    }
                    Ok(res)
                };
            commit_all(&cf_W_E_bits)?.enforce_equal(&cf_U.cmE)?;
            commit_all(&cf_W_W_bits)?.enforce_equal(&cf_U.cmW)?;

            let cf_r1cs = R1CSMatricesVar::<CF1<C2>, NonNativeUintVar<CF2<C2>>>::new_constant(
                ConstraintSystemRef::None,
                self.cf_arith,
            )?;

            // 8. the final CycleFold instance satisfies the relaxed R1CS of the CycleFold circuit
            cf_r1cs.enforce_relation(&cf_W, &cf_U)?;
        }

        match link {
            LinkMode::Open => {
                // 9a. the field part of U_b computed by the in-circuit fold is the public one.
                //     The relation R(U_b, W_b) and the openings of U_b.cmW, U_b.cmE are checked
                //     by the verifier on the revealed W_b.
                let (u, x) = U_b_u_x.ok_or(SynthesisError::AssignmentMissing)?;
                U_b.u.enforce_equal(&u)?;
                U_b.x.enforce_equal(&x)?;
            }
            LinkMode::KzgEval => {
                let (kzg_challenges, kzg_evaluations) =
                    kzg.ok_or(SynthesisError::AssignmentMissing)?;
                // the R1CS matrices are allocated as constants (`R1CSMatricesVar::new_variable`)
                let arith =
                    R1CSMatricesVar::<CF1<C1>, FpVar<CF1<C1>>>::new_witness(cs.clone(), || {
                        Ok(&self.arith)
                    })?;
                let W_b = WitnessVar::<C1>::new_witness(cs.clone(), || Ok(self.W_b))?;

                // 9b. `U_b` and `W_b` satisfy the relaxed R1CS of the augmented circuit
                arith.enforce_relation(&W_b, &U_b)?;

                // 10b. compute and check the KZG challenges
                KZGChallengesGadget::get_challenges_gadget(&mut transcript, &U_b)?
                    .enforce_equal(&kzg_challenges)?;

                // 11b. check the claimed evaluations of W_b.W and W_b.E
                for (((v, _r), c), e) in W_b
                    .get_openings()
                    .iter()
                    .zip(&kzg_challenges)
                    .zip(&kzg_evaluations)
                {
                    EvalGadget::evaluate_gadget(v, c)?.enforce_equal(e)?;
                }
            }
        }

        Ok(())
    }
}

/// converts the bits of a folding challenge into the non-native representation used as the first
/// public input of a CycleFold instance (same as in `AugmentedFCircuit`).
fn bits_to_nonnative<C1: Curve>(r_bits: Vec<Boolean<CF1<C1>>>) -> NonNativeUintVar<CF1<C1>> {
    let mut bits = r_bits;
    bits.resize(C1::BaseField::MODULUS_BIT_SIZE as usize, Boolean::FALSE);
    NonNativeUintVar::from(&bits)
}
