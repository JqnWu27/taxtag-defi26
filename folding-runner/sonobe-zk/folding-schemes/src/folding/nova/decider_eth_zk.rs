/// Hiding ("blind-then-compress") variant of Nova's onchain decider: prover and verifier.
///
/// This file is an ADDITION to sonobe (pinned at 9414c45) made for the TaxTag artifact; the
/// original decider in `decider_eth.rs` is untouched. See `decider_eth_zk_circuit.rs` for the
/// circuit and `folding-runner/ZK-DECIDER.md` for the construction and its analysis.
///
/// Differences to `decider_eth::Decider` that matter to a caller:
/// - the verifier is NOT given the commitments of the running and incoming instances, nor `cmT`,
///   nor the folding challenge `r`. It receives the blinded folded instance inside the proof and
///   nothing else that depends on the IVC witness;
/// - the proof is randomized: two proofs of the same statement differ in every component;
/// - the Nova instance is still `Nova<.., false>` (non-hiding commitments): hiding comes from the
///   blinding fold, not from the commitment scheme;
/// - there are two proof formats, selected by `LinkMode` at setup time (see the circuit file).
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::{
    rand::{CryptoRng, RngCore},
    One, Zero,
};
use core::marker::PhantomData;

pub use super::decider_eth_zk_circuit::{BlindedFoldAux, DeciderEthZKCircuit, LinkMode};
use super::Nova;
use crate::arith::{r1cs::R1CS, Arith};
use crate::commitment::{
    kzg::Proof as KZGProof, pedersen::Params as PedersenParams, CommitmentScheme,
};
use crate::folding::traits::{CommittedInstanceOps, Dummy, InputizeNonNative, WitnessOps};
use crate::frontend::FCircuit;
use crate::{Curve, Error, FoldingScheme};

/// The hiding decider proof. This struct, together with the statement `(i, z_0, z_i)`, is
/// everything the verifier sees. Fields are public so that tests can tamper with them.
///
/// The mode-specific parts are vectors so that one (de)serializable struct covers both formats:
/// - `LinkMode::KzgEval`: `kzg_proofs` and `kzg_challenges` have length 2, the `open_*` are empty;
/// - `LinkMode::Open`: `open_u` has length 1, `open_x` the number of public inputs of the
///   augmented circuit (2), `open_W` its number of witnesses; the `kzg_*` are empty.
#[derive(Debug, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<C, CS, S>
where
    C: Curve,
    CS: CommitmentScheme<C, ProverChallenge = C::ScalarField, Challenge = C::ScalarField>,
    S: SNARK<C::ScalarField>,
{
    pub snark_proof: S::Proof,
    /// `[cmW, cmE]` of the blinded folded instance `U_b`
    pub U_b_commitments: [C; 2],
    /// KZG openings (evaluation and opening proof) of `cmW`, `cmE` at the two challenges
    pub kzg_proofs: Vec<CS::Proof>,
    /// the KZG challenges are provided by the prover, and checked in-circuit to match the ones
    /// derived from the (hidden) transcript.
    pub kzg_challenges: Vec<C::ScalarField>,
    /// `U_b.u`
    pub open_u: Vec<C::ScalarField>,
    /// `U_b.x`
    pub open_x: Vec<C::ScalarField>,
    /// `W_b.W`, the blinded folded witness vector
    pub open_W: Vec<C::ScalarField>,
}

// `Clone` is implemented by hand because the derive would demand `S: Clone`, which the SNARK
// marker types (e.g. `Groth16`) do not implement.
impl<C, CS, S> Clone for Proof<C, CS, S>
where
    C: Curve,
    CS: CommitmentScheme<C, ProverChallenge = C::ScalarField, Challenge = C::ScalarField>,
    S: SNARK<C::ScalarField>,
{
    fn clone(&self) -> Self {
        Self {
            snark_proof: self.snark_proof.clone(),
            U_b_commitments: self.U_b_commitments,
            kzg_proofs: self.kzg_proofs.clone(),
            kzg_challenges: self.kzg_challenges.clone(),
            open_u: self.open_u.clone(),
            open_x: self.open_x.clone(),
            open_W: self.open_W.clone(),
        }
    }
}

/// The proof without its SNARK part (see `DeciderZK::link_parts`).
#[derive(Debug, Clone)]
pub struct ProofLinkParts<C, CS>
where
    C: Curve,
    CS: CommitmentScheme<C, ProverChallenge = C::ScalarField, Challenge = C::ScalarField>,
{
    pub U_b_commitments: [C; 2],
    pub kzg_proofs: Vec<CS::Proof>,
    pub kzg_challenges: Vec<C::ScalarField>,
    pub open_u: Vec<C::ScalarField>,
    pub open_x: Vec<C::ScalarField>,
    pub open_W: Vec<C::ScalarField>,
}

impl<C, CS> ProofLinkParts<C, CS>
where
    C: Curve,
    CS: CommitmentScheme<C, ProverChallenge = C::ScalarField, Challenge = C::ScalarField>,
{
    pub fn into_proof<S: SNARK<C::ScalarField>>(self, snark_proof: S::Proof) -> Proof<C, CS, S> {
        Proof {
            snark_proof,
            U_b_commitments: self.U_b_commitments,
            kzg_proofs: self.kzg_proofs,
            kzg_challenges: self.kzg_challenges,
            open_u: self.open_u,
            open_x: self.open_x,
            open_W: self.open_W,
        }
    }
}

/// Verifier parameters. `r1cs` and `cs_pk` are used in `LinkMode::Open` only (the verifier
/// re-evaluates the relation and recomputes the two commitments); `cs_vp` is used in
/// `LinkMode::KzgEval` only.
#[derive(Debug, Clone)]
pub struct VerifierParam<C1: Curve, CS_ProverKey, CS_VerifyingKey, S_VerifyingKey> {
    pub link: LinkMode,
    pub pp_hash: C1::ScalarField,
    pub snark_vp: S_VerifyingKey,
    pub cs_vp: CS_VerifyingKey,
    pub cs_pk: CS_ProverKey,
    pub r1cs: R1CS<C1::ScalarField>,
}

/// Prover parameters: the SNARK proving key, the commitment key and the circuit variant the keys
/// were generated for.
#[derive(Debug, Clone)]
pub struct ProverParam<S_ProvingKey, CS_ProverKey> {
    pub link: LinkMode,
    pub snark_pk: S_ProvingKey,
    pub cs_pk: CS_ProverKey,
}

/// Hiding onchain-style Decider for Nova (Groth16 + KZG when instantiated as in the runner).
#[derive(Clone, Debug)]
pub struct DeciderZK<C1, C2, FC, CS1, CS2, S> {
    _c1: PhantomData<C1>,
    _c2: PhantomData<C2>,
    _fc: PhantomData<FC>,
    _cs1: PhantomData<CS1>,
    _cs2: PhantomData<CS2>,
    _s: PhantomData<S>,
}

#[allow(clippy::type_complexity)]
impl<C1, C2, FC, CS1, CS2, S> DeciderZK<C1, C2, FC, CS1, CS2, S>
where
    C1: Curve<BaseField = C2::ScalarField, ScalarField = C2::BaseField>,
    C2: Curve,
    FC: FCircuit<C1::ScalarField>,
    // CS1 is a KZG commitment, where challenge is C1::Fr elem
    CS1: CommitmentScheme<
        C1,
        ProverChallenge = C1::ScalarField,
        Challenge = C1::ScalarField,
        Proof = KZGProof<C1>,
    >,
    // CS2 is the Pedersen commitment scheme of the CycleFold side
    CS2: CommitmentScheme<C2, ProverParams = PedersenParams<C2>>,
    S: SNARK<C1::ScalarField>,
{
    /// Circuit-specific setup of the SNARK for the hiding decider circuit in the given mode.
    pub fn preprocess(
        mut rng: impl RngCore + CryptoRng,
        (nova_pp, nova_vp): (
            <Nova<C1, C2, FC, CS1, CS2, false> as FoldingScheme<C1, C2, FC>>::ProverParam,
            <Nova<C1, C2, FC, CS1, CS2, false> as FoldingScheme<C1, C2, FC>>::VerifierParam,
        ),
        state_len: usize,
        link: LinkMode,
    ) -> Result<
        (
            ProverParam<S::ProvingKey, CS1::ProverParams>,
            VerifierParam<C1, CS1::ProverParams, CS1::VerifierParams, S::VerifyingKey>,
        ),
        Error,
    > {
        let circuit = Self::setup_circuit(&(nova_pp.clone(), nova_vp.clone()), state_len, link);
        let (snark_pk, snark_vp) = S::circuit_specific_setup(circuit, &mut rng)
            .map_err(|e| Error::SNARKSetupFail(e.to_string()))?;
        Self::params_from_keys((nova_pp, nova_vp), link, snark_pk, snark_vp)
    }

    /// The circuit (with dummy values) on which the SNARK setup has to be run. `preprocess` is
    /// `setup_circuit` + the SNARK's circuit-specific setup + `params_from_keys`; the three are
    /// exposed separately so that a caller can run the same SNARK through another driver (the
    /// TaxTag runner stores the R1CS matrices during setup to save memory at proving time).
    pub fn setup_circuit(
        (nova_pp, nova_vp): &(
            <Nova<C1, C2, FC, CS1, CS2, false> as FoldingScheme<C1, C2, FC>>::ProverParam,
            <Nova<C1, C2, FC, CS1, CS2, false> as FoldingScheme<C1, C2, FC>>::VerifierParam,
        ),
        state_len: usize,
        link: LinkMode,
    ) -> DeciderEthZKCircuit<C1, C2> {
        DeciderEthZKCircuit::<C1, C2>::dummy((
            nova_vp.r1cs.clone(),
            nova_vp.cf_r1cs.clone(),
            nova_pp.cf_cs_pp.clone(),
            nova_pp.poseidon_config.clone(),
            state_len,
            link,
        ))
    }

    /// Packs SNARK keys generated for `setup_circuit(.., link)` into the decider's parameters.
    pub fn params_from_keys(
        (nova_pp, nova_vp): (
            <Nova<C1, C2, FC, CS1, CS2, false> as FoldingScheme<C1, C2, FC>>::ProverParam,
            <Nova<C1, C2, FC, CS1, CS2, false> as FoldingScheme<C1, C2, FC>>::VerifierParam,
        ),
        link: LinkMode,
        snark_pk: S::ProvingKey,
        snark_vp: S::VerifyingKey,
    ) -> Result<
        (
            ProverParam<S::ProvingKey, CS1::ProverParams>,
            VerifierParam<C1, CS1::ProverParams, CS1::VerifierParams, S::VerifyingKey>,
        ),
        Error,
    > {
        let pp_hash = nova_vp.pp_hash()?;

        Ok((
            ProverParam {
                link,
                snark_pk,
                cs_pk: nova_pp.cs_pp.clone(),
            },
            VerifierParam {
                link,
                pp_hash,
                snark_vp,
                cs_vp: nova_vp.cs_vp,
                cs_pk: nova_pp.cs_pp,
                r1cs: nova_vp.r1cs,
            },
        ))
    }

    /// Honest prover: blinds the Nova instance with a fresh random satisfying relaxed instance,
    /// checks natively that the result is satisfiable (to fail early on a broken IVC state) and
    /// compresses it.
    pub fn prove(
        mut rng: impl RngCore + CryptoRng,
        pp: &ProverParam<S::ProvingKey, CS1::ProverParams>,
        nova: Nova<C1, C2, FC, CS1, CS2, false>,
    ) -> Result<Proof<C1, CS1, S>, Error> {
        let (circuit, aux) = DeciderEthZKCircuit::<C1, C2>::from_nova(nova, pp.link, &mut rng)?;
        circuit.check_native(&aux)?;
        Self::prove_circuit(rng, pp, circuit)
    }

    /// Compresses an already prepared circuit WITHOUT any native check. Exposed so that tests can
    /// run the prover on malformed witnesses and observe that the verifier rejects.
    pub fn prove_circuit(
        mut rng: impl RngCore + CryptoRng,
        pp: &ProverParam<S::ProvingKey, CS1::ProverParams>,
        circuit: DeciderEthZKCircuit<C1, C2>,
    ) -> Result<Proof<C1, CS1, S>, Error> {
        let parts = Self::link_parts(pp, &circuit)?;
        let snark_proof = S::prove(&pp.snark_pk, circuit, &mut rng)
            .map_err(|e| Error::Other(e.to_string()))?;
        Ok(parts.into_proof(snark_proof))
    }

    /// Everything of the proof except the SNARK proof itself: the public commitments and the
    /// mode-specific link (KZG openings, or the opened blinded witness). `prove_circuit` is
    /// `link_parts` + the SNARK prover + `ProofLinkParts::into_proof`; exposed separately so
    /// that a caller can produce the SNARK proof with another driver (see `setup_circuit`).
    pub fn link_parts(
        pp: &ProverParam<S::ProvingKey, CS1::ProverParams>,
        circuit: &DeciderEthZKCircuit<C1, C2>,
    ) -> Result<ProofLinkParts<C1, CS1>, Error> {
        if circuit.link != pp.link {
            return Err(Error::Other(
                "circuit variant (LinkMode) does not match the prover key".to_string(),
            ));
        }
        let U_b_commitments: [C1; 2] = circuit
            .U_b
            .get_commitments()
            .try_into()
            .map_err(|e: Vec<_>| Error::NotExpectedLength(e.len(), 2))?;

        let (kzg_proofs, kzg_challenges, open_u, open_x, open_W) = match pp.link {
            LinkMode::KzgEval => {
                let kzg_challenges = circuit.kzg_challenges.clone();
                // KZG opening proofs of U_b.cmW and U_b.cmE at the two challenges
                let kzg_proofs = circuit
                    .W_b
                    .get_openings()
                    .iter()
                    .zip(&kzg_challenges)
                    .map(|((v, _), &c)| {
                        CS1::prove_with_challenge(&pp.cs_pk, c, v, &C1::ScalarField::zero(), None)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                (kzg_proofs, kzg_challenges, vec![], vec![], vec![])
            }
            LinkMode::Open => (
                vec![],
                vec![],
                vec![circuit.U_b.u],
                circuit.U_b.x.clone(),
                circuit.W_b.W.clone(),
            ),
        };

        Ok(ProofLinkParts {
            U_b_commitments,
            kzg_proofs,
            kzg_challenges,
            open_u,
            open_x,
            open_W,
        })
    }

    /// The public inputs of the SNARK, as the verifier lays them out:
    /// - `Open`:    `[pp_hash, i, z_0, z_i, U_b.cmW, U_b.cmE, U_b.u, U_b.x]`
    /// - `KzgEval`: `[pp_hash, i, z_0, z_i, U_b.cmW, U_b.cmE, c_W, c_E, eval_W, eval_E]`
    ///
    /// (the two commitments in their non-native limb representation).
    pub fn public_inputs(
        link: LinkMode,
        pp_hash: C1::ScalarField,
        i: C1::ScalarField,
        z_0: &[C1::ScalarField],
        z_i: &[C1::ScalarField],
        proof: &Proof<C1, CS1, S>,
    ) -> Vec<C1::ScalarField> {
        let common = [
            &[pp_hash, i][..],
            z_0,
            z_i,
            &proof.U_b_commitments.inputize_nonnative(),
        ]
        .concat();
        match link {
            LinkMode::Open => [&common[..], &proof.open_u, &proof.open_x].concat(),
            LinkMode::KzgEval => [
                &common[..],
                &proof.kzg_challenges,
                &proof.kzg_proofs.iter().map(|p| p.eval).collect::<Vec<_>>(),
            ]
            .concat(),
        }
    }

    /// Verifier. Returns `Ok(true)` if the proof is accepted and an error otherwise.
    pub fn verify(
        vp: &VerifierParam<C1, CS1::ProverParams, CS1::VerifierParams, S::VerifyingKey>,
        i: C1::ScalarField,
        z_0: &[C1::ScalarField],
        z_i: &[C1::ScalarField],
        proof: &Proof<C1, CS1, S>,
    ) -> Result<bool, Error> {
        // same restriction as the original decider
        if i <= C1::ScalarField::one() {
            return Err(Error::NotEnoughSteps);
        }

        // shape of the mode-specific part
        match vp.link {
            LinkMode::Open => {
                if !proof.kzg_proofs.is_empty() || !proof.kzg_challenges.is_empty() {
                    return Err(Error::NotExpectedLength(proof.kzg_proofs.len(), 0));
                }
                if proof.open_u.len() != 1 {
                    return Err(Error::NotExpectedLength(proof.open_u.len(), 1));
                }
                if proof.open_x.len() != vp.r1cs.n_public_inputs() {
                    return Err(Error::NotExpectedLength(
                        proof.open_x.len(),
                        vp.r1cs.n_public_inputs(),
                    ));
                }
                if proof.open_W.len() != vp.r1cs.n_witnesses() {
                    return Err(Error::NotExpectedLength(
                        proof.open_W.len(),
                        vp.r1cs.n_witnesses(),
                    ));
                }
            }
            LinkMode::KzgEval => {
                if proof.kzg_proofs.len() != 2 {
                    return Err(Error::NotExpectedLength(proof.kzg_proofs.len(), 2));
                }
                if proof.kzg_challenges.len() != 2 {
                    return Err(Error::NotExpectedLength(proof.kzg_challenges.len(), 2));
                }
                if !proof.open_u.is_empty() || !proof.open_x.is_empty() || !proof.open_W.is_empty()
                {
                    return Err(Error::NotExpectedLength(proof.open_W.len(), 0));
                }
            }
        }

        let public_input = Self::public_inputs(vp.link, vp.pp_hash, i, z_0, z_i, proof);

        let snark_v = S::verify(&vp.snark_vp, &public_input, &proof.snark_proof)
            .map_err(|e| Error::Other(e.to_string()))?;
        if !snark_v {
            return Err(Error::SNARKVerificationFail);
        }

        match vp.link {
            LinkMode::Open => {
                // the revealed pair (U_b, W_b) satisfies the relaxed R1CS relation by
                // construction of E, and both commitments open to the revealed vectors
                let z = [&proof.open_u[..], &proof.open_x, &proof.open_W].concat();
                let E = vp.r1cs.eval_at_z(&z)?;
                let zero = C1::ScalarField::zero();
                if CS1::commit(&vp.cs_pk, &proof.open_W, &zero)? != proof.U_b_commitments[0] {
                    return Err(Error::CommitmentVerificationFail);
                }
                if CS1::commit(&vp.cs_pk, &E, &zero)? != proof.U_b_commitments[1] {
                    return Err(Error::CommitmentVerificationFail);
                }
            }
            LinkMode::KzgEval => {
                // verify the KZG openings of the two public commitments
                for ((cm, &c), pi) in proof
                    .U_b_commitments
                    .iter()
                    .zip(&proof.kzg_challenges)
                    .zip(&proof.kzg_proofs)
                {
                    CS1::verify_with_challenge(&vp.cs_vp, c, cm, pi)?;
                }
            }
        }

        Ok(true)
    }
}
