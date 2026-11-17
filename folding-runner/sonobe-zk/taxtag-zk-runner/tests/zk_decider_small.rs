#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
//! Tests of the hiding ("blind-then-compress") decider on a small arkworks step circuit
//! (`CustomFCircuit`, state length 1, no external inputs), for both link modes.
//!
//! Run (reduced circuit, `light-test`; the CycleFold checks are compiled out):
//!   cargo test --release --offline -p taxtag-zk-runner --features light --test zk_decider_small -- --test-threads=1
//! Run (full circuit; minutes and many GB of RAM for the end-to-end tests):
//!   cargo test --release --offline -p taxtag-zk-runner --test zk_decider_small -- --test-threads=1
//!
//! The same checks on the artifact's circom step circuit are in the runner binary
//! (`taxtag_zk_flow`). Every test starts the memory guard of `taxtag_zk_runner::mem`.
use ark_bn254::{Bn254, Fr, G1Projective as G1};
use ark_ec::{AffineRepr, CurveGroup};
use ark_groth16::Groth16;
use ark_grumpkin::Projective as G2;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::rngs::OsRng, One, Zero};

use folding_schemes::{
    arith::ArithRelation,
    commitment::{kzg::KZG, pedersen::Pedersen, CommitmentScheme},
    folding::nova::{
        decider_eth_zk::{DeciderZK, Proof},
        decider_eth_zk_circuit::{sample_relaxed_instance, DeciderEthZKCircuit, LinkMode},
        CommittedInstance, Nova, PreprocessorParam, ProverParams, VerifierParams, Witness,
    },
    frontend::{utils::CustomFCircuit, FCircuit},
    transcript::poseidon::poseidon_canonical_config,
    Error, FoldingScheme,
};
use taxtag_zk_runner::mem;

type FC = CustomFCircuit<Fr>;
type K = KZG<'static, Bn254>;
type N = Nova<G1, G2, FC, K, Pedersen<G2>, false>;
type D = DeciderZK<G1, G2, FC, K, Pedersen<G2>, Groth16<Bn254>>;
type P = Proof<G1, K, Groth16<Bn254>>;
type NovaParams = (
    ProverParams<G1, G2, K, Pedersen<G2>, false>,
    VerifierParams<G1, G2, K, Pedersen<G2>, false>,
);

const MODES: [LinkMode; 2] = [LinkMode::Open, LinkMode::KzgEval];

fn setup_nova() -> Result<(FC, NovaParams), Error> {
    mem::start_guard();
    let f_circuit = FC::new(10)?;
    let prep = PreprocessorParam::new(poseidon_canonical_config::<Fr>(), f_circuit);
    let params = N::preprocess(OsRng, &prep)?;
    Ok((f_circuit, params))
}

fn fold(f_circuit: FC, params: &NovaParams, n_steps: usize) -> Result<N, Error> {
    let mut nova = N::init(params, f_circuit, vec![Fr::from(3_u32)])?;
    for _ in 0..n_steps {
        nova.prove_step(OsRng, (), None)?;
    }
    N::verify(params.1.clone(), nova.ivc_proof())?;
    Ok(nova)
}

fn satisfied(c: DeciderEthZKCircuit<G1, G2>) -> Result<bool, Error> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    c.generate_constraints(cs.clone())?;
    Ok(cs.is_satisfied()?)
}

/// A "random" pair that does NOT satisfy the relation: the error vector is modified in one
/// position and re-committed, so every commitment still opens correctly and only the relaxed
/// R1CS relation is violated.
fn non_satisfying_blinder(nova: &N) -> Result<(Witness<G1>, CommittedInstance<G1>), Error> {
    let (mut W_r, mut U_r) = sample_relaxed_instance::<G1, K>(&nova.r1cs, &nova.cs_pp, OsRng)?;
    W_r.E[0] += Fr::one();
    U_r.cmE = <K as CommitmentScheme<G1>>::commit(&nova.cs_pp, &W_r.E, &Fr::zero())?;
    assert!(nova.r1cs.check_relation(&W_r, &U_r).is_err());
    Ok((W_r, U_r))
}

/// The sampled blinding pair satisfies the relaxed relation, and the circuit built from an honest
/// IVC state is satisfied for both link modes and for an even and an odd number of steps.
#[test]
fn circuit_honest_is_satisfied() -> Result<(), Error> {
    let (f, params) = setup_nova()?;
    for n_steps in [2, 3] {
        let nova = fold(f, &params, n_steps)?;
        let (W_r, U_r) = sample_relaxed_instance::<G1, K>(&nova.r1cs, &nova.cs_pp, OsRng)?;
        nova.r1cs.check_relation(&W_r, &U_r)?;
        for link in MODES {
            let (circuit, aux) = DeciderEthZKCircuit::from_nova(nova.clone(), link, OsRng)?;
            circuit.check_native(&aux)?;
            assert!(satisfied(circuit)?, "n_steps={n_steps} link={link:?}");
        }
    }
    Ok(())
}

/// Every single deviation from the honest witness leaves the circuit unsatisfied.
#[test]
fn circuit_rejects_deviations() -> Result<(), Error> {
    let (f, params) = setup_nova()?;
    let nova = fold(f, &params, 3)?;
    for link in MODES {
        let (good, _) = DeciderEthZKCircuit::from_nova(nova.clone(), link, OsRng)?;
        assert!(satisfied(good.clone())?);
        let mut bad: Vec<(&str, DeciderEthZKCircuit<G1, G2>)> = vec![];

        let mut c = good.clone();
        c.z_i[0] += Fr::one();
        bad.push(("wrong final state", c));
        let mut c = good.clone();
        c.i += Fr::one();
        bad.push(("wrong step count", c));
        let mut c = good.clone();
        c.z_0[0] += Fr::one();
        bad.push(("wrong initial state", c));
        let mut c = good.clone();
        c.pp_hash += Fr::one();
        bad.push(("wrong pp_hash", c));
        // In `Open` mode the public commitments enter the circuit only as the claimed outputs of
        // CycleFold instances. With the `light` feature the final CycleFold instance is not
        // checked in-circuit, so the reduced circuit does NOT bind them (the verifier still
        // recomputes them from the revealed witness, see `end_to_end`); the full circuit does.
        let commitments_bound_in_circuit = !cfg!(feature = "light") || link == LinkMode::KzgEval;
        if commitments_bound_in_circuit {
            let mut c = good.clone();
            c.U_b.cmW = c.U_b.cmW + c.U_b.cmW;
            bad.push(("tampered U_b.cmW", c));
            let mut c = good.clone();
            c.U_b.cmE = c.U_b.cmE + c.U_b.cmE;
            bad.push(("tampered U_b.cmE", c));
        }
        let mut c = good.clone();
        c.cmT_r = c.cmT_r + c.cmT_r;
        bad.push(("cross-term commitment differs from the absorbed one", c));
        let (_, U_r2) = sample_relaxed_instance::<G1, K>(&nova.r1cs, &nova.cs_pp, OsRng)?;
        let mut c = good.clone();
        c.U_r = U_r2;
        bad.push(("random instance differs from the absorbed one", c));
        // The last CycleFold cross-term only influences the final CycleFold instance. With the
        // `light` feature that instance is not checked in-circuit, so in `Open` mode this
        // deviation is (by design of the reduced circuit) NOT detected: one concrete reason why
        // the reduced circuit is not a sound proof. In `KzgEval` mode the later transcript
        // challenges still depend on it.
        if commitments_bound_in_circuit {
            let mut c = good.clone();
            c.cf_cmT[4] = c.cf_cmT[4] + c.cf_cmT[4];
            bad.push(("tampered CycleFold cross-term", c));
        }

        match link {
            LinkMode::Open => {
                let mut c = good.clone();
                c.U_b.u += Fr::one();
                bad.push(("tampered public U_b.u", c));
                let mut c = good.clone();
                c.U_b.x[1] += Fr::one();
                bad.push(("tampered public U_b.x", c));
            }
            LinkMode::KzgEval => {
                let mut c = good.clone();
                c.kzg_evaluations[1] += Fr::one();
                bad.push(("tampered evaluation", c));
                let mut c = good.clone();
                c.kzg_challenges[0] += Fr::one();
                bad.push(("tampered challenge", c));
                let mut c = good.clone();
                c.W_b.W[0] += Fr::one();
                bad.push(("folded witness modified", c));
            }
        }
        for (name, c) in bad {
            assert!(!satisfied(c)?, "accepted: {name} ({link:?})");
        }
    }
    Ok(())
}

/// Blinding with a "random" instance that does NOT satisfy the relation.
/// - `KzgEval`: the circuit itself is unsatisfied (it checks the relation of the folded pair);
/// - `Open`: the relation is the verifier's job, so the circuit stays satisfied; the native check
///   fails here and the verifier-side rejection is asserted in `end_to_end`.
#[test]
fn circuit_and_non_satisfying_blinder() -> Result<(), Error> {
    let (f, params) = setup_nova()?;
    let nova = fold(f, &params, 3)?;
    for link in MODES {
        let (W_r, U_r) = non_satisfying_blinder(&nova)?;
        let (bad, aux) =
            DeciderEthZKCircuit::from_nova_with_blinder(nova.clone(), link, W_r, U_r, OsRng)?;
        assert!(bad.check_native(&aux).is_err());
        match link {
            LinkMode::KzgEval => assert!(!satisfied(bad)?),
            LinkMode::Open => assert!(satisfied(bad)?),
        }
    }
    Ok(())
}

/// Two blindings of the same IVC state share no verifier-visible value.
#[test]
fn blinding_is_fresh() -> Result<(), Error> {
    let (f, params) = setup_nova()?;
    let nova = fold(f, &params, 2)?;
    let (a, _) = DeciderEthZKCircuit::from_nova(nova.clone(), LinkMode::KzgEval, OsRng)?;
    let (b, _) = DeciderEthZKCircuit::from_nova(nova.clone(), LinkMode::KzgEval, OsRng)?;
    assert_ne!(a.U_b.cmW, b.U_b.cmW);
    assert_ne!(a.U_b.cmE, b.U_b.cmE);
    assert_ne!(a.U_b.u, b.U_b.u);
    assert_ne!(a.U_b.x, b.U_b.x);
    assert_ne!(a.kzg_challenges, b.kzg_challenges);
    assert_ne!(a.kzg_evaluations, b.kzg_evaluations);
    // no coordinate of the blinded witness repeats
    assert!(a.W_b.W.iter().zip(&b.W_b.W).all(|(x, y)| x != y));
    Ok(())
}

/// G3: a fold that is started from another first state than the claimed `z_0` must be rejected.
/// The prover keeps `z_0 = 3` as the public initial state but feeds the first step with the
/// state 4. Every step is a valid application of the step function, so without the base-case
/// constraint `z_i == z_0` (added to `AugmentedFCircuit` in this copy of sonobe) nothing in the
/// IVC notices.
#[test]
fn fold_started_from_another_state_is_rejected() -> Result<(), Error> {
    let (f, params) = setup_nova()?;
    let mut nova = N::init(&params, f, vec![Fr::from(3_u32)])?;
    nova.z_i = vec![Fr::from(4_u32)];
    for _ in 0..3 {
        nova.prove_step(OsRng, (), None)?;
    }
    assert_eq!(nova.z_0, vec![Fr::from(3_u32)]);
    // the IVC verifier rejects
    assert!(
        N::verify(params.1.clone(), nova.ivc_proof()).is_err(),
        "IVC proof accepted for a chain that did not start at z_0"
    );
    // and so does the decider's native check of the blinded pair, in both formats
    for link in MODES {
        let (circuit, aux) = DeciderEthZKCircuit::from_nova(nova.clone(), link, OsRng)?;
        assert!(circuit.check_native(&aux).is_err());
    }
    Ok(())
}

/// Full prove / verify cycle with Groth16, including the rejection cases at the verifier.
fn end_to_end(link: LinkMode) -> Result<(), Error> {
    let (f, params) = setup_nova()?;
    let (pp, vp) = D::preprocess(OsRng, params.clone(), f.state_len(), link)?;
    let nova = fold(f, &params, 3)?;
    let ok = |p: &P| D::verify(&vp, nova.i, &nova.z_0, &nova.z_i, p);

    let proof = D::prove(OsRng, &pp, nova.clone())?;
    assert!(ok(&proof)?);

    // serialization round trip
    let mut bytes = vec![];
    proof.serialize_compressed(&mut bytes)?;
    let proof2 = P::deserialize_compressed(&mut bytes.as_slice())?;
    assert!(ok(&proof2)?);

    // wrong statement: step count, final state, initial state
    assert!(D::verify(&vp, nova.i + Fr::one(), &nova.z_0, &nova.z_i, &proof).is_err());
    assert!(D::verify(&vp, nova.i, &nova.z_0, &[nova.z_i[0] + Fr::one()], &proof).is_err());
    assert!(D::verify(&vp, nova.i, &[nova.z_0[0] + Fr::one()], &nova.z_i, &proof).is_err());

    // tampered proof components
    let mut t = proof.clone();
    t.snark_proof.a = (t.snark_proof.a.into_group() + t.snark_proof.a).into_affine();
    assert!(ok(&t).is_err());
    let mut t = proof.clone();
    t.U_b_commitments[0] = t.U_b_commitments[0] + t.U_b_commitments[0];
    assert!(ok(&t).is_err());
    let mut t = proof.clone();
    t.U_b_commitments[1] = t.U_b_commitments[1] + t.U_b_commitments[1];
    assert!(ok(&t).is_err());
    match link {
        LinkMode::KzgEval => {
            let mut t = proof.clone();
            t.kzg_proofs[1].eval += Fr::one();
            assert!(ok(&t).is_err());
            let mut t = proof.clone();
            t.kzg_proofs[0].proof = t.kzg_proofs[0].proof + t.kzg_proofs[0].proof;
            assert!(ok(&t).is_err());
            let mut t = proof.clone();
            t.kzg_challenges[0] += Fr::one();
            assert!(ok(&t).is_err());
        }
        LinkMode::Open => {
            let mut t = proof.clone();
            t.open_u[0] += Fr::one();
            assert!(ok(&t).is_err());
            let mut t = proof.clone();
            t.open_x[0] += Fr::one();
            assert!(ok(&t).is_err());
            let mut t = proof.clone();
            t.open_W[7] += Fr::one();
            assert!(ok(&t).is_err());
            let mut t = proof.clone();
            t.open_W.pop();
            assert!(ok(&t).is_err());
        }
    }

    // a proof produced with a non-satisfying blinding instance is rejected
    let (W_r, U_r) = non_satisfying_blinder(&nova)?;
    let (bad, _) =
        DeciderEthZKCircuit::from_nova_with_blinder(nova.clone(), link, W_r, U_r, OsRng)?;
    let bad_proof = D::prove_circuit(OsRng, &pp, bad)?;
    assert!(ok(&bad_proof).is_err());

    // fresh blinding: a second proof of the same statement shares no component
    let proof_b = D::prove(OsRng, &pp, nova.clone())?;
    assert!(ok(&proof_b)?);
    assert_ne!(proof.snark_proof, proof_b.snark_proof);
    assert_ne!(proof.U_b_commitments[0], proof_b.U_b_commitments[0]);
    assert_ne!(proof.U_b_commitments[1], proof_b.U_b_commitments[1]);
    match link {
        LinkMode::KzgEval => {
            assert_ne!(proof.kzg_challenges, proof_b.kzg_challenges);
            assert_ne!(proof.kzg_proofs[0].eval, proof_b.kzg_proofs[0].eval);
            assert_ne!(proof.kzg_proofs[1].eval, proof_b.kzg_proofs[1].eval);
        }
        LinkMode::Open => {
            assert_ne!(proof.open_u, proof_b.open_u);
            assert_ne!(proof.open_x, proof_b.open_x);
            assert!(proof.open_W.iter().zip(&proof_b.open_W).all(|(x, y)| x != y));
        }
    }
    Ok(())
}

#[test]
fn end_to_end_open() -> Result<(), Error> {
    end_to_end(LinkMode::Open)
}

#[test]
fn end_to_end_kzg_eval() -> Result<(), Error> {
    end_to_end(LinkMode::KzgEval)
}
