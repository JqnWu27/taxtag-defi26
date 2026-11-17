# ZK-DECIDER: a hiding final proof for the Nova + CycleFold pipeline ("blind-then-compress")

Scope: the final proof that the taxpayer sends to the authority. Folding itself is unchanged.
Code: `sonobe-zk/folding-schemes/src/folding/nova/decider_eth_zk_circuit.rs` (circuit, native
blinding), `.../decider_eth_zk.rs` (setup, prover, verifier), runner
`sonobe-zk/taxtag-zk-runner/`. sonobe is pinned at rev 9414c45 ("pre-GR1CS"); the original
decider files are untouched.

Status of the claims in this file:

- The construction is implemented in full: both folds are verified by the compressing SNARK,
  including the CycleFold side. It was run end to end on the FULL decider circuit (not sonobe's
  reduced `light-test` circuit) for `c_step_d1` with 8 and 16 folded steps, in both proof
  formats: honest proofs are accepted and all rejection tests pass. (`c_step_d1` is a smaller
  step circuit with an IVC state of length 1 and 60 external inputs. It is not part of this
  repository. The numbers below that name it were measured on it. The numbers for the filing
  step circuit `c_fstep` are in `RESULTS.md`.)
- Two proof formats exist (section 3.4). `Open` is the one for which this file argues soundness
  and zero knowledge. `KzgEval` is the constant-size format; it is zero knowledge by the same
  argument, but its soundness rests on the same evaluation link as sonobe's original decider,
  which has the gap G2 (section 1.2; options in section 6). Do not describe `KzgEval` as sound.
- Everything stated here is an informal argument, not a proof, and nothing here was audited.

## 1. What was wrong with the existing final proof

### 1.1 It is not zero knowledge (the reason for this work)

sonobe's `DeciderEth` requires `Nova<.., false>` and gives the verifier:
`U_i.cmW`, `U_i.cmE`, `u_i.cmW` (deterministic KZG commitments to the running witness, the running
error vector and the witness of the last augmented step), `cmT`, the folding challenge `r`, the two
commitments of the folded instance, two evaluation points and the two evaluations of the folded
witness and error polynomials at them (linear functions of the private vectors), two KZG opening
proofs and the Groth16 proof. The commitments are deterministic, so a party that can guess the
witness can confirm the guess, and nothing bounds what the evaluations reveal.

### 1.2 Findings made while reading the pinned code

These are observations from reading the source (plus the build fingerprint for F0). None of them
was "exploited"; they are listed because they decide what the hiding construction may rely on.

- **F0, an example of the `solidity-verifiers` package is built with sonobe's reduced test
  circuit.** sonobe's own decider examples are registered as examples of the
  `solidity-verifiers` package. That package's dev-dependencies enable
  `folding-schemes/light-test`, and examples are compiled with dev-dependencies. With `light-test`
  the decider circuit skips its checks 4 and 5 (Pedersen openings of the CycleFold instance and
  the CycleFold relaxed R1CS relation). The build fingerprint of a runner registered this way
  lists the features `["default", "light-test", "parallel"]`. The reduced circuit has 677,659
  constraints for `c_step_d1`, the full one 9,283,431 (both measured here). A proof for the
  reduced circuit does not check the CycleFold side at
  all, so it does not establish that the commitments were folded correctly in any IVC step.
- **G1, the commitment fold of the last step is not bound by the circuit.** In the original
  decider the verifier computes the commitments of the folded instance from `U_i`'s and `u_i`'s
  commitments, `cmT` and `r`, all supplied next to the proof. None of those is a public input of
  the circuit (the public inputs are `pp_hash, i, z_0, z_i`, the folded commitments, the two
  challenges, the two evaluations, `cmT`). Inside the circuit the commitments of `U_i` and `u_i`
  are free witnesses that only enter hashes. So the circuit does not tie the public folded
  commitments to the instance whose hash sits in `u_i.x`. Since the error vector of a relaxed
  instance is free, satisfiability of the folded instance alone constrains nothing.
- **G2, the evaluation link does not fix the in-circuit vectors.** The link between the vectors
  inside the circuit and the public KZG commitments is: challenge `c = H(transcript, commitment)`,
  then "the in-circuit vector, as a polynomial, evaluates at `c` to the same value as the committed
  polynomial". The challenge does not depend on the in-circuit vectors. The Schwartz-Zippel
  argument needs both polynomials to be fixed before `c` is known, and the in-circuit vector is
  not. The link therefore does not show that the vector satisfying the relation in the circuit is
  the committed one.
- **G3, base case of the augmented circuit.** `AugmentedFCircuit` (nova/circuits.rs) computes
  `z_{i+1} = F(z_i)` from the witness `z_i` and, in the base case `i = 0`, outputs
  `H(1, z_0, z_1, U_bot)`. There was no constraint `z_i = z_0` for `i = 0`, so a chain could be
  started from any state while claiming `z_0`. Confirmed by a run before the change: the test
  `fold_started_from_another_state_is_rejected` failed with "IVC proof accepted for a chain that
  did not start at z_0".
  **FIXED in this copy of sonobe:** one conditional constraint was added to
  `sonobe-zk/folding-schemes/src/folding/nova/circuits.rs`, right after `is_basecase`:
  `z_i.conditional_enforce_equal(z_0, is_basecase)`. It is the only change to a non-hiding
  sonobe file. After the change the same test passes, on the small circuit
  (7 tests) and on the filing step circuit
  (runner mode `g3`: IVC verifier and decider both reject, the control
  with the honest `z_0` is accepted). The augmented circuit grows by one constraint per state
  element (158,982 to 158,983 for the filing step circuit); keys made before the change are
  invalid. The filing statement's Start check relies on this constraint. The filing fold
  driver's own sonobe clone (`folding/sonobe`) receives the same change from
  `folding/basecase_z0.patch`, so both copies fold over the same augmented
  circuit (the patch file is this change verbatim; the runner's mode `same-r1cs` compares the
  augmented circuits of the two frontends of this copy entry by entry).
- **G4, `PedersenGadget::commit` and odd lengths.** The gadget sums the entries pairwise; for an
  odd vector length `n` its loop leaves entries `n-3` and `n-2` out. The CycleFold error vector
  has length 1,349 here, so two of its entries are not bound by the in-circuit commitment check
  of the original circuit.
- **F1, the original FULL decider circuit is not satisfiable on honest witnesses of this
  pipeline.** Measured, not only read: `--mode sat-baseline` on the full build reports
  `satisfied = false`, and a Groth16 proof made from the honest
  witness with keys for that circuit is rejected by the verifier.
  Cause: with the r1cs-std revision that
  sonobe pins (`yelhousni/r1cs-std@440ca3`), `joint_scalar_mul_be`, which the Pedersen gadget
  uses for each pair of entries, is built from incomplete additions and has no satisfying
  assignment when both scalars of a pair are 0. The honest CycleFold error vector contains such
  pairs: `--mode cfzeros` shows zeros at entries 1342 to 1348 (the linear rows at the end of the
  CycleFold circuit, whose error entries are always 0) and double-zero pairs starting at 748,
  1342, 1344, 1346. So at the pinned revision the existing
  non-hiding decider yields a valid proof only for the reduced circuit of F0.

- **G5, incomplete curve additions on scalars that are not range-checked.** The same gadget
  (`joint_scalar_mul_be`, and the `add_unchecked` / `double_and_add_unchecked` formulas under
  it) computes slopes with `mul_by_inverse_unchecked`; its documented precondition is that the
  two points of an addition are never equal or opposite. The scalars it is given here are the
  bits of 256-bit non-native values that are not constrained to be below the group order
  (254 bits). I did not analyse whether a prover can choose such scalars so that a precondition
  fails inside the circuit, nor what that would let it do to the in-circuit commitment. This
  concerns the original decider and the hiding decider alike, because both commit to the
  CycleFold witness with this gadget (check 7 below). It is an open item, not a claim.
- **F2, weight of the full circuit.** The matrices of the full hiding circuit (`Open`) have
  19.7M, 20.9M and 270.3M non-zero entries (A, B, C): the
  gadget keeps intermediate curve points as linear combinations, so its rows grow along each
  double-and-add chain. This is a cost fact, not a soundness fact, but it is why the full
  circuit could not be set up with arkworks' standard path on a 32 GB machine.

Consequence for this work: the hiding decider must not reuse the verifier-side commitment fold
(G1), must cover the CycleFold part of the full circuit (F0), needs an answer to G2, and needs
its own in-circuit commitment check that covers every entry (G4) and accepts zero entries (F1).
G3 was fixed afterwards in the augmented circuit itself. G5 is inherited unchanged.

## 2. Idea

Before compression, fold the folded instance once more with a uniformly random satisfying relaxed
instance. The result `(U_b, W_b)` is uniformly distributed, so it may be shown to the verifier.
What must stay hidden is everything "upstream" of it: `U_i`, `u_i`, `cmT`, the random instance,
its cross-term commitment, the challenges, and the CycleFold instance. All of that is moved into
the witness of the compressing SNARK, which verifies both folds:

- the field part of each fold (the `u` and `x` components and the challenge derivation) directly,
- the group part of each fold (the commitments) through CycleFold: five CycleFold instances are
  folded into the CycleFold running instance inside the decider circuit, with the same gadgets
  that `AugmentedFCircuit` uses at every IVC step, and the final CycleFold instance is checked in
  the circuit (Pedersen openings and relaxed R1CS), as in the original full decider.

This follows the zero-knowledge layer of HyperNova (Kothapalli and Setty, appendix on zero
knowledge) and sonobe's `zk.rs`, with two differences: the proof of the folds is a SNARK instead
of revealed instances, so no hiding commitment scheme is needed and nothing of the CycleFold
instance is revealed; and the random instance's `cmE` is non-zero, which costs one extra CycleFold
instance.

## 3. The construction

Notation. `F` = BN254 scalar field. `R` = relaxed R1CS of the augmented step circuit
(`A z o B z = u C z + E`, `z = (u, x, W)`, `|x| = 2`). A committed instance is
`U = (cmE, u, cmW, x)`, its witness `(W, E)`. `Com` = sonobe's KZG vector commitment on BN254 G1,
non-hiding (`H = false`). `R_cf`, `cf_U`, `cf_W` = the same for the CycleFold circuit over
Grumpkin with Pedersen commitments. `T` = one Poseidon sponge used as transcript, started fresh.
`pp` = `pp_hash`. Folding challenges are 128-bit (`NOVA_N_BITS_RO`).

Input of the prover: the Nova state after `i >= 2` steps:
`(U_i, W_i)`, `(u_i, w_i)`, `(cf_U_i, cf_W_i)`, and the statement `(i, z_0, z_i)`.

### 3.1 Prover, native part (`DeciderEthZKCircuit::from_nova`)

1. **Fold A (the last real step).** `T_1 = cross term of (U_i, W_i), (u_i, w_i)`,
   `cmT = Com(T_1)`. `T` absorbs `pp, U_i, u_i, cmT`; `r_1 = T.squeeze(128 bits)`.
   `U_f = U_i + r_1 u_i` (with `cmE_f = U_i.cmE + r_1 cmT`), `W_f` accordingly.
2. **CycleFold for fold A.** Two CycleFold circuit instances with public inputs
   `(r_1, U_i.cmW, u_i.cmW, U_f.cmW)` and `(r_1, U_i.cmE, cmT, U_f.cmE)` (each asserts
   `P_out = P_0 + r P_1`). Each is committed (`cf_u_k`), its cross term committed (`cf_cmT_k`),
   `T` absorbs `pp, cf_U, cf_u_k, cf_cmT_k`, a challenge is squeezed, and `cf_u_k` is folded into
   the CycleFold running instance. Same order as `Nova::prove_step`.
3. **Sample the blinder** (`sample_relaxed_instance`): `u_r, x_r, W_r` uniform from `OsRng`;
   `E_r := A z_r o B z_r - u_r C z_r`; `U_r = (Com(E_r), u_r, Com(W_r), x_r)`. This pair satisfies
   `R` by construction. Fresh for every proof.
4. **Fold B (blinding).** `T_2 = cross term of (U_f, W_f), (U_r, W_r)`, `cmT_r = Com(T_2)`.
   `T` absorbs `pp, U_f, U_r, cmT_r`, where `U_r` is absorbed as `(u_r, x_r, cmE_r, cmW_r)`;
   only then `r_2 = T.squeeze(128 bits)`.
   `U_b = U_f + r_2 U_r`: `u_b = u_f + r_2 u_r`, `x_b = x_f + r_2 x_r`,
   `cmW_b = cmW_f + r_2 cmW_r`, `cmE_b = cmE_f + r_2 cmT_r + r_2^2 cmE_r`;
   `W_b = W_f + r_2 W_r`, `E_b = E_f + r_2 T_2 + r_2^2 E_r`.
5. **CycleFold for fold B.** Three instances:
   `(r_2, cmW_f, cmW_r, cmW_b)`, `(r_2, cmT_r, cmE_r, cmE_aux)` with
   `cmE_aux = cmT_r + r_2 cmE_r`, and `(r_2, cmE_f, cmE_aux, cmE_b)`. Folded as in step 2.
   The final CycleFold pair is `(cf_U_5, cf_W_5)`.
6. `KzgEval` format only: `T` absorbs `cmW_b`, squeezes `c_W`; absorbs `cmE_b`, squeezes `c_E`;
   `e_W = W_b(c_W)`, `e_E = E_b(c_E)` (vectors read as evaluations on a power-of-two domain, as
   in the original decider); KZG opening proofs for both.

The honest prover then checks natively that `(U_b, W_b)` satisfies `R` and `(cf_U_5, cf_W_5)`
satisfies `R_cf` (`check_native`), to fail early on a broken IVC state.

### 3.2 The decider circuit (`DeciderEthZKCircuit`, Groth16 over BN254)

Public inputs, in order:
`pp, i, z_0, z_i, cmW_b, cmE_b` (each point as non-native limbs), then
`u_b, x_b` (`Open`) or `c_W, c_E, e_W, e_E` (`KzgEval`).

Witness: `U_i, u_i, cmT, cmW_f, cmE_f, U_r, cmT_r, cmE_aux, cf_U_i`, the five `cf_u_k.cmW`, the
five `cf_cmT_k`, `cf_W_5`; in `KzgEval` also `(W_b, E_b)`.

Checks (the code uses the same numbers, with 9a for `Open` and 9b to 11b for `KzgEval`):

1. `u_i` is an incoming instance: `u_i.u = 1`, `u_i.cmE = 0`.
2. `u_i.x[0] = H(pp, i, z_0, z_i, U_i)` and `u_i.x[1] = H(pp, cf_U_i)`.
3. Fold A, field part: `r_1` is recomputed from the in-circuit transcript (absorbing
   `pp, U_i, u_i, cmT`); `u_f = U_i.u + r_1`, `x_f = U_i.x + r_1 u_i.x`.
4. The two CycleFold instances of fold A are built from the in-circuit values
   (`cf_u.u = 1`, `cf_u.cmE = 0`, `x = (r_1, P_0, P_1, P_out)`), their challenges are recomputed
   from the transcript, and they are folded into `cf_U_i` (group operations on Grumpkin are
   native in this circuit).
5. Fold B, field part: `r_2` is recomputed from the transcript after absorbing
   `pp, U_f, U_r, cmT_r`; `u_b = u_f + r_2 u_r`, `x_b = x_f + r_2 x_r`. The commitments of `U_b`
   are the public inputs.
6. The three CycleFold instances of fold B, folded as in 4. Result: `cf_U_5`.
7. Pedersen openings: `cf_U_5.cmE = Ped(cf_W_5.E)`, `cf_U_5.cmW = Ped(cf_W_5.W)` (full build only).
   Not a direct call of sonobe's gadget (see G4, F1): the gadget is applied to the first
   `m = n - (n mod 2)` entries with a constant 1 appended to every scalar as an extra top bit, so
   it computes `sum_j (v_j + 2^w) G_j`; the constant `2^w sum_j G_j` is subtracted; a trailing
   entry of an odd-length vector is added with the complete `scalar_mul_le`. Every entry is
   covered and zero entries are accepted.
8. `(cf_U_5, cf_W_5)` satisfies `R_cf` (non-native arithmetic; full build only).
9. `Open`: the public `u_b, x_b` equal the values computed in 5.
   `KzgEval`: `(U_b, (W_b, E_b))` satisfies `R`; `c_W, c_E` are recomputed from the transcript
   and equal the public ones; `W_b(c_W) = e_W`, `E_b(c_E) = e_E`.

Checks 7 and 8 are compiled out under sonobe's `light-test` feature, exactly as checks 4 and 5 of
the original circuit. A circuit without them is not a proof of anything about the commitments
(the tests show that the reduced `Open` circuit accepts a modified public commitment).

### 3.3 What the verifier receives

Statement: `i, z_0, z_i` (and `pp`, part of the verifier key).

| format | values received besides the statement |
|---|---|
| `Open` | Groth16 proof; `cmW_b`, `cmE_b`; `u_b`; `x_b` (2 elements); the vector `W_b` (one field element per witness of the augmented circuit, 89,938 for `c_step_d1`) |
| `KzgEval` | Groth16 proof; `cmW_b`, `cmE_b`; `c_W`, `c_E`; `e_W`, `e_E`; two KZG opening proofs (one G1 point each) |

Nothing else leaves the prover. In particular not `U_i`, `u_i`, `cmT`, `r_1`, `U_r`, `cmT_r`,
`r_2`, `cmE_aux`, `U_f`, nor any part of the CycleFold instance or witness.

### 3.4 Verifier (`DeciderZK::verify`)

Reject if `i <= 1` (same rule as the original decider). Check the lengths of the mode-specific
parts. Verify the Groth16 proof against the public inputs listed in 3.2. Then:

- `Open`: compute `E := A z o B z - u_b C z` for `z = (u_b, x_b, W_b)`; accept iff
  `Com(W_b) = cmW_b` and `Com(E) = cmE_b`. (Two multi-scalar multiplications and three sparse
  matrix-vector products. The verifier needs the commitment key and the R1CS of the augmented
  circuit; the latter can be regenerated from the step circuit.)
- `KzgEval`: accept iff both KZG openings verify (`cmW_b` at `c_W` to `e_W`, `cmE_b` at `c_E`
  to `e_E`).

## 4. Soundness (format `Open`)

Claim (informal). If the verifier accepts `(i, z_0, z_i)` with `i >= 2`, then, under the
assumptions below, one can extract `(U_i, W_i)`, `(u_i, w_i)`, `(cf_U_i, cf_W_i)` that pass
sonobe's IVC verifier `Nova::verify` for `(i, z_0, z_i)`: `u_i` is an incoming instance satisfied
by `w_i` with `u_i.x = (H(pp, i, z_0, z_i, U_i), H(pp, cf_U_i))`, `(U_i, W_i)` satisfies `R`,
`(cf_U_i, cf_W_i)` satisfies `R_cf`, and all commitments open to the witnesses. By the soundness
of Nova's IVC with CycleFold this means that `z_i` is the result of `i` applications of the step
function starting from `z_0` (G3, the missing base-case constraint, is fixed in this copy; see "Gaps").

Assumptions.
- A1. Groth16 is knowledge sound for the decider circuit and its setup was run honestly.
- A2. Poseidon behaves as a random oracle where it derives challenges (it is evaluated inside
  circuits, the usual heuristic of recursive arguments) and is collision resistant where it
  computes the state hashes.
- A3. The KZG vector commitment is binding (its setup was run honestly), and the Pedersen
  commitment on Grumpkin is binding.
- A4. Nova's folding scheme is knowledge sound (Nova, Theorem 1; rewinding on the folding
  challenge), also when the second instance is relaxed, and also for the CycleFold folds.
- A5. The CycleFold circuit is correct: an instance with public input `(r, P_0, P_1, P_out)` is
  satisfiable only if `P_out = P_0 + r P_1`.
- A6. The in-circuit Pedersen commitment of check 7 is correct: the circuit is satisfiable only
  if the committed vectors are the in-circuit ones. This is where G5 enters: A6 is assumed, not
  argued.

Argument.
1. By A1 there is a witness for the circuit, so checks 1 to 9 hold for extracted values.
2. By checks 7 and 8 and A6, `cf_U_5` is a satisfied CycleFold instance with known opening.
   (The constant top bit that check 7 adds to the paired scalars does not change the equation
   that is enforced: `sum_j (v_j + 2^w) G_j - 2^w sum_j G_j = sum_j v_j G_j`.)
3. `cf_U_5` is the fold of `cf_U_i` with the five instances `cf_u_1 .. cf_u_5` under challenges
   derived from a transcript that had absorbed, for each fold, the running instance, the incoming
   instance (all its public inputs and its commitment) and the cross-term commitment (checks 4, 6).
   Applying A4 five times, from the last fold backwards: each `cf_u_k` is satisfiable, and
   `cf_U_i` is satisfiable with an opening. By A5 the five group equations hold:
   `cmW_f = U_i.cmW + r_1 u_i.cmW`, `cmE_f = U_i.cmE + r_1 cmT`,
   `cmW_b = cmW_f + r_2 U_r.cmW`, `cmE_aux = cmT_r + r_2 U_r.cmE`, `cmE_b = cmE_f + r_2 cmE_aux`.
4. With checks 3 and 5: `U_f = NIFS.V(U_i, u_i; cmT)` with challenge `r_1` and
   `U_b = NIFS.V(U_f, U_r; cmT_r)` with challenge `r_2`, in all components. `r_2` is a hash of a
   transcript that contains `U_f` and the complete `U_r` (both commitments) and `cmT_r`; `r_1`
   likewise for `U_i`, `u_i`, `cmT`. The random instance can therefore not be chosen after the
   challenge it is folded with.
5. The verifier itself checked that `(W_b, E)` opens `(cmW_b, cmE_b)` and satisfies `R` with
   `(u_b, x_b)` (E is computed from the relation). So `(U_b, (W_b, E))` is in `R`. This step
   needs no evaluation argument, hence gap G2 does not arise in this format.
6. By A4 for fold B: `U_f` and `U_r` are satisfiable with extractable openings. By A4 for
   fold A: `U_i` and `u_i` are satisfiable with extractable openings; `u_i` is incoming by check 1.
7. Check 2 gives the two hash equalities. Together with 3 (for `cf_U_i`) and 6 these are the
   conditions of `Nova::verify`.

Soundness of format `KzgEval`: steps 1 to 4, 6 and 7 are identical. Step 5 is replaced by
check 9 in the circuit plus the two KZG openings, and that replacement has gap G2. I therefore
make no soundness claim for `KzgEval`.

Gaps and caveats of the soundness argument.
- It is a sketch. In particular the extraction in steps 3 and 6 rewinds a prover whose output is
  a SNARK proof about hash evaluations; this is the standard heuristic of Nova-style compression
  and is not proved here.
- G3 (section 1.2) is closed in this copy of sonobe by the added base-case constraint: "valid
  IVC chain" now includes that the first step was applied to the public `z_0`. Everything else
  about the IVC is sonobe's `AugmentedFCircuit` as it is at the pinned revision. A proof is only
  as good as the sonobe copy that produced its keys: a fold driven by an unpatched copy has a
  different augmented circuit and cannot be compressed with these keys.
- G5 (section 1.2) is inherited: assumption A6 rests on curve gadgets whose preconditions are
  not enforced for the scalars used. Until that is analysed or the gadget is replaced by one
  with complete arithmetic and range-checked scalars, the soundness claim above is conditional
  on it. (The IVC steps and the CycleFold folds of checks 4 and 6 use `scalar_mul_le` with
  128-bit challenges, not this gadget.)
- Non-native limbs of commitment coordinates are handled as in `AugmentedFCircuit`; I did not
  review that representation for canonicity.
- `i <= 1` is rejected, as in the original decider.
- The reduced (`light`) build is not sound by construction (checks 7, 8 missing).
- Both trusted setups (KZG, Groth16 circuit-specific) are generated locally by the runner from
  `OsRng`. A deployment needs proper ceremonies, and one Groth16 setup per step-circuit shape and
  per format.

## 5. Zero knowledge

Claim (informal). For both formats, the verifier's view can be simulated from the statement
alone, assuming: (Z1) the Groth16 setup is honest and the prover uses fresh proof randomness
(Groth16 is then perfectly zero knowledge); (Z2) the blinder `(u_r, x_r, W_r)` is uniform and
fresh for every proof; (Z3) Poseidon is a random oracle for the transcript, and the adversary
makes fewer than about `2^128` oracle queries.

The commitments are not hiding and do not need to be. The argument goes value by value.

1. **`z_b = (u_b, x_b, W_b)` is uniform and independent of the IVC witness.**
   `z_b = z_f + r_2 z_r`, where `z_r` is uniform and independent of `z_f`. `r_2` is the oracle's
   answer on a fresh point, so `(z_r, r_2)` are independent and `r_2` is non-zero except with
   probability `2^-128`; for fixed `z_f` and fixed non-zero `r_2` the map `z_r -> z_f + r_2 z_r`
   is a bijection. This is Lemma 9 of the HyperNova paper for relaxed R1CS.
2. **`cmW_b = Com(W_b)`** is a deterministic function of `W_b`, so it carries no more
   information than the uniform `W_b`.
3. **`E_b` and `cmE_b`.** Because `(U_b, W_b)` satisfies `R`, `E_b = A z_b o B z_b - u_b C z_b`:
   the folded error vector is a function of `z_b` only. So is `cmE_b = Com(E_b)`. The cross
   terms `T_1`, `T_2` and their commitments `cmT`, `cmT_r` influence the view only through this
   function of `z_b`; the commitments themselves are circuit witnesses and are not sent.
4. **Format `Open`** sends exactly `u_b, x_b, W_b, cmW_b, cmE_b`: covered by 1 to 3.
5. **Format `KzgEval`**, challenges `c_W, c_E`: outputs of the transcript after it absorbed, among
   others, `U_r` and `cmT_r`. Recomputing the transcript requires those values. Given the view and
   even a correct guess of the whole IVC witness, the unknown `r_2` (128 bits) still has to be
   found by trial before `z_r = (z_b - z_f) / r_2` and with it `U_r`, `cmT_r` can be formed and
   the guess tested. Under Z3 the challenges are therefore indistinguishable from uniform values
   independent of the witness.
6. **Format `KzgEval`**, evaluations and opening proofs: `e_W = W_b(c_W)`, `e_E = E_b(c_E)` and
   the two KZG witnesses are deterministic functions of `(W_b, E_b, c_W, c_E)`, i.e. of `z_b` and
   the challenges: covered by 1, 3, 5.
7. **Groth16 proof.** Perfectly simulatable given the public inputs (Z1). The public inputs are
   the statement and values covered above.
8. **CycleFold side.** `cf_U_i`, the five `cf_u_k`, the five cross-term commitments, `cf_U_5` and
   `cf_W_5` are witnesses of the Groth16 circuit. No function of them is output. So the CycleFold
   running instance needs no blinding of its own. (This is different from `zk.rs`, which reveals
   `cf_U_i` and `cf_W_i`.)

Simulator: sample `z_b` uniformly, compute `E_b`, both commitments and (for `KzgEval`) uniform
challenges, the evaluations and KZG witnesses; run the Groth16 simulator on the resulting public
inputs. By 1 to 8 the output is distributed as a real proof up to the events excluded by Z3.

The same guess-testing argument as in point 5 applies to `Open`: knowing `z_b` and a candidate
witness does not allow confirming the candidate without finding `r_2`. Zero knowledge is therefore
computational in the number of oracle queries, not statistical.

What is not hidden, and other caveats.
- The statement: `i`, `z_0`, `z_i`. Whatever `z_i` (the Poseidon digest of the step state)
  reveals is outside the decider. `i` is public; padding is handled elsewhere.
- The shape: proof size and circuit size depend on the step circuit, not on the witness or on `i`.
- Timing and other side channels of the prover are out of scope. The runner prints timings.
- Z1 with a maliciously generated Groth16 setup is not covered.
- The blinding is only as good as `OsRng`. Reusing a blinder for two proofs of different states
  would reveal linear relations between them.
- No test can establish zero knowledge. What the tests check is the necessary condition that two
  proofs of the same statement share no commitment, evaluation, opened value or SNARK element.

Residual leak: none identified beyond the statement itself.

## 6. Why two formats, and what would remove the gap of the constant-size one

G2 means that, for a constant-size proof with the vectors kept inside the circuit, the challenge
must depend on the in-circuit vector. Options considered:

- Hash `W_b` inside the circuit (Poseidon) and absorb the digest before deriving `c_W`, `c_E`.
  `E_b` is then fixed too, since the in-circuit relation determines it. I implemented this first
  (Poseidon of width 17 over the 89,938 elements; an ESTIMATED 3.4 million extra constraints,
  5,621 permutations of 612 constraints each; never measured, because it never ran to the end).
  With arkworks' Poseidon gadget the linear-combination bookkeeping alone needed tens of GB (a
  test process reached 92 GB of committed memory), so this variant could not be run on this
  machine and was removed again. A gadget written to keep linear combinations short would make it
  feasible; it is not delivered.
- A commit-carrying SNARK (a Groth16 variant whose proof contains a binding commitment to chosen
  witness wires, from which the verifier derives the challenge). Free in constraints, but a
  modified proof system with its own security analysis. Not attempted.
- Reveal `W_b`. Sound without any evaluation argument, zero knowledge because `W_b` is uniform,
  and it makes the circuit smaller (no in-circuit relation check, no polynomial evaluation). The
  price is proof size: one field element per witness of the augmented circuit (about 2.9 MB for
  `c_step_d1`), constant in the number of folded steps, and a verifier that performs two
  multi-scalar multiplications. This is format `Open`.

`KzgEval` is kept because it is the direct hiding counterpart of the existing decider (same link,
same proof size class) and allows a like-for-like cost comparison; it should not be used where
soundness matters until G2 is closed.

## 7. Tests (what they establish)

`taxtag-zk-runner/tests/zk_decider_small.rs` (small arkworks step circuit) and the runner's built-in
tests on `c_step_d1`, for both formats: honest proof verifies; wrong step count, wrong final
state, wrong initial state rejected; every public input carried by the proof tampered and
rejected; tampered Groth16 elements, KZG openings and opened witness entries rejected; a proof
whose blinding fold used a non-satisfying "random" instance (error vector changed in one entry,
commitment recomputed) rejected; a second proof of the same statement verifies and shares no
component with the first. Circuit-level tests additionally check that the circuit is unsatisfied
when the random instance or the cross-term commitment differs from the absorbed one.
The tests of `zk_decider_small.rs` run on the reduced build. The runner's built-in tests
(18 checks) passed on the full build in both formats.

## 8. What remains

- A reviewed proof of sections 4 and 5. (G3 is fixed here for Nova. sonobe's HyperNova and
  ProtoGalaxy step circuits, which this artifact does not use, were not examined; a search of
  their sources shows no corresponding base-case constraint.)
- G5: an analysis of the in-circuit Pedersen commitment gadget for scalars above the group
  order, or its replacement by a gadget with complete arithmetic and range-checked scalars
  (which would also remove the need for the extra top bit of check 7). Assumption A6 depends
  on it.
- Closing G2 for a constant-size proof (section 6), if the 2.9 MB of `Open` is not acceptable.
- A smaller full circuit. About 99% of the full hiding circuit (8.6 of 8.7 million constraints,
  the difference between the full and the reduced build) is the check of the final CycleFold
  instance: allocation of its witness, the in-circuit Pedersen commitment and the CycleFold
  relation. The same block dominates the original full decider and makes the matrices heavy
  (F2). This is sonobe's design, not specific to hiding.
- Ceremonies for the two setups (the Groth16 key and the KZG commitment key are generated
  locally with `OsRng`; whoever runs `setup_filing.sh` knows both trapdoors).
- The authority-side verifier, the runner's mode `verify`
  (`verify_filing.sh`), loads the verifier parameters from files (Nova parameters, step circuit,
  Groth16 verification key), uses no proving key, and checks the compressing proof, the boundary
  Groth16 proof, the equality of the start and end digests and the step-count rule
  (`API-zk-decider.md` section 3). It does not compare the other
  boundary public signals (tags, chain ids, addresses, roots, `y`, `C_prev`) with the authority's
  own values.
- `i = 1` (a single folded step) is rejected like in the original decider; padding avoids it.
