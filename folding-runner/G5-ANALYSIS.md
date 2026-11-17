# G5 analysis: the in-circuit Pedersen commitment of the hiding decider

Read-only security review of finding **G5** (incomplete curve additions on scalars that are not
range-checked below the Grumpkin group order) in the hiding "blind-then-compress" decider at
`folding-runner/sonobe-zk/`. Related facts **F1** (honest-witness unsatisfiability
on zero scalar pairs) and **G4** (two skipped entries of an odd-length vector) are covered where
they bear on the answer. Every claim is tagged **[verified <file:line>]**, **[derived]** or
**[not established]**.

Build under analysis: sonobe pinned at rev 9414c45; `ark-r1cs-std` pinned to
`git+https://github.com/yelhousni/r1cs-std?rev=440ca3` ("perf/sw" branch, commit
`440ca331…`, "perf: optimize SW arithmetic")
[verified `sonobe-zk/Cargo.lock:697-699`, `sonobe-zk/Cargo.toml:14`]. Curves: C1 = BN254 G1,
C2 = Grumpkin (cofactor 1, so the group order equals the scalar-field order `q_Fq` = BN254 base
field, a 254-bit prime) [verified `ark-grumpkin-0.5.0/src/curves/mod.rs:21-25`]. The decider
circuit is over BN254 `Fr` = Grumpkin's base field, so Grumpkin point ops are native in it;
the commitment scalars are Grumpkin scalars (= BN254 `Fq`), carried non-natively.

---

## One-paragraph verdict

The soundness of the final (hiding) proof **is conditional**, exactly as ZK-DECIDER.md states.
The in-circuit Pedersen multi-scalar multiplication over Grumpkin is built from **incomplete**
addition formulas (`add_unchecked` / `double_and_add_unchecked`, slopes via
`mul_by_inverse_unchecked`) whose exceptional cases are **not excluded by any constraint**: when an
intermediate addition lands on two equal or opposite points, the slope is computed as `0/0`, which
in R1CS is satisfiable with an *arbitrary* witness, so the gadget's output at that step is
unconstrained. If a prover could reach such a case, it could make the commitment check accept a
`cf_W` that is **not** the true opening of the folded CycleFold instance, which would break the one
link (assumption A6 of ZK-DECIDER.md section 4) that makes the public folded commitments
`cmW_b, cmE_b` certify correct folding of the main Nova commitments — i.e. it would admit a false
IVC statement. **However**, reaching an exceptional case here is equivalent to exhibiting a short
integer relation `a·G_j + b·G_k = 0` between two *fixed, public* commitment generators, i.e. a
discrete-log relation on Grumpkin. Under (i) honest/random generation of the Pedersen generators and
(ii) hardness of discrete log on Grumpkin (~127-bit), no efficient prover can construct the witness
bits that trigger the case, so G5 is **not a practically exploitable break** — but this rests on an
*assumption that the code does not enforce*, rather than on a constraint. The honest-prover failure
F1 is a **completeness** problem (not soundness) and is worked around inside the hiding circuit; G4
is a genuine soundness hole in sonobe's **original** decider but is **repaired** in the hiding
circuit's own commitment routine. Net: conditional on honest generator setup and discrete-log
hardness on Grumpkin; a constraint-level fix (range-check + complete formulas, or an offset-point
MSM) would make it unconditional.

---

## Q1. Which curve operations, which formulas, which exceptional cases

**What the hiding circuit calls.** Check 7 builds the commitment through a local closure
`commit_all` [verified `decider_eth_zk_circuit.rs:696-729`], which:
- calls `PedersenGadget::<C2>::commit` on the even prefix (length `m = n − n%2`)
  [verified `:716`], and for an odd trailing entry adds `G[n-1].scalar_mul_le(v[n-1])`
  [verified `:725-727`];
- subtracts a **constant** offset point `C2::Var::constant(-offset)` [verified `:724`] (complete
  addition, because one operand is constant — see below).

`PedersenGadget::commit` sums the entries **pairwise** [verified `pedersen.rs:182-210`]; each pair
`(v[i-1], v[i])` is accumulated with `g[i-1].joint_scalar_mul_be(&g[i], bits(v[i-1]), bits(v[i]))`
[verified `pedersen.rs:196-207`]. So the dominant operation is **`joint_scalar_mul_be`** on the
fixed generators, plus one **`scalar_mul_le`** for the trailing odd entry.

**Which addition formulas these resolve to (pinned r1cs-std @440ca3).**
- `ProjectiveVar::joint_scalar_mul_be` is the SW-specific override, a Strauss–Shamir
  double-and-add whose body is entirely `NonZeroAffineVar::add_unchecked` /
  `double_and_add_unchecked` [verified `short_weierstrass/mod.rs:653-713`].
- `ProjectiveVar::scalar_mul_le` → `fixed_scalar_mul_le`, which uses `add_unchecked` for the first
  `split_len = scalar_modulus_bits − 2` bits and the **complete** `add_mixed`
  (Renes–Costello–Batina Alg. 2) for the remaining bits [verified
  `short_weierstrass/mod.rs:287-387, 591-646`].
- `add_unchecked`, `double`, `double_and_add_unchecked`, `triple` all compute slopes with
  `FieldVar::mul_by_inverse_unchecked` [verified `non_zero_affine.rs:46-204`].
- `mul_by_inverse_unchecked(self, d)` allocates `result` as a witness and enforces only
  `result · d = self`; when `d = 0` it stores `result = 0` and the constraint becomes `0 = self`
  [verified `fields/mod.rs:178-197`]. **Consequence:** if a slope's denominator is 0 *and* its
  numerator is 0, the constraint `result·0 = 0` holds for **every** `result` — the slope, and
  therefore the output point, is a free (unconstrained) witness. The slope's denominator and
  numerator are both 0 exactly when the two added points are **equal** (a doubling fed into an
  `add`), and the x-difference is 0 (points **±equal**) for the first-slope inverses.
- The ordinary `ProjectiveVar + ProjectiveVar` operator, by contrast, is the **complete** RCB
  Alg. 1 formula [verified `short_weierstrass/mod.rs:757-833`]; the `-offset` subtraction in
  `commit_all` uses it (constant operand) and is safe.

**Exceptional inputs.** For `add_unchecked(P, Q)`: unsatisfiable/underconstrained when `Q = 0`,
`Q = P` (0/0 slope → free output), or `Q = −P` (x1=x2, y1=−y2 → `x2−x1=0` but `y2−y1≠0` →
`result·0 = nonzero`, **unsatisfiable**). For `double()`: needs `y1 ≠ 0`. These are the documented
preconditions ("self ≠ ±other", "self ≠ zero") [verified `non_zero_affine.rs:44-131`]; nothing in
`PedersenGadget`/`commit_all` enforces them. **[derived]**

**Completeness vs soundness split:**
- `Q = −P` or `Q = 0` → constraints **unsatisfiable** → the honest (or any) prover simply cannot
  produce a proof. This is the *completeness* failure class, the same mechanism as **F1**: an
  honest all-zero scalar pair makes `joint_scalar_mul_be` try to form the point at infinity, which
  the incomplete formulas cannot represent. **[derived; F1 itself is the measured result of
  ZK-DECIDER.md section 1.2 — not re-run here]**
- `Q = P` (equal points) → `0/0` slope → **free output witness** → the *soundness* failure class:
  the gadget could emit a commitment value that is not the true MSM of the witness vector. **This is
  the G5 concern.** **[derived]**

---

## Q2. Scalar representation, booleanity, and range

**Representation.** Each committed entry is a `NonNativeUintVar<Fq>` (the CycleFold witness lives in
Grumpkin's scalar field `Fq`), turned into scalar bits by `to_bits_le()`
[verified `decider_eth_zk_circuit.rs:667-676`; `nonnative/uint.rs:495-504`, `154-174`]. A
`NonNativeUintVar` built from a field element has 5 limbs of 55,55,55,55,34 bits = **254 bits**
total [verified `nonnative/uint.rs:188-209, 243-271`].

**Booleanity.** Yes — the bits are genuine `Boolean`s: each limb is reconstructed with
`Boolean::le_bits_to_fp(bits).enforce_equal(v)` and each limb is bit-length-enforced
[verified `nonnative/uint.rs:154-174, 533-546, 259-266`]. `Boolean`s are individually constrained
to {0,1} by r1cs-std. **[verified]**

**Range below the group order: NO.** Allocation enforces only per-limb bit lengths; it never
enforces the composed value `< q` (Grumpkin order). The top limb is 34 bits, so the composed
witness can be any integer in `[0, 2^254)` [verified `nonnative/uint.rs:243-271` — no `enforce_lt`
against the modulus on this path]. Since `q ≈ 2^253.6`, a malicious witness assignment can represent
scalars in `[q, 2^254)` (about `0.2·q` values) that exceed the group order. **[derived]**

**Does exceeding the order create commitment ambiguity? No real ambiguity.** `s·G` depends only on
`s mod q`, so an out-of-range `s ∈ [q, 2^254)` commits to the same group element as `s − q`. It does
**not** let the prover "open to a different vector" in the sense of two distinct in-range vectors
with the same commitment — the commitment map on canonical scalars is still injective under the
binding assumption. **[derived]** The real effect of the missing range check is different: it is what
lets the double-and-add coefficients run close to / past the order, which is the precondition for the
exceptional-case analysis of Q3.

**Which routine is actually safe vs exposed under this range:**
- `scalar_mul_le` (odd trailing entry, and checks 4/6 challenge muls): **safe even for unreduced
  bits.** `fixed_scalar_mul_le` caps the incomplete part at `split_len = scalar_modulus_bits − 2 =
  252` bits, so the running coefficient stays `< 2^252 < q`, never reaching the exceptional multiples
  `±2^i·G`; the last 2 bits use complete `add_mixed` [verified `short_weierstrass/mod.rs:293-384`].
  The CycleFold challenge muls additionally use only 128-bit scalars (`NOVA_N_BITS_RO = 128`)
  [verified `constants.rs:5`], far below the order. **[derived]**
- `joint_scalar_mul_be` (every even pair — the bulk of the MSM): **exposed.** It has **no chunking
  and no complete-formula tail**; its Strauss–Shamir loop runs ~254 incomplete steps over the full
  scalar, so the per-generator coefficients grow to ~2^254, i.e. *into and past* the 254-bit order.
  The web-documented failure point for all-incomplete SW scalar mul is bit **252**, exactly this
  regime (see Q5). **[derived; Q5 corroborated by sources]**

---

## Q3. Can a malicious prover drive the gadget into a wrong-output exceptional case?

**Mechanism, if it were reachable (stated, not weaponised).** The MSM computes `Σ_j s_j·G_j` with
`G_j` fixed public generators and `s_j` free witness scalars. Inside `joint_scalar_mul_be` the
accumulator after `k` steps equals `a_k·G_{i-1} + b_k·G_i`, where `a_k, b_k` are the length-`k`
big-endian prefixes of the two chosen scalars [verified `short_weierstrass/mod.rs:695-712`]. An
exceptional case occurs when the accumulator coincides with the base point being added (or its
negation), i.e. `a_k·G_{i-1} + b_k·G_i = ±G_{i-1}` or `±G_i`. At that step the slope is `0/0`, the
output point becomes a free witness (Q1), and `NonZeroAffineVar` performs **no on-curve re-check**
after the operation [verified `non_zero_affine.rs:46-67` — output is just `Self::new(x3,y3)`], so the
freed point need not even lie on Grumpkin. A prover who could reach this could steer the MSM output
to an arbitrary point and thus satisfy `commit_all(cf_W_E) == cf_U.cmE`
[verified `decider_eth_zk_circuit.rs:730-731`] with a `cf_W` that is **not** the true opening.

**What that would buy the attacker in this protocol.** Checks 7 and 8 together are the only thing
tying the final CycleFold instance `(cf_U_5, cf_W_5)` to a *real* relaxed-R1CS witness
[verified `decider_eth_zk_circuit.rs:730-739`]. The CycleFold instance is what certifies that the
**group/commitment part** of both folds (A and B) was done correctly — it carries the correctness of
`cmW_b, cmE_b`, the public folded commitments (checks 4 and 6 fold five CycleFold instances into it)
[verified `decider_eth_zk_circuit.rs:521-641`]. Breaking A6 (ZK-DECIDER.md section 4) therefore
decouples the public `cmW_b/cmE_b` from the actual Nova commitment folding, which is precisely what a
forgery of the hiding proof for a false `(i, z_0, z_i)` needs. So **if** G5 were reachable, the
consequence would be a full soundness break of the final proof, not a minor leak. **[derived]**

**Why it is nevertheless not practically reachable (the argument, and its load-bearing
assumption).** The exceptional condition `a_k·G_{i-1} + b_k·G_i = ±G_{i-1}/±G_i` rearranges to a
**non-trivial integer relation** `α·G_{i-1} + β·G_i = 0` with `|α|,|β| ≲ 2^k`. For independently and
honestly generated generators, the lattice of such relations has covolume = group order ≈ 2^254, so
its shortest vector has length ≈ 2^127; relations short enough to be realised as a reachable
double-and-add prefix exist information-theoretically only once `k ≳ 127`, and **finding one is
equivalent to solving a 2-dimensional discrete-log / short-vector problem on Grumpkin** — i.e. as
hard as discrete log (~127-bit security). The prover cannot choose the triggering witness bits
without first solving that problem. Every exceptional sub-case in the chain (`add_unchecked` x-match,
the second slope `x3 = x1` inside `double_and_add_unchecked` [verified `non_zero_affine.rs:119-130,
156-167`], and `double()` needing `y ≠ 0`) reduces to the same kind of generator relation. The
generators are circuit **constants** taken from `cf_pedersen_params.generators`
[verified `decider_eth_zk_circuit.rs:661-666`], fixed at setup, so the prover cannot adaptively pick
them either. **[derived]**

**Verdict on Q3:** *No efficient attack*, **conditional on** (A) the Pedersen generators being
generated honestly/at random (no planted discrete-log relation) and (B) discrete-log hardness on
Grumpkin. Neither is enforced by a constraint; both are standard setup/hardness assumptions. If a
generator setup were adversarial (e.g. a generator chosen as a known small multiple of another), the
exceptional case would become reachable and the break of the preceding paragraph would apply. This is
the exact sense in which "the soundness claim is conditional on G5." **[derived]** I did **not**
attempt to construct a triggering assignment, and I did not run the circuit. **[not established: any
concrete reachable exceptional assignment under honest generators — argued negligible, not proven
absent.]**

---

## Q4. Does the hiding circuit's own commitment check change the answer, and is G4 a problem here?

**F1 ("covers").** The hiding circuit does not call `PedersenGadget::commit` directly on the raw
vector. `commit_all` appends a constant `Boolean::TRUE` top bit to every paired scalar, so the gadget
computes `Σ (v_j + 2^w)·G_j`, and then subtracts the constant `2^w·Σ G_j`
[verified `decider_eth_zk_circuit.rs:706-724`]. Effect: **every paired scalar is now ≥ 2^w ≠ 0**, so
the honest all-zero pair that made F1 unsatisfiable can no longer occur — this restores
**completeness** for zero entries. **[verified/derived]** It does **not** address G5: the paired
scalars still flow through the same incomplete `joint_scalar_mul_be`, now 255-bit, so the
exceptional-case *soundness* exposure of Q3 is unchanged (the offset is a constant-operand complete
addition and is safe) [verified `:716, :724`]. So F1 is covered; G5 is not — consistent with
ZK-DECIDER.md. **[derived]**

**G4 (two skipped entries of odd length).** In sonobe's **original** gadget the pairing loop is
`for i in (1..n-2).step_by(2)` plus explicit handling of the last one/two entries
[verified `pedersen.rs:192-208`]. For **odd** `n` this covers indices `0..=n-4` and `n-1`, leaving
**`n-3` and `n-2` unconstrained** by the commitment check. **[verified by reading the loop bounds]**
The CycleFold error vector has odd length (1349, per ZK-DECIDER.md section 1.2, G4 — **[not re-measured]**), so the
**original on-chain decider** (`on_chain.rs:271-274`, a direct `PedersenGadget::commit` call
[verified]) leaves two error-vector entries unbound — a real soundness gap in that circuit.
**In the hiding circuit this is repaired:** `commit_all` runs the gadget only on the even prefix
`m = n − n%2` (which the pairing loop covers completely) and adds the single trailing entry `n-1`
explicitly with `scalar_mul_le` [verified `decider_eth_zk_circuit.rs:706-727`]. Every entry of both
`cf_W.E` and `cf_W.W` is therefore covered. So **G4 is harmless in the hiding decider** (it is fixed
there), though it remains present in the untouched original decider. **[verified/derived]**

---

## Q5. Is this a known issue / changed upstream?

- **Pinned fork introduced the exposure.** Upstream arkworks' *default* `CurveVar::joint_scalar_mul_be`
  is `scalar_mul_le(bits1) + scalar_mul_le(bits2)` using the **complete** `+`
  [verified `r1cs-std@440ca3 src/groups/mod.rs:145-154`]. The pinned "perf/sw" fork **overrides** it
  for SW curves with the all-incomplete Strauss–Shamir version
  [verified `short_weierstrass/mod.rs:653-713`], and its CHANGELOG attributes this to PR #155
  ("Implement `joint_scalar_mul` using Strauss-Shamir's trick")
  [verified `r1cs-std@440ca3 CHANGELOG.md:3-8`]. The optimisation dropped the `split_len`/complete-tail
  safety that `scalar_mul_le` still has, which is what moves the paired path from "safe" to "exposed".
  **[verified]**
- **The hazard class is publicly known and acknowledged as unresolved.** The SW scalar-mul code
  itself documents that incomplete `add_unchecked` is exceptional "when either `b.is_zero()`, or when
  `b = ±a`," and that safety comes from partitioning the scalar
  [verified `short_weierstrass/mod.rs:300-314`]. Public discussion notes the all-incomplete algorithm
  first fails at **bit 252** and must switch to complete addition for the final iterations
  (zcash-derived analysis), and arkworks issue #14 explicitly leaves open whether the soundness holds.
  A separate historical advisory, **RUSTSEC-2021-0075 / CVE-2021-38194**, is a *different but adjacent*
  bug: `FieldVar::mul_by_inverse` enforced **no** constraint in ark-r1cs-std 0.2.0–0.3.0 (fixed 0.3.1),
  used primarily in SW scalar multiplication — the same primitive (`mul_by_inverse(_unchecked)`) that
  underlies the G5 slopes. **[verified via web sources below]**
- I found **no** public advisory specifically about sonobe's `PedersenGadget` or about this fork's
  `joint_scalar_mul_be` zero-pair / exceptional-case behaviour. **[not established]**

Sources (web): arkworks r1cs-std issue #14 — https://github.com/arkworks-rs/r1cs-std/issues/14 ;
RUSTSEC-2021-0075 — https://osv.dev/vulnerability/RUSTSEC-2021-0075 ;
CVE-2021-38194 — https://www.mend.io/vulnerability-database/CVE-2021-38194 ;
SW constant-bit handling commit — https://git.arnaucube.com/arnaucube/ark-r1cs-std/commit/d9e02004339d4a0d87d315c88f84a2bce331d01b .

---

## Q6. Cost of a fix

All three options target the paired MSM in `commit_all` / `PedersenGadget::commit`. Constraint
figures are **order-of-magnitude estimates [not measured]** (no builds run); the full circuit is ~8.6M constraints dominated by this block (ZK-DECIDER.md
F2, §8).

1. **Range-check each scalar `< q` before the MSM.** One `NonNativeUintVar::enforce_lt` against the
   modulus per entry (the machinery already exists: `enforce_lt`, used inside `modulo`
   [verified `nonnative/uint.rs:296-371, 741-742`]). Cost ≈ a few hundred constraints per entry ×
   (|E|+|W| ≈ 2·1349) ≈ low hundreds of thousands of constraints total. **This alone does not close
   G5** — even with `s < q`, the Strauss–Shamir coefficients still reach ~q and the `±G` collision /
   DL-relation exposure of Q3 remains. It removes the `[q, 2^254)` slack and the ambiguity of Q2 but
   must be combined with option 2 or 3. **Effort: low.** **[derived]**

2. **Use complete addition formulas for the paired path.** Replace `joint_scalar_mul_be` by two
   `scalar_mul_le` calls (upstream default) — each already has the `split_len` + complete-tail safety
   and is sound for 254-bit scalars (Q2) — or by a fully complete double-and-add. This **removes the
   exceptional case unconditionally** (no reliance on generator honesty or DL hardness). Cost: the
   complete RCB formulas are ~2× the constraints of the incomplete ones, and dropping Strauss–Shamir
   loses the shared-doubling saving, so expect roughly a **1.5–2× blow-up of the commitment block**
   (order a few million extra constraints on the full circuit). **Effort: low-moderate** (swap the
   gadget; re-generate keys). It also makes the F1 workaround (the appended top bit + offset) and
   the G4 trailing-entry special-casing unnecessary, simplifying `commit_all`. **[derived]**

3. **Offset-point ("blinding base") trick.** Run the incomplete MSM against a shifted accumulator
   `A0 = [2^t]·B` for a nothing-up-my-sleeve base `B`, guaranteeing every intermediate stays in the
   non-exceptional regime, then subtract the known constant `A0` at the end (one complete, constant
   addition). This keeps the cheap incomplete inner loop, adding only ~one extra base's worth of
   doublings and one final subtraction — **near-zero constraint overhead**. It is the standard SNARK
   MSM hardening. **Effort: moderate** (must prove the offset keeps the accumulator clear of all
   `±G_j` multiples for every admissible scalar; still wants option 1's range-check to bound the
   coefficients). **[derived]**

Recommendation for an unconditional claim: **option 1 + option 3** (range-check + offset base), or
the simpler **option 1 + option 2** if constraint count is not critical. Either removes G5 from the
assumption list and lets A6 be *argued from constraints* rather than assumed.

---

## What could not be established (read-only, no builds)

- **[not established]** Any concrete witness assignment that actually reaches an exceptional case
  under honestly generated generators. The negligibility argument is a reduction to discrete log, not
  a proof that no such assignment exists; it was not formalised.
- **[not established]** The specific bit index / step at which this fork's `joint_scalar_mul_be`
  first becomes exceptional for 254/255-bit scalars (the public "bit 252" figure is for a plain SW
  scalar mul, not this exact Strauss–Shamir variant). Not derived precisely; not simulated.
- **[not re-measured]** The CycleFold error/witness vector lengths (1349, odd) and the F1 run results
  (`sat-baseline = false`, `cfzeros` zero positions) — taken from ZK-DECIDER.md; F1's double-zero
  positions were not independently reconfirmed here.
- **[not established]** Whether the actual generator setup used by the runner is a
  nothing-up-my-sleeve / honest sampling in deployment; `Pedersen::setup` uses `C::rand` over the
  provided RNG [verified `pedersen.rs:45-57`], which is honest if the RNG is, but no ceremony exists
  (ZK-DECIDER.md §4 already flags this for the KZG and Groth16 setups).
- **[not established]** Exact constraint costs of the three fixes (no cargo builds were run);
  figures in Q6 are estimates.
- **[not established]** Whether downstream HyperNova/ProtoGalaxy variants (not used by this artifact)
  share the exposure — out of scope; not examined.
