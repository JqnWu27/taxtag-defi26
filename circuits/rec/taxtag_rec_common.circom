pragma circom 2.0.0;
include "poseidon.circom";
include "smt/smtverifier.circom";
include "eddsaposeidon.circom";
include "comparators.circom";
include "bitify.circom";

// TaxTag recording circuit (SPEC.md sections 2 and 4, paper Fig. "crec").
//
// ONE circuit for every record. Five checks:
//   1 credential      EdDSA-Poseidon signature on M = P(9, tag) under one of
//                     the NKEYS recognized TA keys, which one staying hidden
//   2 anchor          id_tax = P(1, tag, S); AT[P(3, tag)] = P(2, S) under root_at
//   3 non-revocation  TRL leaf at P(3, tag) empty under root_trl
//   4 nullifier       nf = P(8, id_tax, cid, acaddr, i)
//   5 predecessor     only for i > 1:
//                       nf_prev   = P(8, id_tax, cid, acaddr, i - 1)
//                       leaf_prev = P(P(7, nf_prev, cid, block_prev, idx_prev),
//                                     body_prev, tail_prev)
//                     is in the RCL under root_rcl; nf_prev stays private.
//                     For i = 1 the check is off and root_rcl is unconstrained.
//
// Domain tags (first Poseidon input):
//   1 id_tax   2 anchor   3 AT/TRL index   7 leaf meta   8 nullifier
//   9 credential message   (10 leaf tail, 11 PSL meta, 13 blinding: not here)
//
// The circuit has no UNL path. Nullifier freshness is checked by the
// agency contract against its own storage (used[nf]).
//
// Trees: AT and TRL are circomlib sparse Merkle trees of depth D (16/64/128).
// The RCL is the positional append-only Merkle tree of leaves, depth DR = 32,
// node = P(left, right), empty leaf = 0.

// --- positional Merkle root for the RCL -------------------------------------
// Returns the root the path leads to; the caller compares it (so the
// comparison can be switched off for the first record).
template MerkleRootPos(DR) {
    signal input leaf;
    signal input pos;             // append index of the leaf
    signal input siblings[DR];
    signal output root;

    component bits = Num2Bits(DR);
    bits.in <== pos;

    signal cur[DR + 1];
    signal l[DR];
    signal r[DR];
    component h[DR];
    cur[0] <== leaf;
    for (var k = 0; k < DR; k++) {
        l[k] <== cur[k] + bits.out[k] * (siblings[k] - cur[k]);
        r[k] <== siblings[k] + bits.out[k] * (cur[k] - siblings[k]);
        h[k] = Poseidon(2);
        h[k].inputs[0] <== l[k];
        h[k].inputs[1] <== r[k];
        cur[k + 1] <== h[k].out;
    }
    root <== cur[DR];
}

// --- hidden selection of the verifying TA key -------------------------------
// Proves (Ax, Ay) is the key_index-th entry of the committed key list and
// that the list hashes to keyset_digest = P(P(pubx[0..]), P(puby[0..])).
template KeySelect(NKEYS) {
    signal input pubx[NKEYS];
    signal input puby[NKEYS];
    signal input key_index;
    signal input keyset_digest;
    signal output Ax;
    signal output Ay;

    component hx = Poseidon(NKEYS);
    component hy = Poseidon(NKEYS);
    for (var j = 0; j < NKEYS; j++) {
        hx.inputs[j] <== pubx[j];
        hy.inputs[j] <== puby[j];
    }
    component hd = Poseidon(2);
    hd.inputs[0] <== hx.out;
    hd.inputs[1] <== hy.out;
    keyset_digest === hd.out;

    component eq[NKEYS];
    signal accx[NKEYS + 1];
    signal accy[NKEYS + 1];
    signal accs[NKEYS + 1];
    accx[0] <== 0; accy[0] <== 0; accs[0] <== 0;
    for (var j = 0; j < NKEYS; j++) {
        eq[j] = IsEqual();
        eq[j].in[0] <== key_index;
        eq[j].in[1] <== j;
        accx[j + 1] <== accx[j] + eq[j].out * pubx[j];
        accy[j + 1] <== accy[j] + eq[j].out * puby[j];
        accs[j + 1] <== accs[j] + eq[j].out;
    }
    accs[NKEYS] === 1;      // exactly one key selected, index in range
    Ax <== accx[NKEYS];
    Ay <== accy[NKEYS];
}

// --- C_rec: the recording statement -----------------------------------------
template CRec(D, DR, NKEYS) {
    // ---- public, in the order the verifier contract receives them ----
    signal input nf;              // NF_i, marked used on acceptance
    signal input root_rcl;        // any earlier RCL root (unconstrained if i = 1)
    signal input root_at;         // any earlier AT root
    signal input root_trl;        // the current TRL root
    signal input keyset_digest;
    signal input cid;             // chain id
    signal input acaddr;          // agency contract address
    signal input owner;           // owner address the entry contract reports

    // ---- private ----
    signal input tag;
    signal input S;
    signal input i;               // counter of this record, 1-based
    // credential
    signal input R8x; signal input R8y; signal input Sig;
    signal input pubx[NKEYS]; signal input puby[NKEYS];
    signal input key_index;
    // anchor opening (AT inclusion at P(3, tag))
    signal input at_siblings[D];
    // TRL exclusion at P(3, tag)
    signal input trl_siblings[D];
    signal input trl_oldKey; signal input trl_oldValue; signal input trl_isOld0;
    // predecessor leaf (ignored when i = 1; any values, e.g. zeros)
    signal input block_prev; signal input idx_prev;
    signal input body_prev;  signal input tail_prev;
    signal input leaf_pos;
    signal input rcl_siblings[DR];

    // counter range: 1 <= i < 2^32
    component ibits = Num2Bits(32);
    ibits.in <== i;
    component izero = IsZero();
    izero.in <== i;
    izero.out === 0;

    // (1) credential: sigma_TA verifies on M = P(9, tag) under one
    //     recognized TA public key, which one staying hidden
    component ks = KeySelect(NKEYS);
    for (var j = 0; j < NKEYS; j++) {
        ks.pubx[j] <== pubx[j];
        ks.puby[j] <== puby[j];
    }
    ks.key_index <== key_index;
    ks.keyset_digest <== keyset_digest;

    component hm = Poseidon(2);
    hm.inputs[0] <== 9; hm.inputs[1] <== tag;
    component sig = EdDSAPoseidonVerifier();
    sig.enabled <== 1;
    sig.Ax <== ks.Ax;  sig.Ay <== ks.Ay;
    sig.R8x <== R8x;   sig.R8y <== R8y;  sig.S <== Sig;
    sig.M <== hm.out;

    // (2) anchor: id_tax = P(1, tag, S) and AT[P(3, tag)] = P(2, S)
    component hid = Poseidon(3);
    hid.inputs[0] <== 1; hid.inputs[1] <== tag; hid.inputs[2] <== S;
    signal id_tax;
    id_tax <== hid.out;

    component hix = Poseidon(2);
    hix.inputs[0] <== 3; hix.inputs[1] <== tag;
    component han = Poseidon(2);
    han.inputs[0] <== 2; han.inputs[1] <== S;
    component at = SMTVerifier(D);
    at.enabled <== 1;  at.fnc <== 0;          // inclusion
    at.root <== root_at;
    at.oldKey <== 0; at.oldValue <== 0; at.isOld0 <== 0;
    at.key <== hix.out;  at.value <== han.out;
    for (var k = 0; k < D; k++) { at.siblings[k] <== at_siblings[k]; }

    // (3) non-revocation: empty TRL leaf at P(3, tag)
    //
    // The exclusion flag MUST be boolean. circomlib's SMTVerifier does not
    // constrain isOld0: the level that should hold "another leaf" evaluates
    // to old1leaf * (1 - isOld0), so with a free flag a prover could pick any
    // (oldKey, oldValue), solve the flag as 1 - leaf(key, 1) / old1leaf and
    // get the exclusion of a key that IS in the tree accepted, i.e. a
    // revoked tag would still prove non-revocation.
    // Regression test: harness/test_isold0.js.
    trl_isOld0 * (trl_isOld0 - 1) === 0;
    component trl = SMTVerifier(D);
    trl.enabled <== 1;  trl.fnc <== 1;        // exclusion
    trl.root <== root_trl;
    trl.oldKey <== trl_oldKey; trl.oldValue <== trl_oldValue;
    trl.isOld0 <== trl_isOld0;
    trl.key <== hix.out;  trl.value <== 0;
    for (var k = 0; k < D; k++) { trl.siblings[k] <== trl_siblings[k]; }

    // (4) nullifier: nf = P(8, id_tax, cid, acaddr, i)
    component hnf = Poseidon(5);
    hnf.inputs[0] <== 8; hnf.inputs[1] <== id_tax;
    hnf.inputs[2] <== cid; hnf.inputs[3] <== acaddr; hnf.inputs[4] <== i;
    hnf.out === nf;

    // (5) predecessor, only when i > 1
    component hnfp = Poseidon(5);
    hnfp.inputs[0] <== 8; hnfp.inputs[1] <== id_tax;
    hnfp.inputs[2] <== cid; hnfp.inputs[3] <== acaddr; hnfp.inputs[4] <== i - 1;
    component hmeta = Poseidon(5);
    hmeta.inputs[0] <== 7; hmeta.inputs[1] <== hnfp.out;
    hmeta.inputs[2] <== cid; hmeta.inputs[3] <== block_prev;
    hmeta.inputs[4] <== idx_prev;
    component hleaf = Poseidon(3);
    hleaf.inputs[0] <== hmeta.out; hleaf.inputs[1] <== body_prev;
    hleaf.inputs[2] <== tail_prev;
    component mp = MerkleRootPos(DR);
    mp.leaf <== hleaf.out; mp.pos <== leaf_pos;
    for (var k = 0; k < DR; k++) { mp.siblings[k] <== rcl_siblings[k]; }

    component first = IsEqual();
    first.in[0] <== i; first.in[1] <== 1;
    // i > 1  =>  the path leads to root_rcl;  i = 1  =>  no condition
    (1 - first.out) * (mp.root - root_rcl) === 0;

    // owner is bound as a Groth16 public input; wire it once so the
    // signal is not dangling
    signal owner_sq;
    owner_sq <== owner * owner;
}
