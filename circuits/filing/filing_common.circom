pragma circom 2.0.0;
include "poseidon.circom";
include "comparators.circom";
include "bitify.circom";
include "smt/smtverifier.circom";

// TaxTag, filing side: gadgets shared by the step circuit (c_fstep) and
// the boundary circuit (c_boundary). Formats follow SPEC.md section 2.
//
// Domain tags used on the filing side (first Poseidon input):
//    1 id_tax = P(1, tag, S)            2 anchor = P(2, S)
//    3 AT index = P(3, tag)             7 leaf meta = P(7, NF, cid, block, idx)
//    8 NF_i = P(8, id_tax, cid, acaddr, i)
//   10 leaf tail = P(10, value, position_id, time, 0)
//   11 PSL meta = P(11, kind, cid, block, idx)
//   12 closing state digest = P(12, root_assets, root_ledger, root_open, n_open)
//   13 blind_y = P(13, S, y)
// Untagged hashes: leaf body P(op, a_in, m_in, a_out, m_out), record leaf
// P(meta, body, tail), PSL body P(a_a, m_a, a_b, m_b, value), PSL entry
// P(pmeta, pbody, time), asset leaf P(q, avg), ledger leaf
// P(id_tax, n_chain0, n_chain1), open-position key P(cid, position_id),
// open-position leaf P(key, mark), pins P(9 fields), IVC state P(12 fields),
// C_y = P(state_digest, blind_y).

// Root of a positional Merkle tree. bits[0] is the lowest level; a set bit
// means the running node is the right child. siblings are bottom-up.
template PosRoot(D) {
    signal input leaf;
    signal input bits[D];
    signal input siblings[D];
    signal output root;
    component h[D];
    signal aux[D];
    for (var i = 0; i < D; i++) {
        h[i] = Poseidon(2);
        if (i == 0) {
            aux[i] <== (siblings[i] - leaf) * bits[i];
            h[i].inputs[0] <== leaf + aux[i];
        } else {
            aux[i] <== (siblings[i] - h[i - 1].out) * bits[i];
            h[i].inputs[0] <== h[i - 1].out + aux[i];
        }
        h[i].inputs[1] <== siblings[i] - aux[i];
    }
    root <== h[D - 1].out;
}

// One authenticated leaf replacement in a positional Merkle tree of depth D:
// checks old_leaf at index idx under root_in (when en = 1) and returns the
// root with new_leaf at the same index. en = 0 passes root_in through and
// checks nothing. idx is range-checked to D bits.
template TreeUpdate(D) {
    signal input en;
    signal input root_in;
    signal input idx;
    signal input siblings[D];
    signal input old_leaf;
    signal input new_leaf;
    signal output root_out;

    component bits = Num2Bits(D);
    bits.in <== idx;
    component ro = PosRoot(D);
    component rn = PosRoot(D);
    ro.leaf <== old_leaf;
    rn.leaf <== new_leaf;
    for (var i = 0; i < D; i++) {
        ro.bits[i] <== bits.out[i];
        rn.bits[i] <== bits.out[i];
        ro.siblings[i] <== siblings[i];
        rn.siblings[i] <== siblings[i];
    }
    en * (ro.root - root_in) === 0;
    root_out <== root_in + en * (rn.root - root_in);
}

// Dual-mode authenticated path over ONE chain of nLevels Poseidon(2) hashes.
//
//  smt_en = 1: circomlib sparse-Merkle-tree proof for `key` under `root`,
//              exactly SMTVerifier(nLevels): fnc = 0 proves (key -> leaf) is
//              in the tree, fnc = 1 proves key is absent (oldKey, oldValue,
//              isOld0 describe the leaf found on key's path).
//  rcl_en = 1: positional Merkle inclusion of `leaf` in a tree of depth DR
//              (the RCL). The path is read top-down: siblings[j] is the
//              sibling at height DR-1-j and bit j of `key` is the index bit
//              at that height, so `key` is the bit-reversed leaf index.
//  both 0   : nothing is checked.
// The caller guarantees smt_en, rcl_en, fnc are boolean and
// smt_en * rcl_en = 0. isOld0 is forced boolean HERE: circomlib's
// SMTVerifier leaves it unconstrained, and a non-boolean isOld0 lets a
// prover scale the old-leaf hash to any node value and forge an exclusion.
// Differences from circomlib's SMTVerifier: the bit decomposition of oldKey
// is dropped (its bits are never read by the verifier), isOld0 is boolean,
// and the two rcl_en hooks below.
template DualPath(nLevels, DR) {
    signal input smt_en;
    signal input rcl_en;
    signal input fnc;
    signal input root;
    signal input siblings[nLevels];
    signal input oldKey;
    signal input oldValue;
    signal input isOld0;
    signal input key;
    signal input leaf;

    assert(DR <= nLevels);
    var i;

    isOld0 * (isOld0 - 1) === 0;

    component hash1Old = SMTHash1();
    hash1Old.key <== oldKey;
    hash1Old.value <== oldValue;

    component hash1New = SMTHash1();
    hash1New.key <== key;
    hash1New.value <== leaf;

    component n2bNew = Num2Bits_strict();
    n2bNew.in <== key;

    component smtLevIns = SMTLevIns(nLevels);
    for (i = 0; i < nLevels; i++) smtLevIns.siblings[i] <== siblings[i];
    smtLevIns.enabled <== smt_en;

    component sm[nLevels];
    for (i = 0; i < nLevels; i++) {
        sm[i] = SMTVerifierSM();
        if (i == 0) {
            sm[i].prev_top <== smt_en;
            sm[i].prev_i0 <== 0;
            sm[i].prev_inew <== 0;
            sm[i].prev_iold <== 0;
            sm[i].prev_na <== 1 - smt_en;
        } else {
            sm[i].prev_top <== sm[i - 1].st_top;
            sm[i].prev_i0 <== sm[i - 1].st_i0;
            sm[i].prev_inew <== sm[i - 1].st_inew;
            sm[i].prev_iold <== sm[i - 1].st_iold;
            sm[i].prev_na <== sm[i - 1].st_na;
        }
        sm[i].is0 <== isOld0;
        sm[i].fnc <== fnc;
        sm[i].levIns <== smtLevIns.levIns[i];
    }
    sm[nLevels - 1].st_na + sm[nLevels - 1].st_iold + sm[nLevels - 1].st_inew + sm[nLevels - 1].st_i0 === 1;

    component levels[nLevels];
    for (i = nLevels - 1; i != -1; i--) {
        levels[i] = SMTVerifierLevel();

        // rcl hook 1: in positional mode every level below DR hashes.
        // (smt_en = 0 makes sm[i].st_top = 0, so the sum stays boolean.)
        if (i < DR) {
            levels[i].st_top <== sm[i].st_top + rcl_en;
        } else {
            levels[i].st_top <== sm[i].st_top;
        }
        levels[i].st_i0 <== sm[i].st_i0;
        levels[i].st_inew <== sm[i].st_inew;
        levels[i].st_iold <== sm[i].st_iold;
        levels[i].st_na <== sm[i].st_na;

        levels[i].sibling <== siblings[i];
        levels[i].old1leaf <== hash1Old.out;
        levels[i].new1leaf <== hash1New.out;

        levels[i].lrbit <== n2bNew.out[i];
        // rcl hook 2: in positional mode the leaf enters below level DR-1.
        // (smt_en = 0 makes every levels[*].root above it 0.)
        if (i == nLevels - 1) {
            if (i == DR - 1) {
                levels[i].child <== rcl_en * leaf;
            } else {
                levels[i].child <== 0;
            }
        } else {
            if (i == DR - 1) {
                levels[i].child <== levels[i + 1].root + rcl_en * leaf;
            } else {
                levels[i].child <== levels[i + 1].root;
            }
        }
    }

    // exclusion with an occupied neighbour leaf: its key must differ
    component areKeyEquals = IsEqual();
    areKeyEquals.in[0] <== oldKey;
    areKeyEquals.in[1] <== key;
    component keysOk = MultiAND(4);
    keysOk.in[0] <== fnc;
    keysOk.in[1] <== 1 - isOld0;
    keysOk.in[2] <== areKeyEquals.out;
    keysOk.in[3] <== smt_en;
    keysOk.out === 0;

    (smt_en + rcl_en) * (levels[0].root - root) === 0;
}

// circomlib SMTVerifier with isOld0 forced boolean (see DualPath).
template SMTVerifierB(nLevels) {
    signal input enabled;
    signal input root;
    signal input siblings[nLevels];
    signal input oldKey;
    signal input oldValue;
    signal input isOld0;
    signal input key;
    signal input value;
    signal input fnc;
    isOld0 * (isOld0 - 1) === 0;
    component v = SMTVerifier(nLevels);
    v.enabled <== enabled;
    v.root <== root;
    for (var i = 0; i < nLevels; i++) { v.siblings[i] <== siblings[i]; }
    v.oldKey <== oldKey;
    v.oldValue <== oldValue;
    v.isOld0 <== isOld0;
    v.key <== key;
    v.value <== value;
    v.fnc <== fnc;
}
