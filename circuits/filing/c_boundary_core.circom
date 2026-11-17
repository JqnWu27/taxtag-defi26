pragma circom 2.0.0;
include "filing_common.circom";

// TaxTag boundary circuit (SPEC.md section 7, final checks 1-7), proven
// with Groth16. It shares the public start and end state digests z0, zn with
// the folded proof: the authority checks that the decider's (z_0, z_i) equal
// this proof's (z0, zn) and that the step count is a power of two >= 64.
//
// Template Boundary(NT, D): NT tag slots (1..16, slots NT..15 of the depth-4
// ledger tree are empty), 2 chains, SMT depth D for the AT and UNL proofs.
// A slot with tag = 0 is inactive (an empty ledger leaf, no checks).
//
// Public inputs, in this order:
//   z0, zn                       start and end IVC state digests
//   tags[NT]                     demanded tag set T, slot order
//   cid[2], acaddr[2]            per chain
//   root_rcl[2], root_unl[2], root_at[2], root_psl[2]   snapshot roots at B
//   y                            the period (nonzero)
//   d_proceeds, d_cost, d_income line items D; d_income is
//                                proceeds - cost + other_income in the field
//                                (a loss is p - |loss|)
//   c_prev                       C_{y-1}, 0 at a first filing
//   c_y                          C_y
//   closing                      1 = closing filing (final open set empty)
//
// What it proves:
//  1 Start. z0 opens to (root_assets, ledger_start, root_open, cnt_work =
//    n_open, cnt_final = 0, zero totals, zero merge key, pins, blind), where
//    (root_assets, ledger_prev, root_open, n_open) is committed in c_prev
//    with blind P(13, S_0, y - 1); at a first filing (c_prev = 0) the state is
//    the empty one. ledger_start equals ledger_prev except that an active
//    slot whose previous leaf was empty starts as P(id_tax, 0, 0) (a tag new
//    in this filing).
//  2 Anchor. Per active slot and chain: id_tax = P(1, tag, S) and the AT
//    holds P(2, S) at P(3, tag) under root_at[c].
//  3 End of ledger. Per active slot and chain: NF = P(8, id_tax, cid, acaddr,
//    n + 1) is absent from the UNL under root_unl[c]; NF stays private.
//  4 Every pair. All 16 ledger leaves are rebuilt here, so every demanded
//    (tag, chain) has its start counter, its anchor and its end.
//  5 The working open set is empty: zn opens with cnt_work = 0.
//  6 D equals the final totals, and c_y = P(P(12, root_assets, ledger_end,
//    root_open, cnt_final), P(13, S_0, y)).
//  7 closing = 1 forces cnt_final = 0 and the empty open-position root.
//  The pins inside z0 and zn are recomputed from the public roots, so the
//  fold ran against the public snapshot.

// Root of the depth-4 ledger tree from the first NT leaves; the rest are the
// empty leaf. EL[k] = root of an all-empty subtree of height k.
template LedgerRoot(NT) {
    signal input leaves[NT];
    signal output root;
    var EL[5] = [
        5317387130258456662214331362918410991734007599705406860481038345552731150762,
        5301900180746108365834837840355741695167403565517259206503735319173783315742,
        19759440382600727929415049642887307143518671081639244670052489500787514850212,
        11575399251628151734428362828441614938772848828475906566857213866326592241179,
        6632555919090241659299800894218068745568431736196896666697681740099319754273
    ];
    var W = 16;
    signal lvl[5][16];
    component h[4][8];
    for (var j = 0; j < 16; j++) {
        if (j < NT) { lvl[0][j] <== leaves[j]; } else { lvl[0][j] <== EL[0]; }
    }
    // nodes whose subtree is entirely beyond slot NT-1 are constants
    for (var k = 0; k < 4; k++) {
        W = W \ 2;
        for (var j = 0; j < 16; j++) {
            if (j < W) {
                if ((j << (k + 1)) < NT) {
                    h[k][j] = Poseidon(2);
                    h[k][j].inputs[0] <== lvl[k][2 * j];
                    h[k][j].inputs[1] <== lvl[k][2 * j + 1];
                    lvl[k + 1][j] <== h[k][j].out;
                } else {
                    lvl[k + 1][j] <== EL[k + 1];
                }
            } else {
                lvl[k + 1][j] <== 0;
            }
        }
    }
    root <== lvl[4][0];
}

template Boundary(NT, D) {
    // empty roots of the depth-16 asset and open-position trees (leaf P(0,0))
    var EMPTY16 = 21035245323335827719745544373081896983162834604456827698288649288827293579666;

    // ---- public ----
    signal input z0;
    signal input zn;
    signal input tags[NT];
    signal input cid[2];
    signal input acaddr[2];
    signal input root_rcl[2];
    signal input root_unl[2];
    signal input root_at[2];
    signal input root_psl[2];
    signal input y;
    signal input d_proceeds;
    signal input d_cost;
    signal input d_income;
    signal input c_prev;
    signal input c_y;
    signal input closing;

    // ---- private ----
    signal input S[NT];
    signal input blind;
    // state committed in c_prev
    signal input ra0;             // asset tree root
    signal input ro0;             // open-position tree root
    signal input n_open0;         // number of open positions
    signal input m[NT][2];        // counters carried per (slot, chain)
    signal input is_new[NT];      // 1: the slot's previous leaf was empty
    // closing state
    signal input ra1;
    signal input ro1;
    signal input cf1;             // final open-set count
    signal input proceeds;
    signal input cost;
    signal input other;
    signal input khi;
    signal input klo;
    signal input n[NT][2];        // counters reached per (slot, chain)
    // tree witnesses
    signal input at_sib[NT][2][D];
    signal input unl_sib[NT][2][D];
    signal input unl_oldKey[NT][2];
    signal input unl_oldValue[NT][2];
    signal input unl_isOld0[NT][2];

    var i; var c;

    // chain ids enter the merge key as 64-bit limbs
    component cidr[2];
    for (c = 0; c < 2; c++) { cidr[c] = Num2Bits(64); cidr[c].in <== cid[c]; }
    // the period must be nonzero (mark 0 = "pledged, not yet settled")
    component yz = IsZero();
    yz.in <== y;
    yz.out === 0;
    closing * (closing - 1) === 0;

    // ---- pins ------------------------------------------------------------------
    component hpin = Poseidon(9);
    hpin.inputs[0] <== cid[0];
    hpin.inputs[1] <== cid[1];
    hpin.inputs[2] <== acaddr[0];
    hpin.inputs[3] <== acaddr[1];
    hpin.inputs[4] <== root_rcl[0];
    hpin.inputs[5] <== root_rcl[1];
    hpin.inputs[6] <== root_psl[0];
    hpin.inputs[7] <== root_psl[1];
    hpin.inputs[8] <== y;

    component first = IsZero();
    first.in <== c_prev;

    // ---- per tag slot --------------------------------------------------------
    component tz[NT];
    component hid[NT];
    component hix[NT];
    component han[NT];
    component lprev[NT];
    component lstart[NT];
    component lend[NT];
    component at[NT][2];
    component hnf[NT][2];
    component unl[NT][2];
    signal act[NT];
    signal keep[NT];
    for (i = 0; i < NT; i++) {
        tz[i] = IsZero();
        tz[i].in <== tags[i];
        act[i] <== 1 - tz[i].out;
        is_new[i] * (is_new[i] - 1) === 0;
        keep[i] <== act[i] * (1 - is_new[i]);
        // a first filing carries no ledger
        first.out * keep[i] === 0;

        hid[i] = Poseidon(3);
        hid[i].inputs[0] <== 1;
        hid[i].inputs[1] <== tags[i];
        hid[i].inputs[2] <== S[i];
        hix[i] = Poseidon(2);
        hix[i].inputs[0] <== 3;
        hix[i].inputs[1] <== tags[i];
        han[i] = Poseidon(2);
        han[i].inputs[0] <== 2;
        han[i].inputs[1] <== S[i];

        // ledger leaves: previous (in c_prev), start (in z0), end (in zn)
        lprev[i] = Poseidon(3);
        lprev[i].inputs[0] <== keep[i] * hid[i].out;
        lstart[i] = Poseidon(3);
        lstart[i].inputs[0] <== act[i] * hid[i].out;
        lend[i] = Poseidon(3);
        lend[i].inputs[0] <== act[i] * hid[i].out;
        for (c = 0; c < 2; c++) {
            // only a carried slot has nonzero start counters, only an
            // active slot has nonzero end counters
            (1 - keep[i]) * m[i][c] === 0;
            (1 - act[i]) * n[i][c] === 0;
            lprev[i].inputs[1 + c] <== m[i][c];
            lstart[i].inputs[1 + c] <== m[i][c];
            lend[i].inputs[1 + c] <== n[i][c];

            // (2) anchor under this chain's AT
            at[i][c] = SMTVerifierB(D);
            at[i][c].enabled <== act[i];
            at[i][c].fnc <== 0;
            at[i][c].root <== root_at[c];
            at[i][c].oldKey <== 0;
            at[i][c].oldValue <== 0;
            at[i][c].isOld0 <== 0;
            at[i][c].key <== hix[i].out;
            at[i][c].value <== han[i].out;
            for (var k = 0; k < D; k++) { at[i][c].siblings[k] <== at_sib[i][c][k]; }

            // (3) end of ledger: NF_{n+1} unused under this chain's UNL
            hnf[i][c] = Poseidon(5);
            hnf[i][c].inputs[0] <== 8;
            hnf[i][c].inputs[1] <== hid[i].out;
            hnf[i][c].inputs[2] <== cid[c];
            hnf[i][c].inputs[3] <== acaddr[c];
            hnf[i][c].inputs[4] <== n[i][c] + 1;
            unl[i][c] = SMTVerifierB(D);
            unl[i][c].enabled <== act[i];
            unl[i][c].fnc <== 1;
            unl[i][c].root <== root_unl[c];
            unl[i][c].oldKey <== unl_oldKey[i][c];
            unl[i][c].oldValue <== unl_oldValue[i][c];
            unl[i][c].isOld0 <== unl_isOld0[i][c];
            unl[i][c].key <== hnf[i][c].out;
            unl[i][c].value <== 0;
            for (var k = 0; k < D; k++) { unl[i][c].siblings[k] <== unl_sib[i][c][k]; }
        }
    }

    component rl_prev = LedgerRoot(NT);
    component rl_start = LedgerRoot(NT);
    component rl_end = LedgerRoot(NT);
    for (i = 0; i < NT; i++) {
        rl_prev.leaves[i] <== lprev[i].out;
        rl_start.leaves[i] <== lstart[i].out;
        rl_end.leaves[i] <== lend[i].out;
    }

    // ---- (1) start state --------------------------------------------------------
    component dprev = Poseidon(5);
    dprev.inputs[0] <== 12;
    dprev.inputs[1] <== ra0;
    dprev.inputs[2] <== rl_prev.root;
    dprev.inputs[3] <== ro0;
    dprev.inputs[4] <== n_open0;
    component bprev = Poseidon(3);
    bprev.inputs[0] <== 13;
    bprev.inputs[1] <== S[0];
    bprev.inputs[2] <== y - 1;
    component cprev = Poseidon(2);
    cprev.inputs[0] <== dprev.out;
    cprev.inputs[1] <== bprev.out;
    (1 - first.out) * (cprev.out - c_prev) === 0;
    first.out * (ra0 - EMPTY16) === 0;
    first.out * (ro0 - EMPTY16) === 0;
    first.out * n_open0 === 0;

    component h0 = Poseidon(12);
    h0.inputs[0] <== ra0;
    h0.inputs[1] <== rl_start.root;
    h0.inputs[2] <== ro0;
    h0.inputs[3] <== n_open0;
    for (i = 4; i < 10; i++) { h0.inputs[i] <== 0; }
    h0.inputs[10] <== hpin.out;
    h0.inputs[11] <== blind;
    h0.out === z0;

    // ---- (5) (6) end state ------------------------------------------------------
    component hn = Poseidon(12);
    hn.inputs[0] <== ra1;
    hn.inputs[1] <== rl_end.root;
    hn.inputs[2] <== ro1;
    hn.inputs[3] <== 0;             // working open set empty
    hn.inputs[4] <== cf1;
    hn.inputs[5] <== proceeds;
    hn.inputs[6] <== cost;
    hn.inputs[7] <== other;
    hn.inputs[8] <== khi;
    hn.inputs[9] <== klo;
    hn.inputs[10] <== hpin.out;
    hn.inputs[11] <== blind;
    hn.out === zn;

    d_proceeds === proceeds;
    d_cost === cost;
    d_income === proceeds - cost + other;

    component dcur = Poseidon(5);
    dcur.inputs[0] <== 12;
    dcur.inputs[1] <== ra1;
    dcur.inputs[2] <== rl_end.root;
    dcur.inputs[3] <== ro1;
    dcur.inputs[4] <== cf1;
    component bcur = Poseidon(3);
    bcur.inputs[0] <== 13;
    bcur.inputs[1] <== S[0];
    bcur.inputs[2] <== y;
    component ccur = Poseidon(2);
    ccur.inputs[0] <== dcur.out;
    ccur.inputs[1] <== bcur.out;
    ccur.out === c_y;

    // ---- (7) closing filing ------------------------------------------------------
    closing * cf1 === 0;
    closing * (ro1 - EMPTY16) === 0;
}
