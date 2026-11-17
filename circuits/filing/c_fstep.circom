pragma circom 2.0.0;
include "filing_common.circom";

// TaxTag filing step circuit (SPEC.md sections 5, 6, 7), folded with
// Nova + CycleFold. The IVC state is ONE Poseidon digest (state length 1, the
// shape sonobe's decider needs); the state vector travels in external_inputs
// and is opened against the digest. Compile with --O0 (REPRODUCE.md).
//
// ---- state vector s[12], ivc = Poseidon(s[0..11]) -------------------------
//  0 root_assets   asset tree, depth DA = 16, index = asset id,
//                  leaf P(q, avg), every leaf starts as P(0, 0)
//  1 root_ledger   ledger tree over the demanded tags, depth DL = 4,
//                  leaf P(id_tax, n_chain0, n_chain1), empty slot P(0, 0, 0)
//  2 root_open     open-position tree, depth DA = 16, any free slot,
//                  leaf P(P(cid, position_id), mark), empty slot P(0, 0).
//                  mark = y  : shown still open at this filing's boundary
//                              (the FINAL open set)
//                  mark != y : not yet settled in this filing (the WORKING
//                              open set; a new pledge enters with mark 0, a
//                              carried position holds the earlier period)
//  3 cnt_work      number of leaves of the working set
//  4 cnt_final     number of leaves of the final set
//  5 proceeds      total proceeds of disposals
//  6 cost          total cost of disposals
//  7 other_income  rewards plus withdrawal interest
//  8 key_hi        last merge key, time * 2^64 + cid
//  9 key_lo        last merge key, block * 2^64 + idx
// 10 pins          Poseidon(p[0..8]) of the constants below
// 11 blind         blinding of the state digest, constant over the fold
//
// ---- pins p[9] -------------------------------------------------------------
//  cid0, cid1, acaddr0, acaddr1, rootRCL0(B), rootRCL1(B), rootPSL0(B),
//  rootPSL1(B), y (the period, nonzero)
//
// ---- external_inputs (EIL = 117 for DR = DP = 32, DA = 16, DL = 4) ---------
//   0.. 11  s[12]            previous state vector
//  12.. 20  p[9]             pins
//  21       kind             0 padding, 1 record, 2 PSL entry, 3 still open
//  22       ch               chain slot, 0 or 1
//  23       op               record: 1 swap 2 pledge 3 borrow 4 repay 5 claim
//                            PSL entry: 1 liquidation 2 withdrawal
//  24, 25   a1, m1           record: asset_in, amount_in
//                            PSL entry: asset_a, amount_a (collateral)
//  26, 27   a2, m2           record: asset_out, amount_out
//                            PSL entry: asset_b, amount_b (debt / interest)
//  28       value
//  29       position_id
//  30, 31, 32  block, idx, time
//  33       slot             ledger-tree slot of the tag (record step)
//  34, 35, 36  id_tax, n0, n1   ledger leaf before the step
//  37.. 40  lsib[DL]         ledger path, bottom-up
//  41       path_key         record: bit-reversed RCL leaf index
//                            PSL entry / still open: position_id
//  42.. 73  psib[DP]         record: RCL siblings TOP-DOWN (psib[j] is the
//                            sibling at height DR-1-j); otherwise the PSL
//                            SMT siblings, zero padded
//  74, 75, 76  old_key, old_value, is_old0   PSL exclusion (still open)
//  77       idx1             asset slot: leaf index (= a1 or a2)
//  78, 79   q1, avg1         asset slot: leaf before the step
//  80.. 95  sib1[DA]
//  96       idx2             flex slot: asset id a2 (swap) or open-tree slot
//  97, 98   x2, y2           flex slot: leaf before the step, (q, avg) or
//                            (key, mark)
//  99..114  sib2[DA]
// 115, 116  avg_hint, rem    quotient and remainder of the buy division
//
// ---- what a step does -------------------------------------------------------
// record (kind 1): next counter i = n_ch + 1 of ledger slot `slot`,
//   NF = P(8, id_tax, cid, acaddr, i), leaf = P(P(7, NF, cid, block, idx),
//   P(op, a1, m1, a2, m2), P(10, value, position_id, time, 0)) opened under
//   the pinned rootRCL of chain ch, merge key strictly larger than the last
//   one, rule applied, a pledge inserts its position into the working set.
// PSL entry (kind 2): pentry = P(P(11, op, cid, block, idx),
//   P(a1, m1, a2, m2, value), time) is the value at key position_id under the
//   pinned rootPSL of chain ch, the position is a working-set leaf and is
//   removed, merged by its own key, rule applied.
// still open (kind 3): position_id is absent under the pinned rootPSL of
//   chain ch, the working-set leaf is re-marked y (moved to the final set).
// padding (kind 0): the state is re-committed unchanged.
//
// ---- rule program (moving average, SPEC section 6) -------------------------
// All quantities are integers. avg is the integer average cost per unit,
// floor((q*avg + value) / (q + m)) after a buy of m units for value; the
// prover supplies quotient and remainder, the circuit checks
// avg_hint * (q + m) + rem = q*avg + value with 0 <= rem < q + m.
// dispose(m): d = min(q, m), q -= d, cost += d * avg (units beyond the
// recorded quantity cost 0), avg unchanged. A buy of m = 0 units is skipped.
//   swap        dispose(a1, m1), buy(a2, m2, value), proceeds += value
//   pledge      buy(a2, m2, value) if a loan is attached, position inserted
//   borrow      buy(a2, m2, value)
//   repay       remove min(q, m1) units of a1, no totals
//   claim       buy(a2, m2, value), other_income += value
//   liquidation dispose(a1, m1), proceeds += value
//   withdrawal  buy(a2, m2, value), other_income += value
// Ranges enforced here: m1, m2, value, block, idx, time < 2^64;
// avg < 2^64; q < 2^97 (buy keeps q + m - 1 - rem and rem below 2^96).

template FStep(DR, DP, DA, DL) {
    var NS = 12;
    var NP = 9;
    var O_P = NS;                 // pins
    var O_E = O_P + NP;           // event fields
    var O_L = O_E + 12;           // ledger opening
    var O_T = O_L + 4 + DL;       // dual path
    var O_1 = O_T + 1 + DP + 3;   // asset slot
    var O_2 = O_1 + 3 + DA;       // flex slot
    var O_H = O_2 + 3 + DA;       // hints
    var EIL = O_H + 2;

    signal input ivc_input[1];
    signal input external_inputs[EIL];
    signal output ivc_output[1];

    var i;

    // ---- open the previous state and the pins ------------------------------
    component hin = Poseidon(NS);
    for (i = 0; i < NS; i++) { hin.inputs[i] <== external_inputs[i]; }
    hin.out === ivc_input[0];

    component hpin = Poseidon(NP);
    for (i = 0; i < NP; i++) { hpin.inputs[i] <== external_inputs[O_P + i]; }
    hpin.out === external_inputs[10];

    signal root_assets <== external_inputs[0];
    signal root_ledger <== external_inputs[1];
    signal root_open <== external_inputs[2];
    signal y <== external_inputs[O_P + 8];

    signal kind <== external_inputs[O_E];
    signal ch <== external_inputs[O_E + 1];
    signal op <== external_inputs[O_E + 2];
    signal a1 <== external_inputs[O_E + 3];
    signal m1 <== external_inputs[O_E + 4];
    signal a2 <== external_inputs[O_E + 5];
    signal m2 <== external_inputs[O_E + 6];
    signal value <== external_inputs[O_E + 7];
    signal position_id <== external_inputs[O_E + 8];
    signal block <== external_inputs[O_E + 9];
    signal idx <== external_inputs[O_E + 10];
    signal time <== external_inputs[O_E + 11];

    // ---- step kind and operation flags -------------------------------------
    component kq[4];
    for (i = 0; i < 4; i++) {
        kq[i] = IsEqual();
        kq[i].in[0] <== kind;
        kq[i].in[1] <== i;
    }
    kq[0].out + kq[1].out + kq[2].out + kq[3].out === 1;
    signal is_rec <== kq[1].out;
    signal is_psl <== kq[2].out;
    signal is_open <== kq[3].out;
    signal smt_en <== is_psl + is_open;
    signal keyed <== is_rec + is_psl;

    ch * (ch - 1) === 0;

    component oq[5];
    for (i = 0; i < 5; i++) {
        oq[i] = IsEqual();
        oq[i].in[0] <== op;
        oq[i].in[1] <== i + 1;
    }
    is_rec * (1 - oq[0].out - oq[1].out - oq[2].out - oq[3].out - oq[4].out) === 0;
    is_psl * (1 - oq[0].out - oq[1].out) === 0;
    signal r_swap <== is_rec * oq[0].out;
    signal r_pledge <== is_rec * oq[1].out;
    signal r_borrow <== is_rec * oq[2].out;
    signal r_repay <== is_rec * oq[3].out;
    signal r_claim <== is_rec * oq[4].out;
    signal p_liq <== is_psl * oq[0].out;
    signal p_wd <== is_psl * oq[1].out;

    // ---- chain selection ------------------------------------------------------
    signal cid <== external_inputs[O_P] + ch * (external_inputs[O_P + 1] - external_inputs[O_P]);
    signal acaddr <== external_inputs[O_P + 2] + ch * (external_inputs[O_P + 3] - external_inputs[O_P + 2]);
    signal rcl_root <== external_inputs[O_P + 4] + ch * (external_inputs[O_P + 5] - external_inputs[O_P + 4]);
    signal psl_root <== external_inputs[O_P + 6] + ch * (external_inputs[O_P + 7] - external_inputs[O_P + 6]);

    // ---- ranges -----------------------------------------------------------------
    component rg[6];
    for (i = 0; i < 6; i++) { rg[i] = Num2Bits(64); }
    rg[0].in <== m1;
    rg[1].in <== m2;
    rg[2].in <== value;
    rg[3].in <== block;
    rg[4].in <== idx;
    rg[5].in <== time;

    // ---- ledger tree: next counter of one (tag, chain), record steps only ----
    signal id_tax <== external_inputs[O_L + 1];
    signal n0 <== external_inputs[O_L + 2];
    signal n1 <== external_inputs[O_L + 3];
    component lold = Poseidon(3);
    lold.inputs[0] <== id_tax;
    lold.inputs[1] <== n0;
    lold.inputs[2] <== n1;
    signal inc1 <== is_rec * ch;
    component lnew = Poseidon(3);
    lnew.inputs[0] <== id_tax;
    lnew.inputs[1] <== n0 + is_rec - inc1;
    lnew.inputs[2] <== n1 + inc1;
    component ltree = TreeUpdate(DL);
    ltree.en <== is_rec;
    ltree.root_in <== root_ledger;
    ltree.idx <== external_inputs[O_L];
    for (i = 0; i < DL; i++) { ltree.siblings[i] <== external_inputs[O_L + 4 + i]; }
    ltree.old_leaf <== lold.out;
    ltree.new_leaf <== lnew.out;

    signal counter <== n0 + ch * (n1 - n0) + 1;
    component hnf = Poseidon(5);
    hnf.inputs[0] <== 8;
    hnf.inputs[1] <== id_tax;
    hnf.inputs[2] <== cid;
    hnf.inputs[3] <== acaddr;
    hnf.inputs[4] <== counter;

    // ---- record leaf / PSL entry, one set of hashers -----------------------
    component hmeta = Poseidon(5);
    hmeta.inputs[0] <== 7 + 4 * is_psl;
    hmeta.inputs[1] <== hnf.out + is_psl * (op - hnf.out);
    hmeta.inputs[2] <== cid;
    hmeta.inputs[3] <== block;
    hmeta.inputs[4] <== idx;
    component hbody = Poseidon(5);
    hbody.inputs[0] <== op + is_psl * (a1 - op);
    hbody.inputs[1] <== a1 + is_psl * (m1 - a1);
    hbody.inputs[2] <== m1 + is_psl * (a2 - m1);
    hbody.inputs[3] <== a2 + is_psl * (m2 - a2);
    hbody.inputs[4] <== m2 + is_psl * (value - m2);
    component htail = Poseidon(5);
    htail.inputs[0] <== 10;
    htail.inputs[1] <== value;
    htail.inputs[2] <== position_id;
    htail.inputs[3] <== time;
    htail.inputs[4] <== 0;
    component hleaf = Poseidon(3);
    hleaf.inputs[0] <== hmeta.out;
    hleaf.inputs[1] <== hbody.out;
    hleaf.inputs[2] <== htail.out + is_psl * (time - htail.out);

    // ---- RCL inclusion / PSL inclusion / PSL exclusion ------------------------
    signal path_key <== external_inputs[O_T];
    smt_en * (path_key - position_id) === 0;
    component dp = DualPath(DP, DR);
    dp.smt_en <== smt_en;
    dp.rcl_en <== is_rec;
    dp.fnc <== is_open;
    dp.root <== psl_root + is_rec * (rcl_root - psl_root);
    for (i = 0; i < DP; i++) { dp.siblings[i] <== external_inputs[O_T + 1 + i]; }
    dp.oldKey <== external_inputs[O_T + 1 + DP];
    dp.oldValue <== external_inputs[O_T + 2 + DP];
    dp.isOld0 <== external_inputs[O_T + 3 + DP];
    dp.key <== path_key;
    dp.leaf <== hleaf.out;

    // ---- merge key (time, cid, block, idx), strictly increasing ------------
    signal key_hi <== time * 18446744073709551616 + cid;
    signal key_lo <== block * 18446744073709551616 + idx;
    component gt_hi = LessThan(128);
    gt_hi.in[0] <== external_inputs[8];
    gt_hi.in[1] <== key_hi;
    component eq_hi = IsEqual();
    eq_hi.in[0] <== external_inputs[8];
    eq_hi.in[1] <== key_hi;
    component gt_lo = LessThan(128);
    gt_lo.in[0] <== external_inputs[9];
    gt_lo.in[1] <== key_lo;
    signal tie <== eq_hi.out * gt_lo.out;
    keyed * (1 - gt_hi.out - tie) === 0;
    signal key_hi_new <== external_inputs[8] + keyed * (key_hi - external_inputs[8]);
    signal key_lo_new <== external_inputs[9] + keyed * (key_lo - external_inputs[9]);

    // ---- rule flags ---------------------------------------------------------------
    component m2z = IsZero();
    m2z.in <== m2;
    signal buy_kind <== r_swap + r_pledge + r_borrow + r_claim + p_wd;
    signal buy_en <== buy_kind * (1 - m2z.out);
    signal s2_buy <== r_swap * (1 - m2z.out);
    signal s1_buy <== buy_en - s2_buy;
    signal s1_dis <== r_swap + r_repay + p_liq;
    signal with_tot <== r_swap + p_liq;
    signal s2_open <== r_pledge + is_psl + is_open;

    // ---- asset slot: one leaf of the asset tree ---------------------------
    signal idx1 <== external_inputs[O_1];
    signal q1 <== external_inputs[O_1 + 1];
    signal avg1 <== external_inputs[O_1 + 2];
    s1_dis * (idx1 - a1) === 0;
    s1_buy * (idx1 - a2) === 0;

    // flex slot leaf before the step: (q, avg) of a2 for a swap, else an
    // open-position leaf (key, mark)
    signal idx2 <== external_inputs[O_2];
    signal x2 <== external_inputs[O_2 + 1];
    signal y2 <== external_inputs[O_2 + 2];
    s2_buy * (idx2 - a2) === 0;

    // dispose: d = min(q1, m1)
    component ltq = LessThan(97);
    ltq.in[0] <== q1;
    ltq.in[1] <== m1;
    signal d <== m1 + ltq.out * (q1 - m1);
    signal cost_part <== d * avg1;
    signal cost_add <== with_tot * cost_part;

    // buy on (qb, avgb): the swap buys in the flex slot, everything else in
    // the asset slot
    signal qb <== q1 + s2_buy * (x2 - q1);
    signal avgb <== avg1 + s2_buy * (y2 - avg1);
    signal avg_hint <== external_inputs[O_H];
    signal rem <== external_inputs[O_H + 1];
    signal qpe <== qb + m2;
    signal t1 <== avg_hint * qpe;
    signal t2 <== qb * avgb;
    buy_en * (t1 + rem - t2 - value) === 0;
    component rg_avg = Num2Bits(64);
    rg_avg.in <== avg_hint;
    component rg_rem = Num2Bits(96);
    rg_rem.in <== rem;
    component rg_gap = Num2Bits(96);
    rg_gap.in <== buy_en * (qpe - 1 - rem);

    component h1old = Poseidon(2);
    h1old.inputs[0] <== q1;
    h1old.inputs[1] <== avg1;
    component h1new = Poseidon(2);
    h1new.inputs[0] <== q1 - d + s1_buy * (qpe - q1 + d);
    h1new.inputs[1] <== avg1 + s1_buy * (avg_hint - avg1);
    component t1u = TreeUpdate(DA);
    t1u.en <== s1_dis + s1_buy;
    t1u.root_in <== root_assets;
    t1u.idx <== idx1;
    for (i = 0; i < DA; i++) { t1u.siblings[i] <== external_inputs[O_1 + 3 + i]; }
    t1u.old_leaf <== h1old.out;
    t1u.new_leaf <== h1new.out;

    // ---- flex slot: second asset leaf (swap) or the open-position tree -----
    component hokey = Poseidon(2);
    hokey.inputs[0] <== cid;
    hokey.inputs[1] <== position_id;
    // pledge: the slot must be empty
    r_pledge * x2 === 0;
    r_pledge * y2 === 0;
    // PSL entry / still open: the slot holds this position, not yet settled
    smt_en * (x2 - hokey.out) === 0;
    component mk = IsEqual();
    mk.in[0] <== y2;
    mk.in[1] <== y;
    smt_en * mk.out === 0;

    signal nx_a <== s2_buy * qpe;
    signal nx_b <== (r_pledge + is_open) * hokey.out;
    signal ny_a <== s2_buy * avg_hint;
    signal ny_b <== is_open * y;
    component h2old = Poseidon(2);
    h2old.inputs[0] <== x2;
    h2old.inputs[1] <== y2;
    component h2new = Poseidon(2);
    h2new.inputs[0] <== nx_a + nx_b;
    h2new.inputs[1] <== ny_a + ny_b;
    component t2u = TreeUpdate(DA);
    t2u.en <== s2_buy + s2_open;
    t2u.root_in <== t1u.root_out + s2_open * (root_open - t1u.root_out);
    t2u.idx <== idx2;
    for (i = 0; i < DA; i++) { t2u.siblings[i] <== external_inputs[O_2 + 3 + i]; }
    t2u.old_leaf <== h2old.out;
    t2u.new_leaf <== h2new.out;

    signal root_assets_new <== t1u.root_out + s2_buy * (t2u.root_out - t1u.root_out);
    signal root_open_new <== root_open + s2_open * (t2u.root_out - root_open);

    // ---- totals --------------------------------------------------------------------
    signal proceeds_add <== with_tot * value;
    signal other_add <== (r_claim + p_wd) * value;

    // ---- new state ----------------------------------------------------------------
    component hout = Poseidon(NS);
    hout.inputs[0] <== root_assets_new;
    hout.inputs[1] <== ltree.root_out;
    hout.inputs[2] <== root_open_new;
    hout.inputs[3] <== external_inputs[3] + r_pledge - is_psl - is_open;
    hout.inputs[4] <== external_inputs[4] + is_open;
    hout.inputs[5] <== external_inputs[5] + proceeds_add;
    hout.inputs[6] <== external_inputs[6] + cost_add;
    hout.inputs[7] <== external_inputs[7] + other_add;
    hout.inputs[8] <== key_hi_new;
    hout.inputs[9] <== key_lo_new;
    hout.inputs[10] <== external_inputs[10];
    hout.inputs[11] <== external_inputs[11];
    ivc_output[0] <== hout.out;
}

component main {public [ivc_input]} = FStep(32, 32, 16, 4);
