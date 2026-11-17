pragma circom 2.0.0;
include "c_boundary_core.circom";

// Boundary circuit for the full depth-4 ledger tree: 16 tag slots, 2 chains,
// SMT depth 64 (1,155,334 constraints with --O2). Its Groth16 setup needs a
// 2^21 powers-of-tau file; see filing/bench_boundary16.sh.
component main {public [z0, zn, tags, cid, acaddr, root_rcl, root_unl, root_at,
                        root_psl, y, d_proceeds, d_cost, d_income, c_prev, c_y,
                        closing]} = Boundary(16, 64);
