pragma circom 2.0.0;
include "taxtag_rec_common.circom";

// TaxTag recording circuit, the shipped configuration:
// SMT depth 64 (AT, TRL), RCL depth 32, 16 recognized TA keys.
// Public inputs in the order SPEC.md section 4 fixes (circom orders
// public signals by declaration order in the template, which matches).
component main {public [nf, root_rcl, root_at, root_trl,
                        keyset_digest, cid, acaddr, owner]} = CRec(64, 32, 16);
