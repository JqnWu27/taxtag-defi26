pragma circom 2.0.0;
include "taxtag_rec_common.circom";

// Constraint-count variant: SMT depth 16, RCL depth 32, 16 keys.
component main {public [nf, root_rcl, root_at, root_trl,
                        keyset_digest, cid, acaddr, owner]} = CRec(16, 32, 16);
