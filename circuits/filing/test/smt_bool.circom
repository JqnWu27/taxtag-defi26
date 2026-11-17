pragma circom 2.0.0;
include "../filing_common.circom";
// The same verifier with isOld0 forced boolean (SMTVerifierB), the form the
// filing circuits use. Used by filing/test_smt_isold0.js.
component main = SMTVerifierB(32);
