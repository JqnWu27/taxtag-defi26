pragma circom 2.0.0;
include "smt/smtverifier.circom";
// circomlib's SMTVerifier as is, every input a private witness the way a
// caller wires an exclusion proof when it passes isOld0 straight
// through. Used by filing/test_smt_isold0.js.
component main = SMTVerifier(32);
