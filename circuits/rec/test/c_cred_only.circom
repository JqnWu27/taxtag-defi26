pragma circom 2.0.0;
include "../taxtag_rec_common.circom";
// Check 1 of the recording statement alone (the credential check), wired as
// in CRec: the hidden selection of one recognized TA key, the message hash
// M = P(9, tag), and the EdDSA signature verification. Compiled only to
// count its constraints (REPRODUCE.md, step 1).
template CredOnly(NKEYS) {
    signal input pubx[NKEYS];
    signal input puby[NKEYS];
    signal input key_index;
    signal input keyset_digest;
    signal input tag;
    signal input R8x;
    signal input R8y;
    signal input Sig;

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
}
component main {public [keyset_digest]} = CredOnly(16);
