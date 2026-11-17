pragma circom 2.0.0;
include "poseidon.circom";
// The state commitment of the step circuit alone: the hash that opens the
// previous state and the hash that commits the new one, each a Poseidon
// over the 12 state values (hin and hout in c_fstep). Compiled only to
// count its constraints (REPRODUCE.md, step 4).
template StateOpen() {
    signal input a[12];
    signal input b[12];
    signal input zin;
    signal output zout;
    component hin = Poseidon(12);
    component hout = Poseidon(12);
    for (var i = 0; i < 12; i++) { hin.inputs[i] <== a[i]; hout.inputs[i] <== b[i]; }
    hin.out === zin;
    zout <== hout.out;
}
component main {public [zin]} = StateOpen();
