pragma circom 2.0.0;
include "poseidon.circom";
// The hash of the pinned values of the step circuit alone, a Poseidon over
// the 9 pins (hpin in c_fstep). Compiled only to count its constraints
// (REPRODUCE.md, step 4).
template PinsOpen() {
    signal input p[9];
    signal input d;
    component h = Poseidon(9);
    for (var i = 0; i < 9; i++) { h.inputs[i] <== p[i]; }
    h.out === d;
}
component main {public [d]} = PinsOpen();
