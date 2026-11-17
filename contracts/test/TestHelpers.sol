// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Measurement helpers. NOT part of the protocol.

// Always-true stand-in for the Groth16 verifier. Used ONLY by the gas sweep
// (harness/gas_sweep.js) to fill the nullifier log of a separate agency
// contract instance without producing hundreds of proofs; the measured
// functions (insertNullifiers, recordPassive, pinSnapshot) never call the
// verifier, so their gas is unaffected.
contract StubVerifier {
    function verifyProof(uint256[2] calldata, uint256[2][2] calldata,
        uint256[2] calldata, uint256[8] calldata) external pure returns (bool)
    { return true; }
}

interface IVerifier8 {
    function verifyProof(uint256[2] calldata a, uint256[2][2] calldata b,
        uint256[2] calldata c, uint256[8] calldata input) external view returns (bool);
}

// Measures gas consumed by calls made from inside another contract, as the
// agency contract makes them (no 21,000 transaction base and no transaction
// calldata charge in the figure).
contract GasProbe {
    // the Groth16 verifier call of record(): first (cold) call to the verifier
    function verifyGas(address verifier, uint256[2] calldata a,
        uint256[2][2] calldata b, uint256[2] calldata c,
        uint256[8] calldata input) external view returns (bool ok, uint256 gasUsed)
    {
        uint256 g0 = gasleft();
        ok = IVerifier8(verifier).verifyProof(a, b, c, input);
        gasUsed = g0 - gasleft();
    }

    // any static call, made twice: the first touches the target cold
    // (2,600 gas account access), the second warm (100 gas)
    function callGas2(address target, bytes calldata data)
        external view returns (bool ok, uint256 cold, uint256 warm)
    {
        uint256 g0 = gasleft();
        (ok, ) = target.staticcall(data);
        cold = g0 - gasleft();
        g0 = gasleft();
        (ok, ) = target.staticcall(data);
        warm = g0 - gasleft();
    }
}
