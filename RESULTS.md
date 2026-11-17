# TaxTag prototype results

Measured on 11 November 2026 on the reference machine, a Windows 11 laptop
with an 8-core AMD Ryzen AI 7 H 350 and 32 GB of memory. Stack: circom
2.2.3, snarkjs 0.7.6 (JavaScript prover), Node 24.14, solc 0.8.36 (viaIR,
optimizer 200 runs), ganache 7.9.2 in process, rustc 1.94.0, Nova and
CycleFold from sonobe at revision 9414c45 with one added constraint,
Groth16 and Poseidon over BN254.

This file lists the numbers behind Section 5 of the paper. Constraint
counts, gas, proof sizes and verdicts are exact. Times are single runs or
small ranges on a quiet machine, one heavy job at a time.

## 1. Circuit sizes (non-linear R1CS constraints)

| Circuit | D = 16 | D = 64 | D = 128 |
|---|---|---|---|
| recording | 30,233 | 54,425 | 86,681 |
| filing step, folded (RLL depth 32) | 32,604 | 32,604 | 32,604 |
| boundary, two tags | 53,465 | 148,697 | 275,673 |
| boundary, sixteen tags | | 1,155,334 | |
| compressing | 8,709,770 | 8,709,770 | 8,709,770 |

D is the depth of the sparse Merkle trees. One level costs about 252
constraints per authenticated path. The circuit folded at every step, the
step circuit with the verifier of the previous fold, has 158,983
constraints.

The credential check alone has 9,153 constraints, 16.8% of the recording
circuit at D = 64. In the step circuit the two hashes that open and
re-commit the state have 1,014 constraints and the hash of the pinned
values 420, together 4.4% of the circuit.

## 2. Gas (agency contract, in-process EVM)

| Caller | Function | Gas |
|---|---|---|
| TA | `writeAnchor` | 142,890 into an empty tree, up to 778,908 over 65 writes |
| TA | `revokeTag` | 97,745 into an empty tree, up to 763,146 over 64 writes |
| entry contract | `record` | 1,759,796 to 1,799,689 |
| | of which proof verification | 237,876 |
| venue | `recordPassive` | 365,551 into an empty tree, up to 973,264 with 128 entries |
| anyone | `insertNullifiers`, per nullifier | 122,969 into an empty tree, 684,000 to 747,000 once the tree holds more than 512 nullifiers |
| anyone | `pinSnapshot` | 109,179 to 129,079 |

Of a 1,760,000-gas `record` call, 54% is the append to the record tree
(32 on-chain Poseidon calls), 19% the four hashes of the leaf, 13.5% the
proof verification and 13.5% storage, the asset table and the transaction
base cost.

## 3. Proving costs

| Proof | When | Time | Peak memory | Proof size |
|---|---|---|---|---|
| recording, D = 64 | before each record | 1.85 to 1.96 s, up to 2.5 s for the first proof after a start | 1.82 to 1.90 GB | 256 bytes of calldata |
| filing step, folded | per record, at filing | 0.93 to 1.00 s | 0.8 GB | stays with the prover |
| compressing proof | once per filing | 71 to 79 s | 13.5 GB | 5,062,888 bytes |
| boundary proof, two tags | once per filing | 3.68 to 3.99 s, 4.2 s for the first proof after a start | 2.15 to 2.32 GB | 256 bytes |
| boundary proof, sixteen tags | once per filing | 22.1 to 25.0 s | 11.0 GB | 256 bytes |

- Memory is the peak working set of the prover. The recording and boundary
  proofs use the snarkjs JavaScript prover. The fold and the compressing
  proof are Rust, and their committed memory peaks higher, at 0.9 GB and
  14.4 GB.
- The times are ranges over two independent runs of the whole artifact on
  the reference machine: the measurement run, and a second run from a
  fresh copy of this repository. Both were made on a quiet machine.
- Fold over 1,024 steps (1,000 records): 996 s in two runs and 1,027 s in
  a third, a mean of 0.97 to 1.00 s per step. Over 64 steps the mean was
  0.93 to 1.03 s. The cost per step does not grow with the number of
  steps. With other programs active and little free memory the same fold
  took 1,188 s and 1,243 s, about 1.2 s per step, and the boundary proof
  4.3 to 4.5 s.
- These fold figures use the witness generator compiled once. With the
  folding library's own frontend a step takes 1.22 to 1.31 s.
- The compressing proof takes the same time and has the same size for 64
  and for 1,024 steps. Loading its proving key takes 6 to 7 s before that.

## 4. Verification by the authority

| Check | Time |
|---|---|
| compressing proof | about 0.4 s (379 to 435 ms) |
| boundary proof | 2 to 3 ms |
| whole command, including loading its material | about 2 s, 0.6 GB |

The folded proof itself, before compression, verifies in 69 to 78 ms on
the prover's side.

## 5. Setup

| Circuit | Time | Peak memory | Proving key |
|---|---|---|---|
| recording, D = 64 | about 10 s | | 46 MB |
| boundary, two tags | 40 to 41 s | 1.6 to 1.8 GB | 95 MB |
| boundary, sixteen tags | 323 to 334 s | 8.0 GB | 733 MB |
| compressing | 243 to 298 s | 14.6 GB committed, 13.8 GB working set | 3.85 GB, plus 12.6 GB of scratch files |

The verification key of the compressing proof is 1,128 bytes. Prover and
authority also hold a commitment key of 8.4 MB. All keys are generated
locally without a ceremony.

## 6. Validation

| Run | Result |
|---|---|
| worked example of Section 4, recording side | 19 of 19 checks |
| liquidation, withdrawal, concurrency, two chains, repay under another tag | all checks pass |
| recording negative cases | 67 of 67 behave as required |
| worked example, filing with real fold and both proofs | `D = (9600, 9000, 600)`, accepted |
| the same with a liquidation | `D = (11600, 12000, -400)` |
| the same with a withdrawal with interest | `D = (9600, 9000, 650)` |
| two tags on two chains | accepted |
| sixteen tags | accepted |
| 1,000 records | accepted |
| filing negative cases | 20 of 20 rejected |
| compressing proof, rejection and freshness tests | 18 of 18 |
| filings the authority command must reject | 4 of 4 rejected |

## 7. Limits

- The rule program takes no input besides the records.
- The average cost is stored as a whole number, so it rounds.
- The demo venues are mocks.
- Times are single runs or small ranges, without repetition statistics.
- The tree occupancy was measured up to 1,023 nullifiers, 128 position
  entries, 65 anchors and 64 revocations.
- The compressing proof reveals a blinded witness vector, which is why it
  measures 5 MB. Its size does not depend on the number of records. Its
  soundness rests on the assumptions stated in
  `folding-runner/ZK-DECIDER.md` and `folding-runner/G5-ANALYSIS.md`.
- The authority command checks the two proofs, the step count and the two
  state digests. It does not compare the remaining public values of the
  boundary proof with the authority's own records.
