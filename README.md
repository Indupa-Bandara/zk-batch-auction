# ZK Batch Auction Exchange

An educational prototype of a deterministic batch auction with a RISC Zero
guest verifier. It demonstrates matching, signed-order validation, account
nonce and balance transitions, and commitments to the result and account-state
roots.

> **Prototype, not production software.** The RISC Zero dev-mode pipeline has
> succeeded, but a real cryptographic proof has not been generated. The real
> prover was killed with exit code 137 on the current 4 GiB Ubuntu VM while
> running the sample batch. Do not rely on this project for custody, settlement,
> or production trading.

## What is implemented

- Deterministic clearing price selection with explicit tie-breaks.
- Price-priority allocation and pro-rata allocation at the marginal level.
- Ed25519 order signatures, canonical order hashes, batch checks, and expiry.
- Consecutive per-account nonce validation.
- Atomic net balance settlement and before/after account-state Merkle roots.
- A RISC Zero guest that verifies host-supplied sorted-order witnesses and
  claimed fills rather than rerunning the native matcher.
- Canonical, input-order-independent batch and fills commitments.

The auction rules and order/state encodings are specified in
[docs/spec.md](docs/spec.md). RISC Zero setup and validation details are in
[docs/zkvm.md](docs/zkvm.md).

## Validate

Run the matcher tests from the repository root:

```sh
cargo test --locked -p batch-auction-matching
```

With the RISC Zero 3.1.0 toolchain installed on x86-64 Ubuntu, run the guest
pipeline in dev mode:

```sh
RISC0_DEV_MODE=1 cargo run --locked -p batch-auction-host --release
```

Dev mode is for iteration; it is **not** a cryptographic proof. A real proof
attempt uses:

```sh
RISC0_DEV_MODE=0 cargo run --locked -p batch-auction-host --release
```

The sample dev-mode run was verified on Ubuntu 24.04 with the pinned RISC Zero
3.1.0 components. It reported clearing price `101` and volume `15`. The matcher
suite passed all 16 tests on both Windows and Ubuntu. The real proof attempt has
not completed: the VM ran out of memory.

## Known limitations

- No real proof has been generated or independently verified.
- The complete account list is supplied as the state witness and rehashed in
  the guest; this does not scale to a large exchange. Merkle membership
  multiproofs are future work.
- The batch timestamp is prover-supplied. A settlement system must validate it
  against a trusted clock.
- Settlement must compare the old account root with current state before
  applying the new root.
- This prototype has no token custody, deposits/withdrawals, production API, or
  production key management.
- The user-selected net-settlement model checks per-account net balances; it
  does not reserve order collateral before matching.

Treat all outputs as experimental until real-proof generation, independent
receipt verification, resource requirements, and settlement integration have
been validated.
