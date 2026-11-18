# RISC Zero Guest

The first proof pipeline uses `risc0-zkvm` 3.1.0 and `risc0-build` 3.0.7. The
RISC Zero 3.1.0 release pins `risc0-build` to 3.0.7. The host and guest share
the `batch-auction-matching` crate. The host supplies price-sorted and
hash-sorted order-index permutations and a claimed result; the guest validates
Ed25519 signatures, order hashes, batch eligibility and expiry, then checks
both permutations, the sorted order, optimal price, tie-breaks, and
price-priority allocation without calling the native matcher. It also checks
account nonce sequences and net balances against the complete account-state
witness and commits the before/after account roots. It commits the batch ID and
timestamp, SHA-256 batch commitment, previous and new clearing prices, volume,
and fills commitment.
Orders and `(order hash, fill)` pairs are encoded in hash-sorted order, so the
commitments do not depend on the input vector order.

The timestamp is supplied by the prover; an integrating settlement layer must
check it against a trusted clock and apply the new account root only if the
previous root is still current. The complete account-state witness is private
but does not scale to a large account set; Merkle membership paths are future
work.

The guest scans price levels to verify the clearing price and uses pairwise
remainder ranking at the marginal allocation level, avoiding guest-side sorts.
The guest build and proof have not been run because the Windows environment has
no RISC Zero toolchain; validate them from the repository clone in the Ubuntu
VM before relying on the proof.

## Linux toolchain

Install the RISC Zero 3.1.0 components in the x86-64 Ubuntu VM using the
[official installation guide](https://dev.risczero.com/api/zkvm/install). Pin
the Rust toolchain, `r0vm`, and `cargo-risczero` versions as shown in that
guide. Then, from the repository root, run:

```sh
cargo test -p batch-auction-matching
RISC0_DEV_MODE=1 cargo run -p batch-auction-host --release
```

Dev mode skips real proof generation and is intended for fast iterations. For
the end-to-end real proof, run:

```sh
RISC0_DEV_MODE=0 cargo run -p batch-auction-host --release
```

The host command runs the guest, generates a receipt, verifies it against the
embedded guest ID, and checks the public values against the input.
