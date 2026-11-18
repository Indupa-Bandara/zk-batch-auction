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
The batch commitment hashes the `batch-auction-exchange/order-batch/v1`
domain and zero byte, the order count as a big-endian `u64`, then each order
in hash-sorted order. An order encodes its account key, side byte, limit price,
quantity, nonce, batch ID, expiry, order hash, signature length as a big-endian
`u64`, and signature bytes. The fills commitment hashes the
`batch-auction-exchange/fills/v1` domain and zero byte, the fill count as a
big-endian `u64`, then `(order hash, fill)` pairs in the same canonical order;
each fill is a big-endian `u64`. These encodings are independent of input vector
order and usable by the `no_std` guest.

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
