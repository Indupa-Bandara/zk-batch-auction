# RISC Zero Guest

The first proof pipeline uses `risc0-zkvm` 3.1.0 and `risc0-build` 3.0.7. The
RISC Zero 3.1.0 release pins `risc0-build` to 3.0.7. The host and guest share the
`batch-auction-matching` crate. The guest recomputes the reference matcher,
rejects a host result that differs, and commits the batch ID, SHA-256 batch
commitment, clearing price, volume, and fills commitment.

This is a correctness-first scaffold, not yet the optimized verify-only guest
described in the project design. The guest build and proof have not been run
because the Windows environment has no RISC Zero toolchain; validate them from
the repository clone in the Ubuntu VM before relying on the proof.

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
