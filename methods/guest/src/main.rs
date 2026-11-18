#![no_main]

use batch_auction_matching::{clear_auction, AuctionInput, AuctionPublicValues};
use risc0_zkvm::{
    guest::env,
    sha::{Impl, Sha256},
};

risc0_zkvm::guest::entry!(main);

fn main() {
    let input: AuctionInput = env::read();
    let result = clear_auction(&input.orders, input.previous_clearing_price)
        .expect("auction input must satisfy matcher constraints");
    assert_eq!(
        result, input.expected_result,
        "host-provided auction result does not match the rules"
    );

    let public_values = AuctionPublicValues {
        batch_id: input.batch_id,
        batch_commitment: digest(
            &bincode::serialize(&input.orders).expect("orders must serialize"),
        ),
        clearing_price: result.clearing_price,
        volume: result.volume,
        fills_commitment: digest(&bincode::serialize(&result.fills).expect("fills must serialize")),
    };
    env::commit(&public_values);
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    *Impl::hash_bytes(bytes).as_bytes()
}
