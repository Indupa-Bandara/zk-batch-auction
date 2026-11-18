#![no_main]

use batch_auction_matching::{verify_auction, AuctionInput, AuctionPublicValues};
use risc0_zkvm::{
    guest::env,
    sha::{Impl, Sha256},
};

risc0_zkvm::guest::entry!(main);

fn main() {
    let input: AuctionInput = env::read();
    verify_auction(
        &input.orders,
        &input.sorted_order_indices,
        &input.hash_sorted_order_indices,
        input.previous_clearing_price,
        &input.expected_result,
    )
    .expect("host-provided auction result or order witness is invalid");

    let public_values = AuctionPublicValues {
        batch_id: input.batch_id,
        batch_commitment: digest(
            &bincode::serialize(&input.orders).expect("orders must serialize"),
        ),
        previous_clearing_price: input.previous_clearing_price,
        clearing_price: input.expected_result.clearing_price,
        volume: input.expected_result.volume,
        fills_commitment: digest(
            &bincode::serialize(&input.expected_result.fills).expect("fills must serialize"),
        ),
    };
    env::commit(&public_values);
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    *Impl::hash_bytes(bytes).as_bytes()
}
