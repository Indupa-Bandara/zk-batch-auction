#![no_main]

use batch_auction_matching::{
    apply_account_state_transition, canonical_fills_bytes, canonical_order_batch_bytes,
    validate_signed_orders, verify_auction, AuctionInput, AuctionPublicValues,
};
use risc0_zkvm::{
    guest::env,
    sha::{Impl, Sha256},
};

risc0_zkvm::guest::entry!(main);

fn main() {
    let input: AuctionInput = env::read();
    validate_signed_orders(&input.orders, input.batch_id, input.batch_timestamp)
        .expect("an order is unsigned, expired, or for a different batch");
    verify_auction(
        &input.orders,
        &input.sorted_order_indices,
        &input.hash_sorted_order_indices,
        input.previous_clearing_price,
        &input.expected_result,
    )
    .expect("host-provided auction result or order witness is invalid");
    let state_transition = apply_account_state_transition(
        &input.account_states,
        &input.orders,
        &input.expected_result,
    )
    .expect("account nonce, balance, or state witness is invalid");

    let public_values = AuctionPublicValues {
        batch_id: input.batch_id,
        batch_timestamp: input.batch_timestamp,
        batch_commitment: digest(
            &canonical_order_batch_bytes(&input.orders, &input.hash_sorted_order_indices)
                .expect("order commitment must serialize"),
        ),
        previous_account_root: state_transition.previous_root,
        new_account_root: state_transition.new_root,
        previous_clearing_price: input.previous_clearing_price,
        clearing_price: input.expected_result.clearing_price,
        volume: input.expected_result.volume,
        fills_commitment: digest(
            &canonical_fills_bytes(
                &input.orders,
                &input.expected_result.fills,
                &input.hash_sorted_order_indices,
            )
            .expect("fills commitment must serialize"),
        ),
    };
    env::commit(&public_values);
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    *Impl::hash_bytes(bytes).as_bytes()
}
