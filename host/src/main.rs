use batch_auction_matching::{
    canonical_fills_bytes, canonical_order_batch_bytes, clear_auction, hash_sorted_order_indices,
    sorted_order_indices, AuctionInput, AuctionPublicValues, Order, Side,
};
use batch_auction_methods::{BATCH_AUCTION_GUEST_ELF, BATCH_AUCTION_GUEST_ID};
use risc0_zkvm::{
    default_prover,
    sha::{Impl, Sha256},
    ExecutorEnv,
};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let orders = vec![
        order(Side::Buy, 102, 10, 1),
        order(Side::Buy, 101, 5, 2),
        order(Side::Buy, 100, 8, 3),
        order(Side::Sell, 99, 6, 4),
        order(Side::Sell, 100, 7, 5),
        order(Side::Sell, 101, 9, 6),
    ];
    let expected_result = clear_auction(&orders, None)?;
    let input = AuctionInput {
        batch_id: 0,
        sorted_order_indices: sorted_order_indices(&orders)?,
        hash_sorted_order_indices: hash_sorted_order_indices(&orders)?,
        orders,
        previous_clearing_price: None,
        expected_result,
    };

    let env = ExecutorEnv::builder().write(&input)?.build()?;
    let receipt = default_prover()
        .prove(env, BATCH_AUCTION_GUEST_ELF)?
        .receipt;
    receipt.verify(BATCH_AUCTION_GUEST_ID)?;

    let public_values: AuctionPublicValues = receipt.journal.decode()?;
    let expected_batch_commitment = digest(&canonical_order_batch_bytes(
        &input.orders,
        &input.hash_sorted_order_indices,
    )?);
    let expected_fills_commitment = digest(&canonical_fills_bytes(
        &input.orders,
        &input.expected_result.fills,
        &input.hash_sorted_order_indices,
    )?);
    if public_values.batch_id != input.batch_id
        || public_values.batch_commitment != expected_batch_commitment
        || public_values.previous_clearing_price != input.previous_clearing_price
        || public_values.clearing_price != input.expected_result.clearing_price
        || public_values.volume != input.expected_result.volume
        || public_values.fills_commitment != expected_fills_commitment
    {
        return Err("guest public values do not match the host input".into());
    }

    println!("{public_values:#?}");
    Ok(())
}

fn order(side: Side, limit_price: u64, quantity: u64, hash: u8) -> Order {
    let mut order_hash = [0; 32];
    order_hash[31] = hash;
    Order {
        side,
        limit_price,
        quantity,
        order_hash,
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    *Impl::hash_bytes(bytes).as_bytes()
}
