use batch_auction_matching::{
    apply_account_state_transition, canonical_fills_bytes, canonical_order_batch_bytes,
    canonical_order_hash, clear_auction, hash_sorted_order_indices, order_signing_bytes,
    sorted_order_indices, validate_signed_orders, AccountState, AuctionInput, AuctionPublicValues,
    Order, Side,
};
use batch_auction_methods::{BATCH_AUCTION_GUEST_ELF, BATCH_AUCTION_GUEST_ID};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use risc0_zkvm::{
    default_prover,
    sha::{Impl, Sha256},
    ExecutorEnv,
};
use std::{
    error::Error,
    time::{SystemTime, UNIX_EPOCH},
};

fn main() -> Result<(), Box<dyn Error>> {
    let batch_timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let expiry = batch_timestamp
        .checked_add(3600)
        .ok_or("order expiry timestamp overflow")?;
    let buyer_key = SigningKey::generate(&mut OsRng);
    let seller_key = SigningKey::generate(&mut OsRng);
    let orders = vec![
        order(&buyer_key, Side::Buy, 102, 10, 1, 0, expiry),
        order(&buyer_key, Side::Buy, 101, 5, 2, 0, expiry),
        order(&buyer_key, Side::Buy, 100, 8, 3, 0, expiry),
        order(&seller_key, Side::Sell, 99, 6, 1, 0, expiry),
        order(&seller_key, Side::Sell, 100, 7, 2, 0, expiry),
        order(&seller_key, Side::Sell, 101, 9, 3, 0, expiry),
    ];
    validate_signed_orders(&orders, 0, batch_timestamp)?;
    let expected_result = clear_auction(&orders, None)?;
    let mut account_states = vec![
        AccountState {
            account_id: buyer_key.verifying_key().to_bytes(),
            next_nonce: 1,
            base_balance: 0,
            quote_balance: 1515,
        },
        AccountState {
            account_id: seller_key.verifying_key().to_bytes(),
            next_nonce: 1,
            base_balance: 15,
            quote_balance: 0,
        },
    ];
    account_states.sort_unstable_by_key(|account| account.account_id);
    let state_transition =
        apply_account_state_transition(&account_states, &orders, &expected_result)?;
    let input = AuctionInput {
        batch_id: 0,
        batch_timestamp,
        sorted_order_indices: sorted_order_indices(&orders)?,
        hash_sorted_order_indices: hash_sorted_order_indices(&orders)?,
        orders,
        account_states,
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
        || public_values.batch_timestamp != input.batch_timestamp
        || public_values.batch_commitment != expected_batch_commitment
        || public_values.previous_account_root != state_transition.previous_root
        || public_values.new_account_root != state_transition.new_root
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

fn order(
    signing_key: &SigningKey,
    side: Side,
    limit_price: u64,
    quantity: u64,
    nonce: u64,
    batch_id: u64,
    expiry: u64,
) -> Order {
    let mut order = Order {
        account_id: signing_key.verifying_key().to_bytes(),
        side,
        limit_price,
        quantity,
        nonce,
        batch_id,
        expiry,
        order_hash: [0; 32],
        signature: vec![0; 64],
    };
    order.order_hash = canonical_order_hash(&order);
    order.signature = signing_key
        .sign(&order_signing_bytes(&order))
        .to_bytes()
        .to_vec();
    order
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    *Impl::hash_bytes(bytes).as_bytes()
}
