#![cfg_attr(target_os = "zkvm", no_std)]

extern crate alloc;

use alloc::{vec, vec::Vec};
use core::{cmp::Ordering, fmt};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Side {
    Buy,
    Sell,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Order {
    pub account_id: [u8; 32],
    pub side: Side,
    pub limit_price: u64,
    pub quantity: u64,
    pub nonce: u64,
    pub batch_id: u64,
    pub expiry: u64,
    pub order_hash: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AccountState {
    pub account_id: [u8; 32],
    pub next_nonce: u64,
    pub base_balance: u128,
    pub quote_balance: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountStateTransition {
    pub previous_root: [u8; 32],
    pub new_root: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuctionResult {
    pub clearing_price: Option<u64>,
    pub volume: u128,
    /// Fill quantities are in the same order as the input orders.
    pub fills: Vec<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuctionInput {
    pub batch_id: u64,
    pub batch_timestamp: u64,
    pub orders: Vec<Order>,
    pub account_states: Vec<AccountState>,
    pub sorted_order_indices: Vec<u32>,
    pub hash_sorted_order_indices: Vec<u32>,
    pub previous_clearing_price: Option<u64>,
    pub expected_result: AuctionResult,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuctionPublicValues {
    pub batch_id: u64,
    pub batch_timestamp: u64,
    pub batch_commitment: [u8; 32],
    pub previous_account_root: [u8; 32],
    pub new_account_root: [u8; 32],
    pub previous_clearing_price: Option<u64>,
    pub clearing_price: Option<u64>,
    pub volume: u128,
    pub fills_commitment: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchError {
    DuplicateOrderHash,
    ArithmeticOverflow,
    InvalidAllocation,
    InvalidWitness,
    InvalidAccountId,
    InvalidSignature,
    InvalidOrderHash,
    InvalidOrder,
    WrongBatch,
    ExpiredOrder,
    InvalidAccountState,
    NonceMismatch,
    InsufficientBalance,
}

impl fmt::Display for MatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::DuplicateOrderHash => "duplicate order hash",
            Self::ArithmeticOverflow => "auction arithmetic overflow",
            Self::InvalidAllocation => "invalid auction allocation",
            Self::InvalidWitness => "invalid auction witness",
            Self::InvalidAccountId => "invalid Ed25519 account public key",
            Self::InvalidSignature => "invalid order signature",
            Self::InvalidOrderHash => "order hash does not match signed fields",
            Self::InvalidOrder => "invalid order fields",
            Self::WrongBatch => "order is for a different batch",
            Self::ExpiredOrder => "order is expired",
            Self::InvalidAccountState => "invalid account state",
            Self::NonceMismatch => "account nonce sequence is invalid",
            Self::InsufficientBalance => "account balance is insufficient",
        };
        formatter.write_str(message)
    }
}

impl core::error::Error for MatchError {}

const ORDER_DOMAIN: &[u8] = b"batch-auction-exchange/order/v1\0";

pub fn order_signing_bytes(order: &Order) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(ORDER_DOMAIN.len() + 32 + 1 + 5 * 8);
    bytes.extend_from_slice(ORDER_DOMAIN);
    bytes.extend_from_slice(&order.account_id);
    bytes.push(match order.side {
        Side::Buy => 0,
        Side::Sell => 1,
    });
    bytes.extend_from_slice(&order.limit_price.to_be_bytes());
    bytes.extend_from_slice(&order.quantity.to_be_bytes());
    bytes.extend_from_slice(&order.nonce.to_be_bytes());
    bytes.extend_from_slice(&order.batch_id.to_be_bytes());
    bytes.extend_from_slice(&order.expiry.to_be_bytes());
    bytes
}

pub fn canonical_order_hash(order: &Order) -> [u8; 32] {
    Sha256::digest(order_signing_bytes(order)).into()
}

pub fn validate_signed_orders(
    orders: &[Order],
    batch_id: u64,
    batch_timestamp: u64,
) -> Result<(), MatchError> {
    for order in orders {
        if order.batch_id != batch_id {
            return Err(MatchError::WrongBatch);
        }
        if batch_timestamp >= order.expiry {
            return Err(MatchError::ExpiredOrder);
        }
        if order.quantity == 0 {
            return Err(MatchError::InvalidOrder);
        }
        if canonical_order_hash(order) != order.order_hash {
            return Err(MatchError::InvalidOrderHash);
        }

        let verifying_key = VerifyingKey::from_bytes(&order.account_id)
            .map_err(|_| MatchError::InvalidAccountId)?;
        let signature =
            Signature::from_slice(&order.signature).map_err(|_| MatchError::InvalidSignature)?;
        verifying_key
            .verify_strict(&order_signing_bytes(order), &signature)
            .map_err(|_| MatchError::InvalidSignature)?;
    }
    Ok(())
}

pub fn account_state_root(accounts: &[AccountState]) -> Result<[u8; 32], MatchError> {
    if accounts
        .windows(2)
        .any(|pair| pair[0].account_id >= pair[1].account_id)
    {
        return Err(MatchError::InvalidAccountState);
    }

    let mut level: Vec<[u8; 32]> = accounts.iter().map(account_leaf_hash).collect();
    if level.is_empty() {
        return Ok(Sha256::digest(b"batch-auction-exchange/account-empty/v1\0").into());
    }

    while level.len() > 1 {
        let mut parent_level = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            let mut node = Vec::with_capacity(65);
            node.extend_from_slice(b"batch-auction-exchange/account-node/v1\0");
            node.extend_from_slice(&pair[0]);
            node.extend_from_slice(right);
            parent_level.push(Sha256::digest(node).into());
        }
        level = parent_level;
    }

    Ok(level[0])
}

pub fn apply_account_state_transition(
    accounts: &[AccountState],
    orders: &[Order],
    result: &AuctionResult,
) -> Result<AccountStateTransition, MatchError> {
    if orders.len() != result.fills.len() {
        return Err(MatchError::InvalidWitness);
    }

    let previous_root = account_state_root(accounts)?;
    let mut next_accounts = accounts.to_vec();
    let mut order_counts = vec![0_u64; accounts.len()];
    let mut deltas = vec![BalanceDelta::default(); accounts.len()];

    for (order, fill) in orders.iter().zip(&result.fills) {
        if *fill > order.quantity {
            return Err(MatchError::InvalidAllocation);
        }
        let account_index = accounts
            .binary_search_by_key(&order.account_id, |account| account.account_id)
            .map_err(|_| MatchError::InvalidAccountState)?;
        order_counts[account_index] = order_counts[account_index]
            .checked_add(1)
            .ok_or(MatchError::ArithmeticOverflow)?;

        if *fill == 0 {
            continue;
        }
        let clearing_price = result.clearing_price.ok_or(MatchError::InvalidAllocation)?;
        let notional = u128::from(*fill)
            .checked_mul(u128::from(clearing_price))
            .ok_or(MatchError::ArithmeticOverflow)?;
        match order.side {
            Side::Buy => {
                deltas[account_index].base_credit = deltas[account_index]
                    .base_credit
                    .checked_add(u128::from(*fill))
                    .ok_or(MatchError::ArithmeticOverflow)?;
                deltas[account_index].quote_debit = deltas[account_index]
                    .quote_debit
                    .checked_add(notional)
                    .ok_or(MatchError::ArithmeticOverflow)?;
            }
            Side::Sell => {
                deltas[account_index].base_debit = deltas[account_index]
                    .base_debit
                    .checked_add(u128::from(*fill))
                    .ok_or(MatchError::ArithmeticOverflow)?;
                deltas[account_index].quote_credit = deltas[account_index]
                    .quote_credit
                    .checked_add(notional)
                    .ok_or(MatchError::ArithmeticOverflow)?;
            }
        }
    }

    for (account_index, account) in accounts.iter().enumerate() {
        let order_count = order_counts[account_index];
        if order_count == 0 {
            continue;
        }

        let nonce_end = account
            .next_nonce
            .checked_add(order_count)
            .ok_or(MatchError::ArithmeticOverflow)?;
        for (index, order) in orders.iter().enumerate() {
            if order.account_id != account.account_id {
                continue;
            }
            if order.nonce < account.next_nonce || order.nonce >= nonce_end {
                return Err(MatchError::NonceMismatch);
            }
            if orders[index + 1..]
                .iter()
                .any(|other| other.account_id == order.account_id && other.nonce == order.nonce)
            {
                return Err(MatchError::NonceMismatch);
            }
        }

        let delta = deltas[account_index];
        let next_account = &mut next_accounts[account_index];
        next_account.next_nonce = nonce_end;
        next_account.base_balance = account
            .base_balance
            .checked_add(delta.base_credit)
            .ok_or(MatchError::ArithmeticOverflow)?
            .checked_sub(delta.base_debit)
            .ok_or(MatchError::InsufficientBalance)?;
        next_account.quote_balance = account
            .quote_balance
            .checked_add(delta.quote_credit)
            .ok_or(MatchError::ArithmeticOverflow)?
            .checked_sub(delta.quote_debit)
            .ok_or(MatchError::InsufficientBalance)?;
    }

    let new_root = account_state_root(&next_accounts)?;
    Ok(AccountStateTransition {
        previous_root,
        new_root,
    })
}

#[derive(Clone, Copy, Debug, Default)]
struct BalanceDelta {
    base_credit: u128,
    base_debit: u128,
    quote_credit: u128,
    quote_debit: u128,
}

fn account_leaf_hash(account: &AccountState) -> [u8; 32] {
    let mut leaf = Vec::with_capacity(94);
    leaf.extend_from_slice(b"batch-auction-exchange/account-leaf/v1\0");
    leaf.extend_from_slice(&account.account_id);
    leaf.extend_from_slice(&account.next_nonce.to_be_bytes());
    leaf.extend_from_slice(&account.base_balance.to_be_bytes());
    leaf.extend_from_slice(&account.quote_balance.to_be_bytes());
    Sha256::digest(leaf).into()
}

#[derive(Clone, Copy, Debug)]
struct Candidate {
    price: u64,
    volume: u128,
    imbalance: u128,
    distance_from_previous: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
struct PriceLevel {
    price: u64,
    buy_quantity: u128,
    sell_quantity: u128,
    start: usize,
    end: usize,
}

impl Candidate {
    fn is_better_than(self, other: Self) -> bool {
        self.volume > other.volume
            || (self.volume == other.volume
                && (self.imbalance < other.imbalance
                    || (self.imbalance == other.imbalance
                        && match (self.distance_from_previous, other.distance_from_previous) {
                            (Some(left), Some(right)) if left != right => left < right,
                            _ => self.price < other.price,
                        })))
    }
}

pub fn sorted_order_indices(orders: &[Order]) -> Result<Vec<u32>, MatchError> {
    let mut indices: Vec<usize> = (0..orders.len()).collect();
    indices.sort_unstable_by(|left, right| compare_orders(orders, *left, *right));
    to_u32_indices(indices)
}

pub fn hash_sorted_order_indices(orders: &[Order]) -> Result<Vec<u32>, MatchError> {
    let mut indices: Vec<usize> = (0..orders.len()).collect();
    indices.sort_unstable_by(|left, right| compare_order_hashes(orders, *left, *right));
    to_u32_indices(indices)
}

fn to_u32_indices(indices: Vec<usize>) -> Result<Vec<u32>, MatchError> {
    indices
        .into_iter()
        .map(|index| u32::try_from(index).map_err(|_| MatchError::ArithmeticOverflow))
        .collect()
}

pub fn verify_auction(
    orders: &[Order],
    sorted_order_indices: &[u32],
    hash_sorted_order_indices: &[u32],
    previous_clearing_price: Option<u64>,
    claimed_result: &AuctionResult,
) -> Result<(), MatchError> {
    if claimed_result.fills.len() != orders.len() {
        return Err(MatchError::InvalidWitness);
    }

    let indices = validate_permutation(orders, sorted_order_indices)?;
    if indices
        .windows(2)
        .any(|pair| compare_orders(orders, pair[0], pair[1]).is_gt())
    {
        return Err(MatchError::InvalidWitness);
    }

    validate_hash_sorted_indices(orders, hash_sorted_order_indices)?;

    let levels = build_price_levels(orders, &indices)?;
    let best =
        best_candidate(&levels, previous_clearing_price)?.filter(|candidate| candidate.volume > 0);
    let Some(best) = best else {
        if claimed_result.clearing_price.is_some()
            || claimed_result.volume != 0
            || claimed_result.fills.iter().any(|fill| *fill != 0)
        {
            return Err(MatchError::InvalidWitness);
        }
        return Ok(());
    };

    if claimed_result.clearing_price != Some(best.price) || claimed_result.volume != best.volume {
        return Err(MatchError::InvalidWitness);
    }

    let mut expected_fills = vec![0; orders.len()];
    allocate_sorted_side(
        orders,
        &indices,
        &levels,
        best.price,
        Side::Buy,
        best.volume,
        &mut expected_fills,
    )?;
    allocate_sorted_side(
        orders,
        &indices,
        &levels,
        best.price,
        Side::Sell,
        best.volume,
        &mut expected_fills,
    )?;
    if expected_fills != claimed_result.fills {
        return Err(MatchError::InvalidWitness);
    }
    Ok(())
}

pub fn canonical_order_batch_bytes(
    orders: &[Order],
    hash_sorted_order_indices: &[u32],
) -> Result<Vec<u8>, MatchError> {
    let indices = validate_hash_sorted_indices(orders, hash_sorted_order_indices)?;
    let order_count = u64::try_from(indices.len()).map_err(|_| MatchError::ArithmeticOverflow)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"batch-auction-exchange/order-batch/v1\0");
    bytes.extend_from_slice(&order_count.to_be_bytes());
    for index in indices {
        let order = &orders[index];
        bytes.extend_from_slice(&order.account_id);
        bytes.push(match order.side {
            Side::Buy => 0,
            Side::Sell => 1,
        });
        bytes.extend_from_slice(&order.limit_price.to_be_bytes());
        bytes.extend_from_slice(&order.quantity.to_be_bytes());
        bytes.extend_from_slice(&order.nonce.to_be_bytes());
        bytes.extend_from_slice(&order.batch_id.to_be_bytes());
        bytes.extend_from_slice(&order.expiry.to_be_bytes());
        bytes.extend_from_slice(&order.order_hash);
        let signature_length =
            u64::try_from(order.signature.len()).map_err(|_| MatchError::ArithmeticOverflow)?;
        bytes.extend_from_slice(&signature_length.to_be_bytes());
        bytes.extend_from_slice(&order.signature);
    }
    Ok(bytes)
}

pub fn canonical_fills_bytes(
    orders: &[Order],
    fills: &[u64],
    hash_sorted_order_indices: &[u32],
) -> Result<Vec<u8>, MatchError> {
    if fills.len() != orders.len() {
        return Err(MatchError::InvalidWitness);
    }
    let indices = validate_hash_sorted_indices(orders, hash_sorted_order_indices)?;
    let fill_count = u64::try_from(indices.len()).map_err(|_| MatchError::ArithmeticOverflow)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"batch-auction-exchange/fills/v1\0");
    bytes.extend_from_slice(&fill_count.to_be_bytes());
    for index in indices {
        bytes.extend_from_slice(&orders[index].order_hash);
        bytes.extend_from_slice(&fills[index].to_be_bytes());
    }
    Ok(bytes)
}

fn validate_permutation(orders: &[Order], indices: &[u32]) -> Result<Vec<usize>, MatchError> {
    if indices.len() != orders.len() {
        return Err(MatchError::InvalidWitness);
    }

    let mut seen = vec![false; orders.len()];
    let mut validated = Vec::with_capacity(indices.len());
    for index in indices {
        let index = usize::try_from(*index).map_err(|_| MatchError::InvalidWitness)?;
        if index >= orders.len() || seen[index] {
            return Err(MatchError::InvalidWitness);
        }
        seen[index] = true;
        validated.push(index);
    }
    Ok(validated)
}

fn validate_hash_sorted_indices(
    orders: &[Order],
    indices: &[u32],
) -> Result<Vec<usize>, MatchError> {
    let indices = validate_permutation(orders, indices)?;
    for pair in indices.windows(2) {
        if compare_order_hashes(orders, pair[0], pair[1]).is_gt() {
            return Err(MatchError::InvalidWitness);
        }
        if orders[pair[0]].order_hash == orders[pair[1]].order_hash {
            return Err(MatchError::DuplicateOrderHash);
        }
    }
    Ok(indices)
}

pub fn clear_auction(
    orders: &[Order],
    previous_clearing_price: Option<u64>,
) -> Result<AuctionResult, MatchError> {
    let mut hashes: Vec<[u8; 32]> = orders.iter().map(|order| order.order_hash).collect();
    hashes.sort_unstable();
    if hashes.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(MatchError::DuplicateOrderHash);
    }

    let mut prices: Vec<u64> = orders.iter().map(|order| order.limit_price).collect();
    if let Some(previous_price) = previous_clearing_price {
        prices.push(previous_price);
    }
    prices.sort_unstable();
    prices.dedup();

    let mut best: Option<Candidate> = None;
    for price in prices {
        let (demand, supply) = eligible_totals(orders, price)?;
        let candidate = Candidate {
            price,
            volume: demand.min(supply),
            imbalance: demand.abs_diff(supply),
            distance_from_previous: previous_clearing_price
                .map(|previous| price.abs_diff(previous)),
        };
        if best
            .map(|current| candidate.is_better_than(current))
            .unwrap_or(true)
        {
            best = Some(candidate);
        }
    }

    let Some(best) = best.filter(|candidate| candidate.volume > 0) else {
        return Ok(AuctionResult {
            clearing_price: None,
            volume: 0,
            fills: vec![0; orders.len()],
        });
    };

    let (demand, supply) = eligible_totals(orders, best.price)?;
    let mut fills = vec![0; orders.len()];
    if demand <= supply {
        allocate_side(orders, best.price, Side::Buy, demand, &mut fills)?;
        allocate_side(orders, best.price, Side::Sell, best.volume, &mut fills)?;
    } else {
        allocate_side(orders, best.price, Side::Buy, best.volume, &mut fills)?;
        allocate_side(orders, best.price, Side::Sell, supply, &mut fills)?;
    }

    Ok(AuctionResult {
        clearing_price: Some(best.price),
        volume: best.volume,
        fills,
    })
}

fn compare_orders(orders: &[Order], left: usize, right: usize) -> Ordering {
    let left_order = &orders[left];
    let right_order = &orders[right];
    left_order
        .limit_price
        .cmp(&right_order.limit_price)
        .then_with(|| side_order(left_order.side).cmp(&side_order(right_order.side)))
        .then_with(|| left_order.order_hash.cmp(&right_order.order_hash))
}

fn compare_order_hashes(orders: &[Order], left: usize, right: usize) -> Ordering {
    let left_order = &orders[left];
    let right_order = &orders[right];
    left_order
        .order_hash
        .cmp(&right_order.order_hash)
        .then_with(|| side_order(left_order.side).cmp(&side_order(right_order.side)))
        .then_with(|| left_order.limit_price.cmp(&right_order.limit_price))
}

fn side_order(side: Side) -> u8 {
    match side {
        Side::Buy => 0,
        Side::Sell => 1,
    }
}

fn build_price_levels(
    orders: &[Order],
    sorted_order_indices: &[usize],
) -> Result<Vec<PriceLevel>, MatchError> {
    let mut levels: Vec<PriceLevel> = Vec::new();
    for (position, index) in sorted_order_indices.iter().copied().enumerate() {
        let order = &orders[index];
        let level = match levels.last_mut() {
            Some(level) if level.price == order.limit_price => level,
            _ => {
                levels.push(PriceLevel {
                    price: order.limit_price,
                    buy_quantity: 0,
                    sell_quantity: 0,
                    start: position,
                    end: position + 1,
                });
                levels.last_mut().expect("a price level was just added")
            }
        };
        level.end = position + 1;
        let quantity = u128::from(order.quantity);
        match order.side {
            Side::Buy => {
                level.buy_quantity = level
                    .buy_quantity
                    .checked_add(quantity)
                    .ok_or(MatchError::ArithmeticOverflow)?;
            }
            Side::Sell => {
                level.sell_quantity = level
                    .sell_quantity
                    .checked_add(quantity)
                    .ok_or(MatchError::ArithmeticOverflow)?;
            }
        }
    }
    Ok(levels)
}

fn best_candidate(
    levels: &[PriceLevel],
    previous_clearing_price: Option<u64>,
) -> Result<Option<Candidate>, MatchError> {
    let mut demand = levels.iter().try_fold(0_u128, |total, level| {
        total
            .checked_add(level.buy_quantity)
            .ok_or(MatchError::ArithmeticOverflow)
    })?;
    let mut supply = 0_u128;
    let mut level_index = 0;
    let mut previous_price = previous_clearing_price;
    let mut best = None;

    while level_index < levels.len() || previous_price.is_some() {
        let next_level_price = levels.get(level_index).map(|level| level.price);
        let price = match (previous_price, next_level_price) {
            (Some(previous), Some(level_price)) if previous <= level_price => {
                previous_price = None;
                previous
            }
            (_, Some(level_price)) => level_price,
            (Some(previous), None) => {
                previous_price = None;
                previous
            }
            (None, None) => break,
        };

        while level_index < levels.len() && levels[level_index].price < price {
            demand = demand
                .checked_sub(levels[level_index].buy_quantity)
                .ok_or(MatchError::InvalidWitness)?;
            supply = supply
                .checked_add(levels[level_index].sell_quantity)
                .ok_or(MatchError::ArithmeticOverflow)?;
            level_index += 1;
        }

        if level_index < levels.len() && levels[level_index].price == price {
            supply = supply
                .checked_add(levels[level_index].sell_quantity)
                .ok_or(MatchError::ArithmeticOverflow)?;
        }
        let candidate = Candidate {
            price,
            volume: demand.min(supply),
            imbalance: demand.abs_diff(supply),
            distance_from_previous: previous_clearing_price
                .map(|previous| price.abs_diff(previous)),
        };
        if best
            .map(|current: Candidate| candidate.is_better_than(current))
            .unwrap_or(true)
        {
            best = Some(candidate);
        }

        if level_index < levels.len() && levels[level_index].price == price {
            demand = demand
                .checked_sub(levels[level_index].buy_quantity)
                .ok_or(MatchError::InvalidWitness)?;
            level_index += 1;
        }
    }
    Ok(best)
}

fn allocate_sorted_side(
    orders: &[Order],
    sorted_order_indices: &[usize],
    levels: &[PriceLevel],
    clearing_price: u64,
    side: Side,
    target: u128,
    fills: &mut [u64],
) -> Result<(), MatchError> {
    let eligible_total = levels.iter().try_fold(0_u128, |total, level| {
        if level_is_eligible(level.price, side, clearing_price) {
            total
                .checked_add(level_quantity(level, side))
                .ok_or(MatchError::ArithmeticOverflow)
        } else {
            Ok(total)
        }
    })?;
    if target > eligible_total {
        return Err(MatchError::InvalidWitness);
    }

    if target == eligible_total {
        for index in sorted_order_indices {
            let order = &orders[*index];
            if is_eligible(order, side, clearing_price) {
                fills[*index] = order.quantity;
            }
        }
        return Ok(());
    }

    let mut remaining = target;
    let mut allocate_level = |level: &PriceLevel| -> Result<(), MatchError> {
        if !level_is_eligible(level.price, side, clearing_price) || remaining == 0 {
            return Ok(());
        }

        let level_total = level_quantity(level, side);
        let level_indices: Vec<usize> = sorted_order_indices[level.start..level.end]
            .iter()
            .copied()
            .filter(|index| orders[*index].side == side)
            .collect();
        if level_total <= remaining {
            for index in level_indices {
                fills[index] = orders[index].quantity;
            }
            remaining -= level_total;
        } else {
            allocate_pro_rata(orders, &level_indices, remaining, fills)?;
            remaining = 0;
        }
        Ok(())
    };

    match side {
        Side::Buy => {
            for level in levels.iter().rev() {
                allocate_level(level)?;
            }
        }
        Side::Sell => {
            for level in levels {
                allocate_level(level)?;
            }
        }
    }
    if remaining != 0 {
        return Err(MatchError::InvalidWitness);
    }
    Ok(())
}

fn level_quantity(level: &PriceLevel, side: Side) -> u128 {
    match side {
        Side::Buy => level.buy_quantity,
        Side::Sell => level.sell_quantity,
    }
}

fn level_is_eligible(price: u64, side: Side, clearing_price: u64) -> bool {
    match side {
        Side::Buy => price >= clearing_price,
        Side::Sell => price <= clearing_price,
    }
}

fn eligible_totals(orders: &[Order], price: u64) -> Result<(u128, u128), MatchError> {
    orders
        .iter()
        .try_fold((0_u128, 0_u128), |(demand, supply), order| {
            let quantity = u128::from(order.quantity);
            match order.side {
                Side::Buy if order.limit_price >= price => Ok((
                    demand
                        .checked_add(quantity)
                        .ok_or(MatchError::ArithmeticOverflow)?,
                    supply,
                )),
                Side::Sell if order.limit_price <= price => Ok((
                    demand,
                    supply
                        .checked_add(quantity)
                        .ok_or(MatchError::ArithmeticOverflow)?,
                )),
                _ => Ok((demand, supply)),
            }
        })
}

fn allocate_side(
    orders: &[Order],
    price: u64,
    side: Side,
    target: u128,
    fills: &mut [u64],
) -> Result<(), MatchError> {
    let eligible_total = orders.iter().try_fold(0_u128, |total, order| {
        if is_eligible(order, side, price) {
            total
                .checked_add(u128::from(order.quantity))
                .ok_or(MatchError::ArithmeticOverflow)
        } else {
            Ok(total)
        }
    })?;
    if target > eligible_total {
        return Err(MatchError::InvalidAllocation);
    }

    if target == eligible_total {
        for (index, order) in orders.iter().enumerate() {
            if is_eligible(order, side, price) {
                fills[index] = order.quantity;
            }
        }
        return Ok(());
    }

    let mut eligible_indices: Vec<usize> = orders
        .iter()
        .enumerate()
        .filter_map(|(index, order)| is_eligible(order, side, price).then_some(index))
        .collect();
    eligible_indices.sort_unstable_by(|left, right| {
        let left_order = &orders[*left];
        let right_order = &orders[*right];
        let price_order = match side {
            Side::Buy => right_order.limit_price.cmp(&left_order.limit_price),
            Side::Sell => left_order.limit_price.cmp(&right_order.limit_price),
        };
        price_order.then_with(|| left_order.order_hash.cmp(&right_order.order_hash))
    });

    let mut remaining = target;
    let mut level_start = 0;
    while level_start < eligible_indices.len() && remaining > 0 {
        let level_price = orders[eligible_indices[level_start]].limit_price;
        let mut level_end = level_start + 1;
        while level_end < eligible_indices.len()
            && orders[eligible_indices[level_end]].limit_price == level_price
        {
            level_end += 1;
        }

        let level_indices = &eligible_indices[level_start..level_end];
        let level_total = level_indices.iter().try_fold(0_u128, |total, index| {
            total
                .checked_add(u128::from(orders[*index].quantity))
                .ok_or(MatchError::ArithmeticOverflow)
        })?;
        if level_total <= remaining {
            for index in level_indices {
                fills[*index] = orders[*index].quantity;
            }
            remaining -= level_total;
        } else {
            allocate_pro_rata(orders, level_indices, remaining, fills)?;
            remaining = 0;
        }
        level_start = level_end;
    }

    if remaining != 0 {
        return Err(MatchError::InvalidAllocation);
    }
    Ok(())
}

fn allocate_pro_rata(
    orders: &[Order],
    indices: &[usize],
    target: u128,
    fills: &mut [u64],
) -> Result<(), MatchError> {
    let marginal_total = indices.iter().try_fold(0_u128, |total, index| {
        total
            .checked_add(u128::from(orders[*index].quantity))
            .ok_or(MatchError::ArithmeticOverflow)
    })?;
    if target == 0 || target >= marginal_total {
        return Err(MatchError::InvalidAllocation);
    }

    let mut quotas = Vec::with_capacity(indices.len());
    let mut assigned = 0_u128;
    for index in indices {
        let order = &orders[*index];
        let product = target
            .checked_mul(u128::from(order.quantity))
            .ok_or(MatchError::ArithmeticOverflow)?;
        let base = product / marginal_total;
        fills[*index] = u64::try_from(base).map_err(|_| MatchError::ArithmeticOverflow)?;
        assigned = assigned
            .checked_add(base)
            .ok_or(MatchError::ArithmeticOverflow)?;
        quotas.push((product % marginal_total, order.order_hash, *index));
    }

    let unallocated = target
        .checked_sub(assigned)
        .ok_or(MatchError::InvalidAllocation)?;
    let leftover = usize::try_from(unallocated).map_err(|_| MatchError::ArithmeticOverflow)?;
    if leftover > quotas.len() {
        return Err(MatchError::InvalidAllocation);
    }
    for (remainder, order_hash, index) in &quotas {
        let rank = quotas
            .iter()
            .filter(|(other_remainder, other_hash, _)| {
                other_remainder > remainder
                    || (other_remainder == remainder && other_hash < order_hash)
            })
            .count();
        if rank < leftover {
            fills[*index] = fills[*index]
                .checked_add(1)
                .ok_or(MatchError::ArithmeticOverflow)?;
        }
    }
    Ok(())
}

fn is_eligible(order: &Order, side: Side, price: u64) -> bool {
    order.side == side
        && match side {
            Side::Buy => order.limit_price >= price,
            Side::Sell => order.limit_price <= price,
        }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    fn order(side: Side, limit_price: u64, quantity: u64, hash: u8) -> Order {
        let mut order_hash = [0; 32];
        order_hash[31] = hash;
        Order {
            account_id: [hash; 32],
            side,
            limit_price,
            quantity,
            nonce: u64::from(hash),
            batch_id: 0,
            expiry: u64::MAX,
            order_hash,
            signature: vec![0; 64],
        }
    }

    fn signed_order(
        seed: u8,
        side: Side,
        limit_price: u64,
        quantity: u64,
        nonce: u64,
        batch_id: u64,
        expiry: u64,
    ) -> Order {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
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

    #[test]
    fn signed_orders_bind_fields_batch_and_expiry() {
        let order = signed_order(7, Side::Buy, 100, 2, 4, 9, 101);
        assert_eq!(
            validate_signed_orders(std::slice::from_ref(&order), 9, 100),
            Ok(())
        );

        assert_eq!(
            validate_signed_orders(std::slice::from_ref(&order), 10, 100),
            Err(MatchError::WrongBatch)
        );
        assert_eq!(
            validate_signed_orders(std::slice::from_ref(&order), 9, 101),
            Err(MatchError::ExpiredOrder)
        );

        let mut changed_fields = order.clone();
        changed_fields.limit_price += 1;
        assert_eq!(
            validate_signed_orders(&[changed_fields], 9, 100),
            Err(MatchError::InvalidOrderHash)
        );

        let mut changed_signature = order.clone();
        changed_signature.signature[0] ^= 1;
        assert_eq!(
            validate_signed_orders(&[changed_signature], 9, 100),
            Err(MatchError::InvalidSignature)
        );

        let mut malformed_signature = order;
        malformed_signature.signature.pop();
        assert_eq!(
            validate_signed_orders(&[malformed_signature], 9, 100),
            Err(MatchError::InvalidSignature)
        );
    }

    #[test]
    fn signed_orders_reject_zero_quantity() {
        let order = signed_order(8, Side::Sell, 100, 0, 1, 9, 101);
        assert_eq!(
            validate_signed_orders(&[order], 9, 100),
            Err(MatchError::InvalidOrder)
        );
    }

    #[test]
    fn account_state_transition_nets_fills_and_advances_nonces() {
        let orders = [
            signed_order(11, Side::Buy, 10, 2, 5, 9, 101),
            signed_order(22, Side::Sell, 10, 2, 3, 9, 101),
        ];
        let result = clear_auction(&orders, None).unwrap();
        let mut accounts = vec![
            AccountState {
                account_id: orders[0].account_id,
                next_nonce: 5,
                base_balance: 0,
                quote_balance: 20,
            },
            AccountState {
                account_id: orders[1].account_id,
                next_nonce: 3,
                base_balance: 2,
                quote_balance: 0,
            },
        ];
        accounts.sort_unstable_by_key(|account| account.account_id);
        let mut updated_accounts = accounts.clone();

        let transition = apply_account_state_transition(&accounts, &orders, &result).unwrap();

        for account in &mut updated_accounts {
            if account.account_id == orders[0].account_id {
                account.next_nonce = 6;
                account.base_balance = 2;
                account.quote_balance = 0;
            } else {
                account.next_nonce = 4;
                account.base_balance = 0;
                account.quote_balance = 20;
            }
        }
        assert_eq!(
            transition.previous_root,
            account_state_root(&accounts).unwrap()
        );
        assert_eq!(
            transition.new_root,
            account_state_root(&updated_accounts).unwrap()
        );
        assert_ne!(transition.previous_root, transition.new_root);
    }

    #[test]
    fn account_state_transition_handles_multiple_orders_per_account_in_any_order() {
        let orders = [
            signed_order(11, Side::Buy, 10, 1, 5, 9, 101),
            signed_order(11, Side::Buy, 10, 1, 6, 9, 101),
            signed_order(22, Side::Sell, 10, 1, 3, 9, 101),
            signed_order(22, Side::Sell, 10, 1, 4, 9, 101),
        ];
        let result = clear_auction(&orders, None).unwrap();
        let mut accounts = vec![
            AccountState {
                account_id: orders[0].account_id,
                next_nonce: 5,
                base_balance: 0,
                quote_balance: 20,
            },
            AccountState {
                account_id: orders[2].account_id,
                next_nonce: 3,
                base_balance: 2,
                quote_balance: 0,
            },
        ];
        accounts.sort_unstable_by_key(|account| account.account_id);
        let transition = apply_account_state_transition(&accounts, &orders, &result).unwrap();

        let reordered_orders = [
            orders[3].clone(),
            orders[1].clone(),
            orders[2].clone(),
            orders[0].clone(),
        ];
        let reordered_result = clear_auction(&reordered_orders, None).unwrap();
        let reordered_transition =
            apply_account_state_transition(&accounts, &reordered_orders, &reordered_result)
                .unwrap();

        assert_eq!(transition, reordered_transition);
        assert_eq!(result.volume, 2);
        assert_eq!(result.fills, [1, 1, 1, 1]);
    }

    #[test]
    fn account_state_transition_rejects_insufficient_net_balance() {
        let orders = [
            signed_order(11, Side::Buy, 10, 2, 5, 9, 101),
            signed_order(22, Side::Sell, 10, 2, 3, 9, 101),
        ];
        let result = clear_auction(&orders, None).unwrap();
        let mut accounts = vec![
            AccountState {
                account_id: orders[0].account_id,
                next_nonce: 5,
                base_balance: 0,
                quote_balance: 19,
            },
            AccountState {
                account_id: orders[1].account_id,
                next_nonce: 3,
                base_balance: 2,
                quote_balance: 0,
            },
        ];
        accounts.sort_unstable_by_key(|account| account.account_id);

        assert_eq!(
            apply_account_state_transition(&accounts, &orders, &result),
            Err(MatchError::InsufficientBalance)
        );
    }

    #[test]
    fn account_state_transition_consumes_nonces_for_unfilled_orders() {
        let orders = [
            signed_order(11, Side::Buy, 9, 1, 5, 9, 101),
            signed_order(22, Side::Sell, 10, 1, 3, 9, 101),
        ];
        let result = clear_auction(&orders, None).unwrap();
        let mut accounts = vec![
            AccountState {
                account_id: orders[0].account_id,
                next_nonce: 5,
                base_balance: 0,
                quote_balance: 20,
            },
            AccountState {
                account_id: orders[1].account_id,
                next_nonce: 3,
                base_balance: 2,
                quote_balance: 0,
            },
        ];
        accounts.sort_unstable_by_key(|account| account.account_id);
        let transition = apply_account_state_transition(&accounts, &orders, &result).unwrap();

        assert_eq!(result.fills, [0, 0]);
        assert_ne!(
            transition.previous_root, transition.new_root,
            "accepted orders consume nonces even when unfilled"
        );
    }

    #[test]
    fn account_state_transition_rejects_nonce_gaps_and_unsorted_accounts() {
        let orders = [
            signed_order(11, Side::Buy, 10, 2, 6, 9, 101),
            signed_order(22, Side::Sell, 10, 2, 3, 9, 101),
        ];
        let result = clear_auction(&orders, None).unwrap();
        let mut accounts = vec![
            AccountState {
                account_id: orders[0].account_id,
                next_nonce: 5,
                base_balance: 0,
                quote_balance: 20,
            },
            AccountState {
                account_id: orders[1].account_id,
                next_nonce: 3,
                base_balance: 2,
                quote_balance: 0,
            },
        ];
        accounts.sort_unstable_by_key(|account| account.account_id);

        assert_eq!(
            apply_account_state_transition(&accounts, &orders, &result),
            Err(MatchError::NonceMismatch)
        );
        accounts.reverse();
        assert_eq!(
            account_state_root(&accounts),
            Err(MatchError::InvalidAccountState)
        );
    }

    #[test]
    fn matches_the_specification_golden_example() {
        let orders = [
            order(Side::Buy, 102, 10, 1),
            order(Side::Buy, 101, 5, 2),
            order(Side::Buy, 100, 8, 3),
            order(Side::Sell, 99, 6, 4),
            order(Side::Sell, 100, 7, 5),
            order(Side::Sell, 101, 9, 6),
        ];

        let result = clear_auction(&orders, None).unwrap();

        assert_eq!(result.clearing_price, Some(101));
        assert_eq!(result.volume, 15);
        assert_eq!(result.fills, [10, 5, 0, 6, 7, 2]);
        let sorted_indices = sorted_order_indices(&orders).unwrap();
        let hash_sorted_indices = hash_sorted_order_indices(&orders).unwrap();
        assert_eq!(
            verify_auction(
                &orders,
                &sorted_indices,
                &hash_sorted_indices,
                None,
                &result,
            ),
            Ok(())
        );
    }

    #[test]
    fn previous_price_wins_when_it_lies_on_a_tied_price_interval() {
        let orders = [order(Side::Buy, 101, 1, 1), order(Side::Sell, 99, 1, 2)];

        let result = clear_auction(&orders, Some(100)).unwrap();

        assert_eq!(result.clearing_price, Some(100));
        assert_eq!(result.volume, 1);
    }

    #[test]
    fn pro_rata_remainders_use_order_hash_and_ignore_input_order() {
        let orders = [
            order(Side::Buy, 100, 1, 2),
            order(Side::Buy, 100, 1, 1),
            order(Side::Sell, 100, 1, 3),
        ];
        let forward = clear_auction(&orders, None).unwrap();
        let reversed_orders = [orders[2].clone(), orders[1].clone(), orders[0].clone()];
        let reversed = clear_auction(&reversed_orders, None).unwrap();

        assert_eq!(forward.clearing_price, Some(100));
        assert_eq!(forward.volume, 1);
        assert_eq!(forward.fills, [0, 1, 1]);
        assert_eq!(reversed.fills, [1, 1, 0]);
    }

    #[test]
    fn public_commitment_encodings_ignore_input_order() {
        let orders = [
            order(Side::Buy, 100, 2, 1),
            order(Side::Sell, 100, 1, 2),
            order(Side::Buy, 99, 3, 3),
        ];
        let result = clear_auction(&orders, None).unwrap();
        let reversed_orders: Vec<Order> = orders.iter().cloned().rev().collect();
        let reversed_result = clear_auction(&reversed_orders, None).unwrap();
        let hash_indices = hash_sorted_order_indices(&orders).unwrap();
        let reversed_hash_indices = hash_sorted_order_indices(&reversed_orders).unwrap();

        assert_eq!(
            canonical_order_batch_bytes(&orders, &hash_indices).unwrap(),
            canonical_order_batch_bytes(&reversed_orders, &reversed_hash_indices).unwrap()
        );
        assert_eq!(
            canonical_fills_bytes(&orders, &result.fills, &hash_indices).unwrap(),
            canonical_fills_bytes(
                &reversed_orders,
                &reversed_result.fills,
                &reversed_hash_indices
            )
            .unwrap()
        );
    }

    #[test]
    fn overfilled_better_price_level_is_prorated() {
        let orders = [
            order(Side::Sell, 0, 4, 1),
            order(Side::Buy, 1, 3, 2),
            order(Side::Buy, 1, 3, 3),
        ];

        let result = clear_auction(&orders, None).unwrap();

        assert_eq!(result.clearing_price, Some(0));
        assert_eq!(result.volume, 4);
        assert_eq!(result.fills, [4, 2, 2]);
    }

    #[test]
    fn no_cross_returns_no_price_and_zero_fills() {
        let orders = [order(Side::Buy, 99, 4, 1), order(Side::Sell, 100, 3, 2)];

        let result = clear_auction(&orders, None).unwrap();

        assert_eq!(result.clearing_price, None);
        assert_eq!(result.volume, 0);
        assert_eq!(result.fills, [0, 0]);
    }

    #[test]
    fn duplicate_order_hashes_are_rejected() {
        let duplicate = order(Side::Buy, 100, 1, 1);
        let orders = [duplicate.clone(), duplicate];

        assert_eq!(
            clear_auction(&orders, None),
            Err(MatchError::DuplicateOrderHash)
        );
        let price_sorted = sorted_order_indices(&orders).unwrap();
        let hash_sorted = hash_sorted_order_indices(&orders).unwrap();
        let result = AuctionResult {
            clearing_price: Some(100),
            volume: 1,
            fills: vec![1, 0],
        };
        assert_eq!(
            verify_auction(&orders, &price_sorted, &hash_sorted, None, &result),
            Err(MatchError::DuplicateOrderHash)
        );
    }

    #[test]
    fn verifier_rejects_tampered_fills_and_invalid_order_witnesses() {
        let orders = [order(Side::Buy, 100, 2, 1), order(Side::Sell, 100, 1, 2)];
        let result = clear_auction(&orders, None).unwrap();
        let sorted_indices = sorted_order_indices(&orders).unwrap();
        let hash_sorted_indices = hash_sorted_order_indices(&orders).unwrap();

        let mut tampered_result = result.clone();
        tampered_result.fills[0] -= 1;
        assert_eq!(
            verify_auction(
                &orders,
                &sorted_indices,
                &hash_sorted_indices,
                None,
                &tampered_result,
            ),
            Err(MatchError::InvalidWitness)
        );

        let mut tampered_price = result.clone();
        tampered_price.clearing_price = Some(99);
        assert_eq!(
            verify_auction(
                &orders,
                &sorted_indices,
                &hash_sorted_indices,
                None,
                &tampered_price,
            ),
            Err(MatchError::InvalidWitness)
        );

        let duplicate_indices = [sorted_indices[0], sorted_indices[0]];
        assert_eq!(
            verify_auction(
                &orders,
                &duplicate_indices,
                &hash_sorted_indices,
                None,
                &result,
            ),
            Err(MatchError::InvalidWitness)
        );

        let unsorted_indices = [sorted_indices[1], sorted_indices[0]];
        assert_eq!(
            verify_auction(
                &orders,
                &unsorted_indices,
                &hash_sorted_indices,
                None,
                &result,
            ),
            Err(MatchError::InvalidWitness)
        );

        let duplicate_hash_indices = [hash_sorted_indices[0], hash_sorted_indices[0]];
        assert_eq!(
            verify_auction(
                &orders,
                &sorted_indices,
                &duplicate_hash_indices,
                None,
                &result,
            ),
            Err(MatchError::InvalidWitness)
        );

        let unsorted_hash_indices = [hash_sorted_indices[1], hash_sorted_indices[0]];
        assert_eq!(
            verify_auction(
                &orders,
                &sorted_indices,
                &unsorted_hash_indices,
                None,
                &result,
            ),
            Err(MatchError::InvalidWitness)
        );
    }

    fn reference_result(
        orders: &[Order],
        previous_clearing_price: Option<u64>,
    ) -> (Option<u64>, u128) {
        let mut candidates: Vec<u64> = orders.iter().map(|order| order.limit_price).collect();
        if let Some(previous_price) = previous_clearing_price {
            candidates.push(previous_price);
        }
        candidates.sort_unstable();
        candidates.dedup();

        let mut best: Option<(u64, u128, u128)> = None;
        for price in candidates {
            let mut demand = 0_u128;
            let mut supply = 0_u128;
            for order in orders {
                match order.side {
                    Side::Buy if order.limit_price >= price => {
                        demand += u128::from(order.quantity);
                    }
                    Side::Sell if order.limit_price <= price => {
                        supply += u128::from(order.quantity);
                    }
                    _ => {}
                }
            }
            let candidate = (price, demand.min(supply), demand.abs_diff(supply));
            let candidate_is_better = best
                .map(|current| {
                    candidate.1 > current.1
                        || (candidate.1 == current.1
                            && (candidate.2 < current.2
                                || (candidate.2 == current.2
                                    && match previous_clearing_price {
                                        Some(previous)
                                            if candidate.0.abs_diff(previous)
                                                != current.0.abs_diff(previous) =>
                                        {
                                            candidate.0.abs_diff(previous)
                                                < current.0.abs_diff(previous)
                                        }
                                        _ => candidate.0 < current.0,
                                    })))
                })
                .unwrap_or(true);
            if candidate_is_better {
                best = Some(candidate);
            }
        }

        match best {
            Some((price, volume, _)) if volume > 0 => (Some(price), volume),
            _ => (None, 0),
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, .. ProptestConfig::default() })]

        #[test]
        fn generated_batches_obey_matching_invariants(
            raw_orders in prop::collection::vec((any::<bool>(), 0_u64..6, 0_u64..8), 0..20),
            previous_clearing_price in prop_oneof![
                Just(None),
                (0_u64..6).prop_map(Some),
            ],
        ) {
            let orders: Vec<Order> = raw_orders
                .into_iter()
                .enumerate()
                .map(|(index, (is_buy, limit_price, quantity))| {
                    let mut order_hash = [0; 32];
                    order_hash[24..].copy_from_slice(
                        &u64::try_from(index).unwrap().to_be_bytes(),
                    );
                    Order {
                        account_id: [u8::try_from(index).unwrap(); 32],
                        side: if is_buy { Side::Buy } else { Side::Sell },
                        limit_price,
                        quantity,
                        nonce: u64::try_from(index).unwrap(),
                        batch_id: 0,
                        expiry: u64::MAX,
                        order_hash,
                        signature: vec![0; 64],
                    }
                })
                .collect();

            let result = clear_auction(&orders, previous_clearing_price).unwrap();
            let expected = reference_result(&orders, previous_clearing_price);
            prop_assert_eq!((result.clearing_price, result.volume), expected);
            let sorted_indices = sorted_order_indices(&orders).unwrap();
            let hash_sorted_indices = hash_sorted_order_indices(&orders).unwrap();
            prop_assert_eq!(
                verify_auction(
                    &orders,
                    &sorted_indices,
                    &hash_sorted_indices,
                    previous_clearing_price,
                    &result,
                ),
                Ok(())
            );

            let mut buy_fills = 0_u128;
            let mut sell_fills = 0_u128;
            for (order, fill) in orders.iter().zip(&result.fills) {
                prop_assert!(*fill <= order.quantity);
                if *fill > 0 {
                    match (result.clearing_price, order.side) {
                        (Some(price), Side::Buy) => prop_assert!(order.limit_price >= price),
                        (Some(price), Side::Sell) => prop_assert!(order.limit_price <= price),
                        (None, _) => prop_assert_eq!(*fill, 0),
                    }
                }
                match order.side {
                    Side::Buy => buy_fills += u128::from(*fill),
                    Side::Sell => sell_fills += u128::from(*fill),
                }
            }
            prop_assert_eq!(buy_fills, result.volume);
            prop_assert_eq!(sell_fills, result.volume);

            let reversed_orders: Vec<Order> = orders.iter().cloned().rev().collect();
            let reversed_result =
                clear_auction(&reversed_orders, previous_clearing_price).unwrap();
            let reversed_sorted_indices = sorted_order_indices(&reversed_orders).unwrap();
            let reversed_hash_sorted_indices = hash_sorted_order_indices(&reversed_orders).unwrap();
            prop_assert_eq!(
                verify_auction(
                    &reversed_orders,
                    &reversed_sorted_indices,
                    &reversed_hash_sorted_indices,
                    previous_clearing_price,
                    &reversed_result,
                ),
                Ok(())
            );
            let fills_by_hash: BTreeMap<_, _> = orders
                .iter()
                .zip(&result.fills)
                .map(|(order, fill)| (order.order_hash, *fill))
                .collect();
            let reversed_fills_by_hash: BTreeMap<_, _> = reversed_orders
                .iter()
                .zip(&reversed_result.fills)
                .map(|(order, fill)| (order.order_hash, *fill))
                .collect();
            prop_assert_eq!(result.clearing_price, reversed_result.clearing_price);
            prop_assert_eq!(result.volume, reversed_result.volume);
            prop_assert_eq!(fills_by_hash, reversed_fills_by_hash);
        }
    }
}
