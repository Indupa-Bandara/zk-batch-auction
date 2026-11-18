use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Side {
    Buy,
    Sell,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Order {
    pub side: Side,
    pub limit_price: u64,
    pub quantity: u64,
    pub order_hash: [u8; 32],
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
    pub orders: Vec<Order>,
    pub sorted_order_indices: Vec<u32>,
    pub hash_sorted_order_indices: Vec<u32>,
    pub previous_clearing_price: Option<u64>,
    pub expected_result: AuctionResult,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuctionPublicValues {
    pub batch_id: u64,
    pub batch_commitment: [u8; 32],
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
}

impl std::fmt::Display for MatchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::DuplicateOrderHash => "duplicate order hash",
            Self::ArithmeticOverflow => "auction arithmetic overflow",
            Self::InvalidAllocation => "invalid auction allocation",
            Self::InvalidWitness => "invalid auction witness",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for MatchError {}

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

    let hash_indices = validate_permutation(orders, hash_sorted_order_indices)?;
    for pair in hash_indices.windows(2) {
        if compare_order_hashes(orders, pair[0], pair[1]).is_gt() {
            return Err(MatchError::InvalidWitness);
        }
        if orders[pair[0]].order_hash == orders[pair[1]].order_hash {
            return Err(MatchError::DuplicateOrderHash);
        }
    }

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

fn compare_orders(orders: &[Order], left: usize, right: usize) -> std::cmp::Ordering {
    let left_order = &orders[left];
    let right_order = &orders[right];
    left_order
        .limit_price
        .cmp(&right_order.limit_price)
        .then_with(|| side_order(left_order.side).cmp(&side_order(right_order.side)))
        .then_with(|| left_order.order_hash.cmp(&right_order.order_hash))
}

fn compare_order_hashes(orders: &[Order], left: usize, right: usize) -> std::cmp::Ordering {
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
    use proptest::prelude::*;
    use std::collections::BTreeMap;

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
                        side: if is_buy { Side::Buy } else { Side::Sell },
                        limit_price,
                        quantity,
                        order_hash,
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
