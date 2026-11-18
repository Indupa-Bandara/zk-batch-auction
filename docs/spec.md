# Auction Rule Specification

## Scope

This document defines the deterministic matching rule for the MVP: one trading
pair, integer price ticks, integer quantity lots, and a single batch at a time.
It specifies matching only; it does not imply token custody or order privacy.

## Orders

Each order contains:

- account identifier
- side: buy or sell
- limit price in ticks
- quantity in lots
- nonce
- batch identifier
- expiry
- signature

Only limit orders are in scope for the initial matcher. Market orders, if added
later, must use explicit configured price bounds rather than unbounded sentinel
values.

An order is eligible only for its specified batch and while unexpired. Signature
and nonce validation are separate acceptance checks; invalid orders are rejected
before matching. The canonical order hash is computed from all signed order
fields, excluding the signature bytes, and is used to break allocation ties.
The signature encoding and hash implementation will be fixed when the signing
format is selected.

## Clearing price

For each candidate tick `p`:

- `D(p)` is the sum of quantities of buy orders with limit price at least `p`.
- `S(p)` is the sum of quantities of sell orders with limit price at most `p`.
- `V(p) = min(D(p), S(p))`.

Candidate ticks are the distinct limit prices present in the valid batch, plus
the previous clearing price if one exists. Demand and supply change only at
order limit prices; including the previous price also lets the distance
tie-break choose it when it lies inside a price interval with unchanged
volume and imbalance.

Choose the candidate with:

1. greatest executable volume `V(p)`;
2. then smallest absolute imbalance `|D(p) - S(p)|`;
3. then smallest distance from the previous batch's clearing price, when one
   exists;
4. then the lower price.

All sums, differences, and distance comparisons use checked integer arithmetic.
If the maximum executable volume is zero, the batch has no clearing price,
volume is zero, and every order has zero fill.

## Allocation

An order can receive a nonzero fill only if its limit price crosses the clearing
price: a buy's limit is at least the clearing price, or a sell's limit is at
most the clearing price.

The side with less eligible quantity is fully filled. If both sides have equal
eligible quantity, both sides are fully filled. If one side has excess
quantity, allocate in price-priority order: higher-priced buys first and
lower-priced sells first. Fill each price level completely while it fits in
the remaining volume. If the next price level is too large, allocate the
remaining volume among orders at that level pro rata by order quantity; orders
at worse price levels receive zero. The marginal level can be strictly better
than the clearing price when better-priced orders alone exceed executable
volume.

For each order at the marginal level, calculate its quota using integer
division:
  `quota = remaining_quantity * order_quantity / total_marginal_quantity`.
Initially assign the floor of each quota. Assign leftover lots one at a time
in descending order of the quota's fractional remainder; break ties by
ascending canonical order hash.

Orders that do not cross the clearing price receive zero. No fill may exceed an
order's quantity. The sum of buy fills and the sum of sell fills must each equal
the selected executable volume.

## Arithmetic and determinism

Prices and quantities are integers; floating-point arithmetic is forbidden.
Notional and intermediate allocation calculations use checked `u128`
arithmetic. Overflow rejects the batch rather than wrapping or saturating.
Input order must not affect the clearing price or fills.

## Golden example

Buys: `10 @ 102`, `5 @ 101`, `8 @ 100`.

Sells: `6 @ 99`, `7 @ 100`, `9 @ 101`.

| Price | Demand | Supply | Executable volume |
|---:|---:|---:|---:|
| 99 | 23 | 6 | 6 |
| 100 | 23 | 13 | 13 |
| 101 | 15 | 22 | 15 |
| 102 | 10 | 22 | 10 |

The clearing price is `101`, with volume `15`. The buy orders at `102` and
`101` fill completely. The sell orders at `99` and `100` fill completely, and
the sell order at `101` fills `2`.

## Required matcher properties

- No fill violates its order's limit price.
- Buy and sell fill totals are equal to the selected volume.
- No order is filled beyond its quantity.
- The selected price maximizes executable volume and obeys all tie-breaks.
- Reordering the same batch does not change the result.
- Any arithmetic overflow rejects the batch.
