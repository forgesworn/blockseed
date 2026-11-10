# The rule

Everything a second implementation needs to pick the same block, from block headers alone, and
derive the same seed.

## Day, anchor and daily block

- The day number is `D = floor(t / 86400)`, with `t` a Unix time (UTC). Its midnight is
  `M = D * 86400`.
- `MTP(B)`, the median time past of block `B`, is the median of the timestamps of the **11 blocks
  before `B`** (heights `h-11 ..= h-1`; `B` itself is not included). This is Bitcoin Core's
  median time past of `B`'s parent (`pindexPrev->GetMedianTimePast()`), which Esplora explorers
  report as the parent's `mediantime`. It is not `B`'s own `mediantime`.
- The **anchor** `A` of day `D` is the lowest-height block with `MTP(A) >= M - 10800`
  (midnight minus 3 hours).
- The **daily block** of day `D` is the lowest-height block at or above `A` whose own header
  timestamp is `>= M`.

The anchor is unique. Consensus requires every block's timestamp to be greater than its
`MTP`, so `MTP` never decreases along the chain. Every block below `A` has `MTP < M - 10800`, and
every block from `A` up has `MTP >= M - 10800`. To prove that a block is the anchor, a verifier
needs that block, the block below it, and the 11 predecessors of each. That is a run starting 12
blocks below `A`.

Header timestamps are not in height order. A block mined before midnight can carry a timestamp
after it, and the reverse also happens. Because of the anchor, a block below `A` is never the
daily block, even if it is stamped after midnight; such a block was mined roughly two or more
hours before midnight. So the answer does not depend on how far back anyone looks, or on when
they look. On ordinary days the daily block is simply the first block stamped at or after
midnight; this held on every day from 2026-10-10 to 2026-11-09.

- The **current daily** is the daily block of `D` once it has at least **3 blocks on top of it**,
  linked to it by hash. Until then it is the daily block of `D - 1`.
- "Now" is the timestamp of the chain tip, never the local clock. Since timestamps are not in
  order, a tip stamped before midnight makes "now" the previous day for as long as it is the tip,
  even when today's daily block is already confirmed below it; the next tip moves it forward
  again. Callers should never move back to an older day (key on the day number).
- The daily's public number is the block **height**.

## Verification (the explorer is untrusted)

Every header is checked as follows:

1. Parse the 80 bytes. The block hash is the double SHA-256 of the header (explorers display it
   byte-reversed). A header fetched by hash must hash to that hash.
2. Decode compact `bits` to a 256-bit target. Reject zero, negative and overflowing values, and
   any value whose mantissa shifts out to a zero target.
3. Require `hash <= target` (proof of work).
4. Require `target <=` the **floor target**, `FLOOR_BITS = 0x171c25a6`. This is the target of
   difficulty 1.0e13 (about `0000000000000000001c25a6...`). Mainnet difficulty was 1.48e14 in
   November 2026.

The headers walked are then checked against each other:

5. Every header's previous-hash must equal the hash of the header before it.
6. Difficulty rule. A header's `bits` must equal its predecessor's, except at heights that are a
   multiple of 2016. There the new target may be at most 4 times the old one and at least a
   quarter of it. For the compact encoding's rounding, the lower bound allows `(old >> 16) + 1`
   below `old / 4`.
7. Timestamp rule. Every header whose 11 predecessors are in the walked run must have a timestamp
   greater than their median.

Any failure is an error, never a reason to fall back to another day.

## Seed

```
seed = u64::from_be_bytes( SHA-256( domain || block_hash )[0..8] )
```

- `domain` is the application's own versioned byte string, and must not be empty.
- `block_hash` is the 32 bytes in header order (the double-SHA-256 output, not the reversed
  display form).

Worked example: block 974869 has displayed hash
`0000000000000000000123e050878a33503aca65df86ca668fca2ec493b46f79`. Under the domain
`blockseed-example-v1` its seed is `0xefb663922ade8b7f`.

## Fetch

The library makes blocking Esplora REST calls with these limits:

- At most 120 requests to the primary explorer per resolution, plus 2 to the second.
- 8 s per request, which also bounds DNS and the TCP connect.
- No request to the primary is started after 74 s, and none to the second after 90 s (the
  last 16 s are kept for the cross-check).
- Redirects off, bodies capped at 4 KiB.

The calls are:

- `GET /blocks/tip/height`
- `GET /block-height/:height` (hash, plain text)
- `GET /block/:hash/header` (80-byte header, hex)
- `GET /v1/mining/blocks/timestamp/:ts` (mempool.space only; JSON with `height`, the last block
  stamped at or before `ts`)

Procedure:

1. Fetch the tip height, the tip hash and the tip header, and verify the header. Take `D` from the
   tip's timestamp.
2. Ask for the hint at `M`. Start at height `min(hint + 4, tip)`.
3. Grow a run of linked headers from there:
   - Downwards, by each header's previous-hash.
   - Upwards, by height, checking that each new header links to the one below. At the tip height,
     use the tip header from step 1.
4. Stop when the run decides the day. Either it starts at least 12 blocks below the anchor and
   holds the daily block with 3 blocks above it, or it reaches the tip without that ("not yet").
   The hint only picks the starting point. A wrong hint costs requests, and if it is far off it
   exhausts the budget (an error), but it never changes the block.
5. Verify the whole run (checks 1 to 7).
6. If today is "not yet", repeat once for `D - 1`. The caller may supply a daily it already holds;
   if that is the daily of `D - 1` it is used instead of walking yesterday again (it is still
   cross-checked in step 7). If `D - 1` is "not yet" as well, that is an error (`NoDailyBlock`).
7. Cross-check, if a second explorer is given:
   - Ask it for its tip height. A primary tip more than 6 blocks behind it is an error.
   - Ask it for the hash at the daily's height. A different hash is an error.
   - If the second explorer cannot be reached, or answers badly, the result is still returned,
     with that reported.

On late-2026 mainnet, one day attempt is estimated at 22 to 37 requests (a model over 31 days;
one live run took 24 in total).
