# blockseed

A daily random seed that nobody picks: the first Bitcoin block of the UTC day.

Everyone who runs the same code on the same day gets the same 64-bit seed. There is no server,
and nobody can choose the seed cheaply: the miner who finds the daily block could withhold it and
hope for a different one, but only by giving up the block reward (about 3.1 BTC plus fees). The block is read from a public block explorer,
but every header is verified locally before it is used.

## The rule

Header timestamps are not in height order, so "the first block of the day" needs a precise
definition. For UTC day `D` with midnight `M`:

- The **anchor** is the lowest block whose median time past (the median timestamp of the 11
  blocks before it) is at least `M - 3h`.
- The **daily block** is the first block at or above the anchor stamped at or after `M`.

On ordinary days this is simply the first block stamped at or after midnight.

The daily block is adopted once it has 3 blocks on top of it; until then yesterday's stays
current. The seed is

```
seed = u64::from_be_bytes( SHA-256( domain || block_hash )[0..8] )
```

`domain` is your application's own versioned string. `block_hash` is the 32-byte hash in header
order.

[docs/RULE.md](docs/RULE.md) has everything a second implementation needs to get the same block
from headers alone: the exact definitions, the verification steps and the fetch procedure.

## Trust model

### What is verified locally

Each header is checked as follows:

- It is parsed from its 80 bytes and hashed with double SHA-256.
- Its hash is checked against its own claimed target (proof of work).
- The target must be at or below a fixed **difficulty floor**: `bits = 0x171c25a6`, difficulty
  1.0e13. Mainnet was at 1.48e14 in November 2026.
- Each header must point at the hash of the one before it.
- The difficulty may change only at multiples of 2016 blocks, and then by at most 4x.
- Each timestamp must be above the median of the 11 before it.

The 3 confirmations are 3 linked, verified headers on top of the daily block. They are not an
explorer's claimed tip height.

### What one explorer can do on its own

This applies when no second explorer is given, or the second one cannot be reached. A network
attacker can block it; TLS only stops impersonation.

- **Delay or deny.** It can withhold blocks, which turns into an error.
  - It can serve a stale tip, so that yesterday's daily appears current. Key your bookkeeping on
    `outcome.daily.day`.
  - When the second explorer answers, a primary tip more than 6 blocks behind it is an error.
- **Misstate the height.** `daily.height` is the explorer's claim. The seed does not depend on it,
  and only an agreed cross-check backs it.
- **Substitute a different block.** For this it must present a run of linked headers that passes
  every check. Heights are the explorer's claim, so it can build on any real header. The cheapest
  forgery builds on a real 2019 header whose difficulty (about 1e13 to 1.3e13) is already at the
  floor:
  - Its real predecessors supply the low half of the anchor's 11-block lookback for free.
  - Only 10 headers are invented, at that header's difficulty, as the difficulty rule demands:
    6 to lift the median time past over midnight minus 3 hours, the daily, and 3 on top.
  - That is about 4.3e23 to 5.6e23 hashes, roughly 0.7 of a real block's work at November 2026
    difficulty: about 7 minutes of the whole network's hash rate.

  Other routes cost about the same. One is 16 headers invented at the floor (about 6.9e23). The
  other is a daily and 3 confirmations on top of current headers, at a quarter of today's
  difficulty by claiming a retarget height (about 6.4e23).
  - So substitution costs under one block's work, about 4e23 to 7e23 hashes.
  - The floor routes do not grow with mainnet difficulty, so they get relatively cheaper as
    hashing gets cheaper.
  - A real stale block with 3 real blocks on top would also pass, but in practice such blocks do
    not exist.

### What the cross-check adds

The second explorer (blockstream.info, checking mempool.space) must report the same hash at the
daily's height, and a tip no more than 6 blocks ahead of the primary's. Otherwise resolution
fails rather than guess. Substitution then needs both explorers to lie. This cross-check is the
real defence; the proof of work only puts a price on lying.

The result reports the second explorer's verdict in `outcome.cross_check`:

| `outcome.cross_check` | Meaning |
|---|---|
| `Agreed` | Both explorers and the proof of work agree. |
| `Unreachable(_)` | The second explorer could not be reached. |
| `Failed(_)` | The second explorer answered with an error. |
| `NotAsked` | No second explorer was given. |

Anything but `Agreed` (`outcome.cross_checked() == false`) means the result rests on **one
explorer plus the proof of work above**, and nothing more. If that is not enough for you, refuse
such results, or never let one replace a cross-checked result for the same day.

### Why 3 confirmations

A block at or near the tip can still be orphaned, which would leave some users on a different
seed. Waiting for three linked blocks on top makes that very unlikely.

## Use

```rust
use blockseed::resolve::CrossCheck;

// Your application's own versioned domain. Changing it changes every seed.
const DOMAIN: &[u8] = b"myapp-daily-v1";

fn main() -> Result<(), blockseed::Error> {
    // Feature `fetch`: mempool.space, cross-checked on blockstream.info.
    // Blocking (typically a few seconds, at most about 90): use a background thread.
    // Pass the daily you already hold, if any: it saves the walk back to yesterday
    // in the first half hour of each day.
    let known: Option<blockseed::Daily> = None;
    let outcome = blockseed::http::fetch_today_with(DOMAIN, "myapp", known.as_ref())?;
    let d = &outcome.daily;
    println!("day {} block {} seed {:#018x}", d.day, d.height, d.seed);
    if outcome.cross_check != CrossCheck::Agreed {
        println!("not cross-checked: {:?}", outcome.cross_check);
    }
    Ok(())
}
```

`examples/today.rs` is a compiled version of this snippet. `fetch_today(DOMAIN)` is the same with
the default User-Agent, `blockseed`, and no known daily.

To bring your own transport, implement `resolve::Source` and call
`resolve::resolve(DOMAIN, &mut primary, Some(&mut secondary), known)`.

These pure functions work without the network:

- `Header::from_hex`
- `verify_chain`
- `locate_daily` (the rule over timestamps)
- `find_daily`
- `seed_from_hash(domain, &hash)`
- `Daily::from_block(domain, day, &block)`

Each application must use its own versioned, non-empty domain string, for example
`myapp-daily-v1`. This keeps applications from sharing seeds. The domain is hashed into every
seed, so changing it changes all of them: choose it once and bump the version only when you mean
to start over.

## Features

- `fetch` (off by default): blocking HTTPS fetch with `ureq` over rustls and bundled web PKI
  roots (no OpenSSL, no native TLS). Requests time out after 8 s, including DNS and connect, and
  no request is started after 90 s (74 s for the primary, so the cross-check keeps its time).
  A 429 or 503 is retried once, after its `Retry-After` if that is 10 s or less (a longer one is
  not retried) or after 2 s if it has none, and only if the pause fits in that time.

Without it, the crate depends only on `sha2`. `rust-version` is 1.71, the highest declared by
the dependencies (not yet tested on that toolchain).

## Tests

`cargo test --all-features` runs against recorded mainnet headers and mock explorers. It covers:

- Vectors that pin seeds bit for bit.
- A real difficulty adjustment.
- A real midnight whose blocks are stamped out of order.
- Synthetic chains, run through the walk at every tip and with wrong hints, where a block near
  midnight is stamped on the wrong side of it.

The live network test is `#[ignore]`d. Run it with `cargo test --all-features -- --ignored`.

## Used by

Cluster Flock.

## Licence

MIT. Copyright (c) 2026 ForgeSworn.
