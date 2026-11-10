//! A daily random seed that nobody picks: the first Bitcoin block of the UTC day.
//!
//! Nobody can choose it cheaply: the miner who finds the daily block can
//! withhold it and hope for a different one, at the price of the block reward.
//!
//! There is no server. The daily block of a UTC day is read from a public block
//! explorer, but the explorer is only a transport: every header is parsed and
//! checked here (proof of work, difficulty floor, difficulty rule, hash
//! linkage, timestamp rule) before the day rule picks a block. See
//! `docs/RULE.md`.
//!
//! * [`Header`], [`Block`], [`verify_chain`]: parsing and verification.
//! * [`locate_daily`]: the day rule on the timestamps of consecutive blocks;
//!   [`find_daily`] runs it on a verified run of blocks.
//! * [`seed_from_hash`]: the 64-bit seed of a block, under your domain string.
//! * [`resolve`](resolve::resolve): the whole procedure over a [`resolve::Source`].
//! * `http` (feature `fetch`): the blocking HTTPS fetch.
//!
//! # The domain string
//!
//! Every function that derives a seed takes a `domain: &[u8]`. Each application
//! must use its own, versioned, non-empty domain string (for example
//! `b"myapp-daily-v1"`), so that two applications never share seeds. The domain
//! is hashed into every seed: **changing it changes every seed**, past and
//! future. Pick it once and bump the version only when you mean to start over.
//!
//! # Which day
//!
//! A resolution returns the current daily, which is yesterday's until today's
//! has [`CONFIRMATIONS`] blocks on top of it. Key your bookkeeping on
//! [`Daily::day`], never on your own clock.

use sha2::{Digest, Sha256};
use std::fmt;

pub mod resolve;
#[cfg(feature = "fetch")]
pub mod http;

/// Seconds in a UTC day.
pub const DAY_SECS: u64 = 86_400;
/// Blocks in a median time past: the median of the timestamps of the 11
/// blocks before a block.
pub const MTP_BLOCKS: usize = 11;
/// The anchor of a day is the first block whose median time past is at least
/// midnight minus this many seconds (3 hours).
pub const ANCHOR_LEAD_SECS: u64 = 3 * 3600;
/// Linked blocks that must sit on top of a daily block before it is adopted.
pub const CONFIRMATIONS: usize = 3;
/// Blocks between difficulty adjustments.
const RETARGET_INTERVAL: u32 = 2016;

/// The easiest target a header may claim, as compact `bits`.
///
/// It is the target of difficulty 1.0e13 (`0xffff * 2^208 / 1e13`, rounded down
/// by the compact encoding, so the real difficulty is a hair above 1e13).
/// Mainnet difficulty was 1.48e14 in November 2026; one header at the floor
/// costs about 4.3e22 hashes. The floor stops an explorer from inventing
/// headers with an easy target; it is not a proof that the chain is the
/// heaviest one.
pub const FLOOR_BITS: u32 = 0x171c_25a6;

/// A descriptive failure. Nothing here panics on bad network input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A header or hash was not valid hex of the right length.
    BadEncoding(String),
    /// `bits` is zero, negative, overflows 256 bits or decodes to a zero target.
    BadBits(u32),
    /// The header hash is above its own target.
    PowFailed { height: u32 },
    /// The target is easier than [`FLOOR_BITS`].
    TargetTooEasy { height: u32 },
    /// Header `height` does not point at the hash of header `height - 1`.
    BrokenLink { height: u32 },
    /// The difficulty changes where it may not: `bits` differs from the previous
    /// header's away from a multiple of 2016, or changes by more than 4x at one.
    DifficultyChange { height: u32 },
    /// The header's timestamp is not above the median of its 11 predecessors.
    TimeTooEarly { height: u32 },
    /// Heights in a run of blocks are not consecutive, or the run is empty.
    BadWindow(String),
    /// The explorer returned a header whose hash is not the hash it was asked for.
    WrongHeader,
    /// A day number whose midnight does not fit the arithmetic.
    DayOutOfRange(u64),
    /// The seed domain is empty.
    EmptyDomain,
    /// Neither today's nor yesterday's daily block is confirmed yet.
    NoDailyBlock,
    /// The two explorers disagree about the hash at the chosen height.
    CrossCheckMismatch { height: u32 },
    /// The primary explorer's tip is more than 6 blocks behind the second one's.
    PrimaryBehind { primary: u32, secondary: u32 },
    /// The request budget ([`resolve::MAX_REQUESTS`]) ran out.
    TooManyRequests,
    /// A source could not be reached: connection, TLS, timeout.
    Network { source: String, what: String },
    /// A source answered with an HTTP error status.
    Http { source: String, status: u16 },
    /// A source answered, but not in the documented format.
    BadResponse { source: String, what: String },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadEncoding(s) => write!(f, "bad encoding: {s}"),
            Error::BadBits(b) => write!(f, "invalid difficulty bits {b:#010x}"),
            Error::PowFailed { height } => write!(f, "block {height}: hash is above its target"),
            Error::TargetTooEasy { height } => write!(f, "block {height}: target is easier than the floor"),
            Error::BrokenLink { height } => write!(f, "block {height}: does not follow the previous header"),
            Error::DifficultyChange { height } => write!(f, "block {height}: difficulty changes where it may not"),
            Error::TimeTooEarly { height } => write!(f, "block {height}: timestamp is not above the median time past"),
            Error::BadWindow(s) => write!(f, "bad run of headers: {s}"),
            Error::WrongHeader => write!(f, "explorer returned a header that does not match its hash"),
            Error::DayOutOfRange(d) => write!(f, "day {d} is out of range"),
            Error::EmptyDomain => write!(f, "the seed domain is empty"),
            Error::NoDailyBlock => write!(f, "no confirmed daily block found"),
            Error::CrossCheckMismatch { height } => write!(f, "explorers disagree about block {height}"),
            Error::PrimaryBehind { primary, secondary } => {
                write!(f, "primary explorer's tip {primary} is far behind the second one's {secondary}")
            }
            Error::TooManyRequests => write!(f, "request budget exhausted"),
            Error::Network { source, what } => write!(f, "{source}: {what}"),
            Error::Http { source, status } => write!(f, "{source}: HTTP {status}"),
            Error::BadResponse { source, what } => write!(f, "{source}: unexpected response ({what})"),
        }
    }
}

impl std::error::Error for Error {}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Lower-case hex of `bytes`.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 15) as usize] as char);
    }
    s
}

/// Hex to bytes. Accepts upper and lower case, rejects odd lengths and junk.
pub(crate) fn from_hex(s: &str) -> Result<Vec<u8>, Error> {
    let s = s.trim();
    let bad = || Error::BadEncoding(format!("not hex ({} chars)", s.len()));
    if s.len() % 2 != 0 || !s.is_ascii() {
        return Err(bad());
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    s.as_bytes()
        .chunks(2)
        .map(|p| Some(nib(p[0])? << 4 | nib(p[1])?))
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(bad)
}

/// A block hash as explorers display it (byte-reversed) to the 32 bytes in
/// header order (the output of double SHA-256).
pub fn hash_from_display(s: &str) -> Result<[u8; 32], Error> {
    let mut v = from_hex(s)?;
    if v.len() != 32 {
        return Err(Error::BadEncoding(format!("hash is {} bytes, not 32", v.len())));
    }
    v.reverse();
    Ok(v.try_into().unwrap())
}

/// A hash in header order to the displayed (byte-reversed) hex.
pub fn hash_to_display(h: &[u8; 32]) -> String {
    let mut r = *h;
    r.reverse();
    to_hex(&r)
}

/// An 80-byte Bitcoin block header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Header(pub [u8; 80]);

impl Header {
    pub fn from_hex(s: &str) -> Result<Header, Error> {
        let v = from_hex(s)?;
        let a: [u8; 80] = v
            .try_into()
            .map_err(|v: Vec<u8>| Error::BadEncoding(format!("header is {} bytes, not 80", v.len())))?;
        Ok(Header(a))
    }

    /// The previous block's hash, in header order.
    pub fn prev(&self) -> [u8; 32] {
        self.0[4..36].try_into().unwrap()
    }

    /// The header timestamp, seconds since the Unix epoch.
    pub fn time(&self) -> u32 {
        u32::from_le_bytes(self.0[68..72].try_into().unwrap())
    }

    /// The compact difficulty target.
    pub fn bits(&self) -> u32 {
        u32::from_le_bytes(self.0[72..76].try_into().unwrap())
    }

    /// The block hash, double SHA-256, in header order.
    pub fn hash(&self) -> [u8; 32] {
        sha256(&sha256(&self.0))
    }

    /// The block hash as explorers display it.
    pub fn hash_display(&self) -> String {
        hash_to_display(&self.hash())
    }
}

/// The 256-bit big-endian target of compact `bits`.
pub(crate) fn compact_to_target(bits: u32) -> Result<[u8; 32], Error> {
    let exp = (bits >> 24) as usize;
    let mant = bits & 0x007f_ffff;
    if bits & 0x0080_0000 != 0 || mant == 0 {
        return Err(Error::BadBits(bits));
    }
    // Value = mant * 256^(exp-3). Byte i of the mantissa (0 = least significant)
    // lands at little-endian position (exp - 3 + i).
    let mut le = [0u8; 32];
    for i in 0..3usize {
        let byte = ((mant >> (8 * i)) & 0xff) as u8;
        if byte == 0 {
            continue;
        }
        let pos = (exp as isize) - 3 + i as isize;
        if pos < 0 {
            continue; // shifted out below the units digit
        }
        if pos >= 32 {
            return Err(Error::BadBits(bits));
        }
        le[pos as usize] = byte;
    }
    if le == [0u8; 32] {
        return Err(Error::BadBits(bits)); // every mantissa byte was shifted out
    }
    le.reverse();
    Ok(le)
}

/// The floor target ([`FLOOR_BITS`]).
pub(crate) fn floor_target() -> [u8; 32] {
    compact_to_target(FLOOR_BITS).expect("floor bits are valid")
}

/// A 256-bit unsigned number as (high, low) halves, enough for the retarget bounds.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct U256(u128, u128);

impl U256 {
    fn from_be(b: &[u8; 32]) -> U256 {
        U256(u128::from_be_bytes(b[..16].try_into().unwrap()), u128::from_be_bytes(b[16..].try_into().unwrap()))
    }
    /// `self << n` for `0 < n < 128`, saturating at 2^256 - 1.
    fn shl(self, n: u32) -> U256 {
        if self.0 >> (128 - n) != 0 {
            return U256(u128::MAX, u128::MAX);
        }
        U256(self.0 << n | self.1 >> (128 - n), self.1 << n)
    }
    /// `self >> n` for `0 < n < 128`.
    fn shr(self, n: u32) -> U256 {
        U256(self.0 >> n, self.1 >> n | self.0 << (128 - n))
    }
    /// `self + o`, saturating.
    fn add(self, o: U256) -> U256 {
        let (lo, c) = self.1.overflowing_add(o.1);
        match self.0.checked_add(o.0).and_then(|h| h.checked_add(c as u128)) {
            Some(hi) => U256(hi, lo),
            None => U256(u128::MAX, u128::MAX),
        }
    }
}

/// The difficulty rule between a header at `height` and its predecessor.
///
/// Away from a multiple of 2016 the `bits` must be equal. At a multiple of 2016
/// the new target may be at most 4 times the old one (easier) and at least a
/// quarter of it (harder), less the rounding of the compact encoding (which
/// loses under 2^-15 of the value; 2^-16 of the old target plus one is allowed).
pub(crate) fn check_difficulty_step(height: u32, prev_bits: u32, bits: u32) -> Result<(), Error> {
    if height % RETARGET_INTERVAL != 0 {
        return if bits == prev_bits { Ok(()) } else { Err(Error::DifficultyChange { height }) };
    }
    let old = U256::from_be(&compact_to_target(prev_bits)?);
    let new = U256::from_be(&compact_to_target(bits)?);
    let easiest = old.shl(2);
    let slack = old.shr(16).add(U256(0, 1));
    if new > easiest || new.add(slack) < old.shr(2) {
        return Err(Error::DifficultyChange { height });
    }
    Ok(())
}

/// A header with its height.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Block {
    pub height: u32,
    pub header: Header,
}

/// Check one header on its own: valid bits, target at or below the floor,
/// hash at or below the target.
pub fn check_header(height: u32, h: &Header) -> Result<(), Error> {
    let target = compact_to_target(h.bits())?;
    if target > floor_target() {
        return Err(Error::TargetTooEasy { height });
    }
    let mut hash = h.hash();
    hash.reverse(); // big-endian number
    if hash > target {
        return Err(Error::PowFailed { height });
    }
    Ok(())
}

/// The median of the timestamps of the [`MTP_BLOCKS`] blocks before a block
/// (`prev` holds exactly those, in height order). This is Bitcoin Core's
/// median time past of the block's parent (`pindexPrev->GetMedianTimePast()`),
/// which Esplora explorers report as the parent's `mediantime`.
fn median_time_past(prev: &[u32]) -> u32 {
    debug_assert_eq!(prev.len(), MTP_BLOCKS);
    let mut v = [0u32; MTP_BLOCKS];
    v.copy_from_slice(prev);
    v.sort_unstable();
    v[MTP_BLOCKS / 2]
}

/// Consensus requires every block's timestamp to be above its median time
/// past. Checked for every block of the run that has its 11 predecessors in it.
fn check_time_order(blocks: &[Block]) -> Result<(), Error> {
    let times: Vec<u32> = blocks.iter().map(|b| b.header.time()).collect();
    for i in MTP_BLOCKS..times.len() {
        if times[i] <= median_time_past(&times[i - MTP_BLOCKS..i]) {
            return Err(Error::TimeTooEarly { height: blocks[i].height });
        }
    }
    Ok(())
}

/// Verify a run of consecutive blocks: heights step by one, every header
/// passes [`check_header`], every header points at the hash of the one before
/// it, `bits` follow the difficulty rule (equal to the predecessor's except at
/// multiples of 2016, where the target moves by at most 4x), and every
/// timestamp is above the median of its 11 predecessors where they are in the
/// run.
pub fn verify_chain(blocks: &[Block]) -> Result<(), Error> {
    if blocks.is_empty() {
        return Err(Error::BadWindow("empty".into()));
    }
    for (i, b) in blocks.iter().enumerate() {
        check_header(b.height, &b.header)?;
        if i > 0 {
            let p = &blocks[i - 1];
            if p.height.checked_add(1) != Some(b.height) {
                return Err(Error::BadWindow(format!("heights {} then {}", p.height, b.height)));
            }
            if b.header.prev() != p.header.hash() {
                return Err(Error::BrokenLink { height: b.height });
            }
            check_difficulty_step(b.height, p.header.bits(), b.header.bits())?;
        }
    }
    check_time_order(blocks)
}

/// The UTC day number of a Unix time.
pub fn day_of(t: u64) -> u64 {
    t / DAY_SECS
}

/// Where the daily block of a day sits in a run of consecutive blocks, from
/// [`locate_daily`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Locate {
    /// The run does not reach far enough down to prove which block is the
    /// anchor: it needs earlier blocks.
    NeedEarlier,
    /// The anchor or the daily block lies above the run: it needs later blocks.
    NeedLater,
    /// Indices into the run of the day's anchor and of its daily block.
    Found { anchor: usize, daily: usize },
}

/// The day rule, on the timestamps of consecutive blocks (lowest height first).
///
/// With `M = day * 86400` and `MTP(B)` the median of the timestamps of the 11
/// blocks before `B`:
///
/// * the **anchor** `A` is the lowest-height block with `MTP(A) >= M - 3h`;
/// * the **daily block** is the lowest-height block at or above `A` whose own
///   timestamp is `>= M`.
///
/// Consensus makes every timestamp exceed its MTP, so MTP never decreases
/// along the chain and the anchor is unique. The run proves the anchor only
/// when the block below it is in the run with its own 11 predecessors, so a
/// run must start at least 12 blocks below the anchor. Only timestamps are
/// read; verifying the blocks is the caller's job (see [`find_daily`]).
pub fn locate_daily(times: &[u32], day: u64) -> Result<Locate, Error> {
    let midnight = day.checked_mul(DAY_SECS).ok_or(Error::DayOutOfRange(day))?;
    let threshold = midnight.checked_sub(ANCHOR_LEAD_SECS).ok_or(Error::DayOutOfRange(day))?;
    if times.len() <= MTP_BLOCKS {
        return Ok(Locate::NeedEarlier);
    }
    let reaches = |i: usize| median_time_past(&times[i - MTP_BLOCKS..i]) as u64 >= threshold;
    if reaches(MTP_BLOCKS) {
        // The anchor is this block or lower, and the run cannot show which.
        return Ok(Locate::NeedEarlier);
    }
    let Some(anchor) = (MTP_BLOCKS + 1..times.len()).find(|&i| reaches(i)) else {
        return Ok(Locate::NeedLater);
    };
    match (anchor..times.len()).find(|&i| times[i] as u64 >= midnight) {
        Some(daily) => Ok(Locate::Found { anchor, daily }),
        None => Ok(Locate::NeedLater),
    }
}

/// [`verify_chain`], then [`locate_daily`] on the run's timestamps.
pub fn find_daily(blocks: &[Block], day: u64) -> Result<Locate, Error> {
    verify_chain(blocks)?;
    let times: Vec<u32> = blocks.iter().map(|b| b.header.time()).collect();
    locate_daily(&times, day)
}

/// The seed of a block: the first 8 bytes of `SHA-256(domain || hash)`,
/// big-endian, where `hash` is the 32-byte block hash in header order (not the
/// displayed, reversed form).
///
/// `domain` is your application's own versioned domain string; changing it
/// changes every seed. This function is pure and accepts any domain; the
/// resolving functions refuse an empty one.
pub fn seed_from_hash(domain: &[u8], hash: &[u8; 32]) -> u64 {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(hash);
    let d = h.finalize();
    u64::from_be_bytes(d[..8].try_into().unwrap())
}

/// A resolved daily.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Daily {
    /// UTC day number (`floor(t / 86400)`) this block is the daily of. Key on
    /// this: it is yesterday's day until today's daily is confirmed.
    pub day: u64,
    /// The block height, the daily's public number. It is the explorer's
    /// claim; the seed does not depend on it, and only a cross-check that
    /// agreed (the second explorer has this hash at this height) backs it.
    pub height: u32,
    /// The block hash as explorers display it.
    pub hash_hex: String,
    /// The seed, derived under the caller's domain string.
    pub seed: u64,
}

impl Daily {
    /// The daily of `day` from its block, with the seed under `domain`.
    pub fn from_block(domain: &[u8], day: u64, b: &Block) -> Daily {
        let h = b.header.hash();
        Daily { day, height: b.height, hash_hex: hash_to_display(&h), seed: seed_from_hash(domain, &h) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_examples() {
        // Genesis: 0x1d00ffff = 0xffff * 2^208.
        let t = compact_to_target(0x1d00ffff).unwrap();
        assert_eq!(to_hex(&t), "00000000ffff0000000000000000000000000000000000000000000000000000");
        assert!(compact_to_target(0).is_err());
        assert!(compact_to_target(0x0480_0001).is_err(), "negative");
        assert!(compact_to_target(0x2301_0000).is_err(), "overflow");
        assert_eq!(compact_to_target(0x0100_0100), Err(Error::BadBits(0x0100_0100)), "shifted out to zero");
        assert_eq!(compact_to_target(0x0201_0000).unwrap()[30], 1, "0x010000 / 256 = 0x0100");
    }

    #[test]
    fn floor_is_difficulty_1e13_or_harder() {
        // diff1 / 1e13 as hex, from an independent calculation.
        let f = floor_target();
        assert!(to_hex(&f).starts_with("0000000000000000001c25a6"), "{}", to_hex(&f));
        // Mainnet difficulty in 2026 (bits 0x1701e5ac) is far harder than the floor.
        assert!(compact_to_target(0x1701e5ac).unwrap() < f);
    }

    #[test]
    fn seed_vector() {
        // Block 974869, displayed hash.
        let h = hash_from_display("0000000000000000000123e050878a33503aca65df86ca668fca2ec493b46f79").unwrap();
        assert_eq!(h[0], 0x79, "header order is the reverse of the display");
        // Expected values computed independently with a separate SHA-256.
        assert_eq!(seed_from_hash(b"blockseed-example-v1", &h), 0xefb663922ade8b7f);
        assert_eq!(seed_from_hash(b"blockseed-example-v1", &[0u8; 32]), 0xe80c8bc14d09166d);
        assert_ne!(seed_from_hash(b"blockseed-example-v2", &h), seed_from_hash(b"blockseed-example-v1", &h));
    }

    #[test]
    fn hex_round_trip_and_junk() {
        assert_eq!(from_hex("00ffAb").unwrap(), vec![0, 255, 0xab]);
        assert!(from_hex("abc").is_err());
        assert!(from_hex("zz").is_err());
        assert!(Header::from_hex("00").is_err());
        assert!(hash_from_display("00").is_err());
    }

    /// Bitcoin Core's `GetCompact` for a big-endian 256-bit value.
    fn get_compact(v: &[u8; 32]) -> u32 {
        let size = 32 - v.iter().take_while(|b| **b == 0).count();
        let byte = |i: usize| if i < size { v[32 - size + i] as u32 } else { 0 };
        let mut mant = byte(0) << 16 | byte(1) << 8 | byte(2);
        let mut size = size as u32;
        if mant & 0x0080_0000 != 0 {
            mant >>= 8;
            size += 1;
        }
        mant | size << 24
    }

    fn quarter(bits: u32) -> [u8; 32] {
        // floor(target / 4), as Core computes a fully clamped harder retarget.
        let t = U256::from_be(&compact_to_target(bits).unwrap()).shr(2);
        let mut b = [0u8; 32];
        b[..16].copy_from_slice(&t.0.to_be_bytes());
        b[16..].copy_from_slice(&t.1.to_be_bytes());
        b
    }

    #[test]
    fn difficulty_rule() {
        let real = 0x1701_e5ac;
        // Away from a retarget height the bits must not change at all.
        assert_eq!(check_difficulty_step(973_729, real, real), Ok(()));
        assert_eq!(check_difficulty_step(973_729, real, real + 1), Err(Error::DifficultyChange { height: 973_729 }));
        // At a retarget height: up to 4x easier, up to 4x harder.
        let h = 2016 * 483;
        assert_eq!(check_difficulty_step(h, 0x1702_0093, real), Ok(()), "the real retarget at 973728");
        assert_eq!(check_difficulty_step(h, real, 0x1707_96b0), Ok(()), "exactly 4x easier");
        assert_eq!(check_difficulty_step(h, real, 0x1707_96b1), Err(Error::DifficultyChange { height: h }));
        assert_eq!(check_difficulty_step(h, real, FLOOR_BITS), Err(Error::DifficultyChange { height: h }));
        // A full 4x harder retarget, rounded down by the compact encoding, passes.
        for old in [real, 0x1702_0093, 0x1800_8001, 0x1d00_ffff] {
            let q = get_compact(&quarter(old));
            assert_eq!(check_difficulty_step(h, old, q), Ok(()), "{old:#x} -> {q:#x}");
        }
        // Clearly more than 4x harder does not.
        assert_eq!(check_difficulty_step(h, real, 0x1700_7000), Err(Error::DifficultyChange { height: h }));
    }

    #[test]
    fn median_time_past_is_the_sixth_of_eleven() {
        let t = [9, 1, 8, 2, 7, 3, 6, 4, 5, 11, 10];
        assert_eq!(median_time_past(&t), 6);
    }

    #[test]
    fn day_arithmetic_is_checked() {
        assert_eq!(locate_daily(&[0; 20], u64::MAX), Err(Error::DayOutOfRange(u64::MAX)));
        assert_eq!(locate_daily(&[0; 20], 0), Err(Error::DayOutOfRange(0)));
        assert_eq!(locate_daily(&[0; 11], 1), Ok(Locate::NeedEarlier));
    }

    /// Times spaced 600 s, block `y` at midnight + 300.
    fn honest(n: usize, y: usize, mid: u64) -> Vec<u32> {
        (0..n).map(|i| (mid as i64 + 300 + 600 * (i as i64 - y as i64)) as u32).collect()
    }

    #[test]
    fn locate_on_a_regular_chain() {
        let day = 20764;
        let mid = day * DAY_SECS;
        let t = honest(60, 40, mid);
        // MTP(i) = t[i-6]; it reaches mid - 3h at i = 40 - 12.
        assert_eq!(locate_daily(&t, day), Ok(Locate::Found { anchor: 28, daily: 40 }));
        // The run must start 12 blocks below the anchor, at 16; from 17 the
        // anchor's predecessor lacks its lookback.
        assert_eq!(locate_daily(&t[16..], day), Ok(Locate::Found { anchor: 12, daily: 24 }));
        assert_eq!(locate_daily(&t[17..], day), Ok(Locate::NeedEarlier));
        // Ending before the daily block.
        assert_eq!(locate_daily(&t[..40], day), Ok(Locate::NeedLater));
        // Ending before the anchor.
        assert_eq!(locate_daily(&t[..28], day), Ok(Locate::NeedLater));
    }
}
