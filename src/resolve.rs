//! The procedure: tip, day, hint, walk, verify, rule, cross-check.
//!
//! It runs over a [`Source`] so that it can be tested against recorded
//! mainnet headers; the `http` module (feature `fetch`) has the real one.

use crate::{
    check_header, day_of, hash_from_display, locate_daily, verify_chain, Block, Daily, Error, Header, Locate, CONFIRMATIONS, DAY_SECS,
};

/// Most requests one resolution may make to the primary source. A day attempt
/// takes about 30 (22 to 37 estimated over 31 days of late-2026 mainnet), one
/// fallback to yesterday doubles that, and the tip takes 3: 2 x 37 + 3 = 77 on
/// the worst of those days. 120 leaves room for a slow evening (many blocks between the anchor and
/// midnight) or a hint that is off by a dozen blocks. The second source gets
/// 2 more, outside this budget, so the primary cannot use them up.
pub const MAX_REQUESTS: u32 = 120;
/// The primary's tip may be at most this many blocks behind the second source's.
pub const MAX_TIP_LAG: u32 = 6;

/// The four Esplora calls the procedure needs. Everything a source returns is
/// untrusted and is checked by the caller.
pub trait Source {
    /// A short name for error messages.
    fn name(&self) -> &str;
    /// `GET /blocks/tip/height`.
    fn tip_height(&mut self) -> Result<u32, Error>;
    /// `GET /block-height/:height`: the hash in header order.
    fn hash_at(&mut self, height: u32) -> Result<[u8; 32], Error>;
    /// `GET /block/:hash/header`.
    fn header(&mut self, hash: &[u8; 32]) -> Result<Header, Error>;
    /// `GET /v1/mining/blocks/timestamp/:ts`: the height of the last block
    /// stamped at or before `ts`. Only a starting point for the walk: a wrong
    /// hint costs requests, never a different answer.
    fn height_hint(&mut self, ts: u64) -> Result<u32, Error>;
}

/// What the second source said.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CrossCheck {
    /// It has the daily's hash at the daily's height, and its tip is not more
    /// than [`MAX_TIP_LAG`] blocks ahead of the primary's.
    Agreed,
    /// No second source was given.
    NotAsked,
    /// It could not be reached (connection, TLS, timeout).
    Unreachable(Error),
    /// It answered, but with an HTTP error or something unparseable.
    Failed(Error),
}

/// A resolved daily and how sure we are of it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Outcome {
    /// The current daily. Key on `daily.day`: it is yesterday's day until
    /// today's daily block has [`CONFIRMATIONS`] blocks on top.
    pub daily: Daily,
    /// The second source's verdict.
    pub cross_check: CrossCheck,
    /// Requests made, both sources together.
    pub requests: u32,
}

impl Outcome {
    /// The second source agreed. Without it the result rests on one explorer
    /// plus the proof of work of the headers (see the trust model in the README),
    /// and `daily.height` is that explorer's unchecked claim.
    pub fn cross_checked(&self) -> bool {
        self.cross_check == CrossCheck::Agreed
    }
}

/// A day attempt either finds a confirmed daily or proves that it is not
/// there yet. Any failure to verify is an `Err`, never a `NotYet`.
#[derive(Debug)]
enum Attempt {
    /// `segment[daily]` is the daily block, with at least [`CONFIRMATIONS`]
    /// linked blocks above it in `segment`.
    Ready { segment: Vec<Block>, daily: usize },
    /// The segment reaches the verified tip and still has no daily block with
    /// enough confirmations.
    NotYet { segment: Vec<Block> },
}

impl Attempt {
    fn segment(&self) -> &[Block] {
        match self {
            Attempt::Ready { segment, .. } | Attempt::NotYet { segment } => segment,
        }
    }
}

/// Where a day attempt gets its blocks.
trait Walk {
    /// The block the explorer has at `height`.
    fn at(&mut self, height: u32) -> Result<Block, Error>;
    /// The parent of `b`, fetched by `b`'s previous-hash (linked by construction).
    fn below(&mut self, b: &Block) -> Result<Block, Error>;
}

/// Grow a segment of linked blocks around the hint until the day rule can
/// decide. The start is a few blocks above the hint (the hint is the last block
/// before midnight, and going down is cheaper than going up), clamped at the
/// tip. Down: by previous-hash. Up: by height, each block checked to link to
/// the one below; at the tip height the verified tip itself is used, so a
/// `NotYet` is always a segment linked to the tip.
fn attempt_day(w: &mut dyn Walk, day: u64, hint: u32, tip: &Block) -> Result<Attempt, Error> {
    let start = hint.saturating_add(CONFIRMATIONS as u32 + 1).min(tip.height);
    let first = if start == tip.height { *tip } else { w.at(start)? };
    let mut segment = vec![first];
    loop {
        let times: Vec<u32> = segment.iter().map(|b| b.header.time()).collect();
        let top = *segment.last().unwrap();
        let up = match locate_daily(&times, day)? {
            Locate::NeedEarlier => false,
            Locate::Found { daily, .. } if segment.len() - 1 - daily >= CONFIRMATIONS => {
                return Ok(Attempt::Ready { segment, daily });
            }
            Locate::Found { .. } | Locate::NeedLater => true,
        };
        if up {
            if top.height >= tip.height {
                return Ok(Attempt::NotYet { segment });
            }
            let h = top.height + 1;
            let next = if h == tip.height { *tip } else { w.at(h)? };
            if next.height != h || next.header.prev() != top.header.hash() {
                return Err(Error::BrokenLink { height: h });
            }
            segment.push(next);
        } else {
            let low = segment[0];
            if low.height == 0 {
                return Err(Error::BadWindow("the walk reached height 0".into()));
            }
            let p = w.below(&low)?;
            if p.height.checked_add(1) != Some(low.height) || p.header.hash() != low.header.prev() {
                return Err(Error::BrokenLink { height: low.height });
            }
            segment.insert(0, p);
        }
    }
}

struct Budget {
    used: u32,
}

impl Budget {
    fn spend(&mut self) -> Result<(), Error> {
        if self.used >= MAX_REQUESTS {
            return Err(Error::TooManyRequests);
        }
        self.used += 1;
        Ok(())
    }
}

/// The real walk: every header fetched by hash, bound to that hash, and
/// checked for proof of work and the floor as it arrives.
struct Fetch<'a> {
    src: &'a mut dyn Source,
    budget: Budget,
}

impl Fetch<'_> {
    fn header(&mut self, hash: &[u8; 32], height: u32) -> Result<Block, Error> {
        self.budget.spend()?;
        let header = self.src.header(hash)?;
        if &header.hash() != hash {
            return Err(Error::WrongHeader);
        }
        check_header(height, &header)?;
        Ok(Block { height, header })
    }
}

impl Walk for Fetch<'_> {
    fn at(&mut self, height: u32) -> Result<Block, Error> {
        self.budget.spend()?;
        let hash = self.src.hash_at(height)?;
        self.header(&hash, height)
    }

    fn below(&mut self, b: &Block) -> Result<Block, Error> {
        let height = b.height.checked_sub(1).ok_or_else(|| Error::BadWindow("below height 0".into()))?;
        self.header(&b.header.prev(), height)
    }
}

/// Resolve the current daily.
///
/// "Now" is the timestamp of the tip block, never the local clock. Day `D` is
/// tried first; if its daily block is not there yet or has fewer than
/// [`CONFIRMATIONS`] linked blocks on top, `D - 1` is tried. Any verification
/// failure is an error, not a fallback. The whole segment a day attempt walked
/// is verified with [`verify_chain`] (proof of work, floor, linkage,
/// difficulty rule, timestamp rule) before its answer is used.
///
/// A second source, if given, is asked for its tip height and for the hash at
/// the chosen height (2 requests). A different hash is an error, and so is a
/// primary tip more than [`MAX_TIP_LAG`] blocks behind; a second source that
/// cannot be reached or answers badly is reported in
/// [`Outcome::cross_check`]. `domain` is the application's versioned seed
/// domain and must not be empty (see the crate docs).
///
/// `known` is a daily the caller already holds, typically from its last
/// resolution. When today is "not yet" and `known` is the daily of `D - 1`,
/// it is returned as it is instead of walking yesterday again, which saves
/// about 30 requests in the first half hour of every day. It is trusted: pass
/// only a daily this crate gave you under the same `domain`. It is still
/// cross-checked like a derived one. A `known` of any other day is ignored.
pub fn resolve(
    domain: &[u8],
    primary: &mut dyn Source,
    secondary: Option<&mut dyn Source>,
    known: Option<&Daily>,
) -> Result<Outcome, Error> {
    if domain.is_empty() {
        return Err(Error::EmptyDomain);
    }
    let mut f = Fetch { src: primary, budget: Budget { used: 0 } };
    f.budget.spend()?;
    let tip_height = f.src.tip_height()?;
    let tip = f.at(tip_height)?;
    let today = day_of(tip.header.time() as u64);
    let mut day = today;

    let mut found: Option<(Daily, u32, [u8; 32])> = None;
    for _ in 0..2 {
        // Today is not yet: yesterday's daily may already be known.
        if let Some(k) = known.filter(|k| day != today && k.day == day) {
            found = Some((k.clone(), k.height, hash_from_display(&k.hash_hex)?));
            break;
        }
        let midnight = day.checked_mul(DAY_SECS).ok_or(Error::DayOutOfRange(day))?;
        f.budget.spend()?;
        let hint = f.src.height_hint(midnight)?.min(tip.height);
        let attempt = attempt_day(&mut f, day, hint, &tip)?;
        verify_chain(attempt.segment())?;
        match attempt {
            Attempt::Ready { segment, daily } => {
                let b = segment[daily];
                found = Some((Daily::from_block(domain, day, &b), b.height, b.header.hash()));
                break;
            }
            Attempt::NotYet { .. } => day = day.checked_sub(1).ok_or(Error::NoDailyBlock)?,
        }
    }
    let (daily, height, hash) = found.ok_or(Error::NoDailyBlock)?;
    let mut requests = f.budget.used;

    let cross_check = match secondary {
        None => CrossCheck::NotAsked,
        Some(sec) => {
            let verdict = |e: Error| match e {
                Error::Network { .. } => CrossCheck::Unreachable(e),
                e => CrossCheck::Failed(e),
            };
            requests += 1;
            match sec.tip_height() {
                Err(e) => verdict(e),
                Ok(st) if st > tip.height.saturating_add(MAX_TIP_LAG) => {
                    return Err(Error::PrimaryBehind { primary: tip.height, secondary: st });
                }
                Ok(_) => {
                    requests += 1;
                    match sec.hash_at(height) {
                        Ok(h) if h == hash => CrossCheck::Agreed,
                        Ok(_) => return Err(Error::CrossCheckMismatch { height }),
                        Err(e) => verdict(e),
                    }
                }
            }
        }
    };
    Ok(Outcome { daily, cross_check, requests })
}

#[cfg(test)]
mod tests {
    //! The walk over synthetic chains: timestamps only, no proof of work.
    //! For the review's cases X (a block k below the first honest
    //! post-midnight block Y is stamped after midnight) and Z (block Y + j is
    //! stamped before midnight), every tip from the first confirmation on and
    //! every hint error must give the same block, the one the rule defines.
    use super::*;

    const DAY: u64 = 20764;
    const MID: u64 = DAY * DAY_SECS;
    const N: usize = 120;
    const Y: usize = 70;

    /// Headers carrying only `times` and the previous hash, linked.
    fn chain(times: &[u32]) -> Vec<Block> {
        let mut out: Vec<Block> = Vec::new();
        for (i, t) in times.iter().enumerate() {
            let mut h = [0u8; 80];
            if let Some(p) = out.last() {
                h[4..36].copy_from_slice(&p.header.hash());
            }
            h[68..72].copy_from_slice(&t.to_le_bytes());
            out.push(Block { height: i as u32, header: Header(h) });
        }
        out
    }

    struct Synth<'a>(&'a [Block]);
    impl Walk for Synth<'_> {
        fn at(&mut self, height: u32) -> Result<Block, Error> {
            self.0.get(height as usize).copied().ok_or(Error::BadWindow("beyond the chain".into()))
        }
        fn below(&mut self, b: &Block) -> Result<Block, Error> {
            // By height (fast), but only if it really is the parent.
            let p = self.0.get((b.height as usize).wrapping_sub(1)).copied().ok_or(Error::WrongHeader)?;
            if p.header.hash() == b.header.prev() { Ok(p) } else { Err(Error::WrongHeader) }
        }
    }

    /// The rule straight from its definition, over the whole chain.
    fn reference(times: &[u32]) -> usize {
        let mtp = |i: usize| {
            let mut w = times[i - 11..i].to_vec();
            w.sort();
            w[5] as u64
        };
        let a = (11..times.len()).find(|&i| mtp(i) >= MID - 3 * 3600).unwrap();
        assert!(a > 11, "chain too short for the reference");
        (a..times.len()).find(|&i| times[i] as u64 >= MID).unwrap()
    }

    /// Honest blocks every 600 s, Y at midnight + 300.
    fn honest() -> Vec<u32> {
        (0..N).map(|i| (MID as i64 + 300 + 600 * (i as i64 - Y as i64)) as u32).collect()
    }

    /// Every tip and a spread of hints: NotYet before the third confirmation,
    /// the reference block from then on.
    fn sweep(times: &[u32]) -> usize {
        let blocks = chain(times);
        let want = reference(times);
        // The explorer's hint: the highest block stamped at or before midnight.
        let true_hint = (0..N).filter(|&i| times[i] as u64 <= MID).max().unwrap() as i64;
        for tip in (want.saturating_sub(2))..N {
            for off in [-30i64, -12, -3, -1, 0, 1, 3, 12, 30] {
                let hint = (true_hint + off).clamp(0, tip as i64) as u32;
                let got = attempt_day(&mut Synth(&blocks), DAY, hint, &blocks[tip]);
                match got {
                    Ok(Attempt::Ready { segment, daily }) => {
                        assert!(tip >= want + CONFIRMATIONS, "tip {tip} hint {hint}: adopted too early");
                        assert_eq!(segment[daily].height as usize, want, "tip {tip} hint {hint}");
                        assert!(segment.len() - 1 - daily >= CONFIRMATIONS);
                    }
                    Ok(Attempt::NotYet { segment }) => {
                        assert!(tip < want + CONFIRMATIONS, "tip {tip} hint {hint}: not adopted");
                        assert_eq!(segment.last().unwrap().height as usize, tip, "NotYet must reach the tip");
                    }
                    Err(e) => panic!("tip {tip} hint {hint}: {e}"),
                }
            }
        }
        want
    }

    #[test]
    fn an_ordinary_midnight() {
        assert_eq!(sweep(&honest()), Y);
    }

    #[test]
    fn case_x_a_late_stamped_block_before_midnight() {
        // The anchor of the honest chain is Y - 12 (MTP(i) is the time of i - 6).
        for k in [1usize, 3, 5, 9, 12, 20] {
            let mut t = honest();
            t[Y - k] = (MID + 60) as u32;
            let got = sweep(&t);
            let want = if k <= 12 { Y - k } else { Y };
            assert_eq!(got, want, "k = {k}");
        }
    }

    #[test]
    fn case_z_an_early_stamped_block_after_midnight() {
        // With 600 s spacing, j = 6 breaks consensus's timestamp rule (its
        // median time past is Y's time); the walk does not check that rule
        // (production verifies it afterwards), so the case still tests the walk.
        for j in 2usize..=6 {
            let mut t = honest();
            t[Y + j] = (MID - 1) as u32;
            assert_eq!(sweep(&t), Y, "j = {j}");
        }
    }

    #[test]
    fn a_tip_before_the_anchor_is_not_yet() {
        let blocks = chain(&honest());
        let tip = blocks[Y - 15];
        assert!(matches!(attempt_day(&mut Synth(&blocks), DAY, tip.height, &tip), Ok(Attempt::NotYet { .. })));
    }

    #[test]
    fn a_block_that_does_not_link_upwards_is_an_error() {
        let mut blocks = chain(&honest());
        // Swap two blocks above the start: the walk up must notice.
        blocks.swap(Y + 1, Y + 2);
        let tip = blocks[N - 1];
        let r = attempt_day(&mut Synth(&blocks), DAY, (Y - 10) as u32, &tip);
        assert!(matches!(r, Err(Error::BrokenLink { .. })), "{r:?}");
    }
}
