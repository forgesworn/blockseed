//! Recorded mainnet headers. Lines are `height displayed-hash header-hex`.
//!
//! * `day_20764.txt`, `day_20763.txt`: the original 15-block windows around
//!   the UTC midnights of 2026-11-07 and 2026-11-06 (kept byte for byte; they
//!   pin the seed vectors).
//! * `blocks_974690_974889.txt`: 200 consecutive blocks covering both of those
//!   midnights with the anchor lookback, and tips well past them.
//! * `day_20758.txt`: blocks 974010..=974055, the midnight of 2026-11-01, where
//!   block 974043 is stamped before midnight above the daily block 974042.
//! * `retarget_973728.txt`: blocks 973716..=973740, across a difficulty
//!   adjustment.

use blockseed::resolve::{resolve, CrossCheck, Source, MAX_REQUESTS};
use blockseed::*;
use std::collections::HashMap;

/// The domain of the first application to use this crate. The seeds asserted
/// below pin the derivation bit for bit.
const CF: &[u8] = b"clusterflock-daily-v1";

const D64: &str = include_str!("data/day_20764.txt");
const D63: &str = include_str!("data/day_20763.txt");
const RANGE: &str = include_str!("data/blocks_974690_974889.txt");
const D58: &str = include_str!("data/day_20758.txt");
const RETARGET: &str = include_str!("data/retarget_973728.txt");

fn load(s: &str) -> Vec<Block> {
    s.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let mut p = l.split_whitespace();
            let height: u32 = p.next().unwrap().parse().unwrap();
            let hash = p.next().unwrap();
            let header = Header::from_hex(p.next().unwrap()).unwrap();
            assert_eq!(header.hash_display(), hash, "vector {height}");
            Block { height, header }
        })
        .collect()
}

fn index_of(b: &[Block], height: u32) -> usize {
    b.iter().position(|x| x.height == height).unwrap()
}

const MID_64: u64 = 20764 * DAY_SECS;

#[test]
fn hash_is_double_sha256_displayed_reversed() {
    let b = load(D64);
    assert_eq!(b.len(), 15);
    let daily = b.iter().find(|b| b.height == 974869).unwrap();
    assert_eq!(daily.header.hash_display(), "0000000000000000000123e050878a33503aca65df86ca668fca2ec493b46f79");
    assert_eq!(daily.header.time() as u64 - MID_64, 637);
    assert_eq!(daily.header.bits(), 0x1701e5ac);
}

#[test]
fn recorded_runs_verify() {
    for data in [D64, D63, RANGE, D58, RETARGET] {
        verify_chain(&load(data)).unwrap();
    }
    // The old windows are byte-identical slices of the long run.
    let range = load(RANGE);
    for data in [D64, D63] {
        let w = load(data);
        let i = index_of(&range, w[0].height);
        assert_eq!(&range[i..i + w.len()], &w[..]);
    }
}

#[test]
fn the_rule_picks_the_first_block_after_midnight_on_recorded_days() {
    let b = load(RANGE);
    for (day, anchor, daily) in [(20764, 974864, 974869), (20763, 974716, 974733)] {
        match find_daily(&b, day).unwrap() {
            Locate::Found { anchor: a, daily: d } => {
                assert_eq!((b[a].height, b[d].height), (anchor, daily), "day {day}");
                // It is also simply the first block stamped at or after midnight.
                let first = b.iter().find(|x| x.header.time() as u64 >= day * DAY_SECS).unwrap();
                assert_eq!(first.height, daily);
            }
            other => panic!("day {day}: {other:?}"),
        }
    }
    let d = load(D64);
    let i = index_of(&d, 974869);
    assert_eq!(Daily::from_block(CF, 20764, &d[i]).seed, 0x4b9c_c6b9_ba92_b55f);

    // Day 20758: 974043 is stamped before midnight, but its predecessor
    // 974042 is the first at or after it.
    let b = load(D58);
    match find_daily(&b, 20758).unwrap() {
        Locate::Found { anchor, daily } => assert_eq!((b[anchor].height, b[daily].height), (974032, 974042)),
        other => panic!("{other:?}"),
    }
    assert!((b[index_of(&b, 974043)].header.time() as u64) < 20758 * DAY_SECS);
}

#[test]
fn a_run_must_reach_twelve_blocks_below_the_anchor() {
    let b = load(RANGE);
    // The old 15-block window does not prove the anchor.
    assert_eq!(find_daily(&load(D64), 20764), Ok(Locate::NeedEarlier));
    // From the anchor's twelfth predecessor (974852) it does; from 974853 not.
    let i = index_of(&b, 974852);
    assert!(matches!(find_daily(&b[i..], 20764), Ok(Locate::Found { .. })));
    assert_eq!(find_daily(&b[i + 1..], 20764), Ok(Locate::NeedEarlier));
    // A run ending before the daily block, or before the anchor.
    let j = index_of(&b, 974868);
    assert_eq!(find_daily(&b[i..=j], 20764), Ok(Locate::NeedLater));
    assert_eq!(find_daily(&b[..index_of(&b, 974800)], 20764), Ok(Locate::NeedLater));
}

#[test]
fn tampered_header_fails() {
    let mut b = load(D64);
    b[5].header.0[70] ^= 0x01; // a timestamp byte: the hash no longer meets the target
    let e = verify_chain(&b).unwrap_err();
    assert!(matches!(e, Error::PowFailed { .. } | Error::BrokenLink { .. }), "{e}");
}

#[test]
fn too_easy_target_fails() {
    let mut b = load(D64);
    // Difficulty 1 target with a hash that cannot meet it as tampered, but the
    // floor check must fire first, whatever the hash is.
    b[3].header.0[72..76].copy_from_slice(&0x1d00_ffffu32.to_le_bytes());
    assert_eq!(verify_chain(&b), Err(Error::TargetTooEasy { height: b[3].height }));
    // And one step above the floor is refused, one at the floor is not a TargetTooEasy.
    let mut h = b[3].header;
    h.0[72..76].copy_from_slice(&(FLOOR_BITS + 1).to_le_bytes());
    assert_eq!(check_header(1, &h), Err(Error::TargetTooEasy { height: 1 }));
    h.0[72..76].copy_from_slice(&FLOOR_BITS.to_le_bytes());
    assert_eq!(check_header(1, &h), Err(Error::PowFailed { height: 1 }));
}

#[test]
fn broken_link_fails() {
    let mut b = load(D64);
    b.remove(7); // heights jump
    assert!(matches!(verify_chain(&b), Err(Error::BadWindow(_))));
    let mut b = load(D64);
    b[7].header = load(D63)[7].header; // valid header, wrong place, renumbered
    assert_eq!(verify_chain(&b), Err(Error::BrokenLink { height: b[7].height }));
}

#[test]
fn difficulty_may_change_only_at_a_retarget_height() {
    let b = load(RETARGET);
    let i = index_of(&b, 973728);
    assert_ne!(b[i].header.bits(), b[i - 1].header.bits());
    verify_chain(&b).unwrap();
    // The same real headers numbered one higher put the change at 973729.
    let shifted: Vec<Block> = b.iter().map(|x| Block { height: x.height + 1, ..*x }).collect();
    assert_eq!(verify_chain(&shifted), Err(Error::DifficultyChange { height: 973729 }));
}

#[test]
fn seed_changes_with_the_block() {
    let b = load(D64);
    let a = seed_from_hash(CF, &b[8].header.hash());
    let c = seed_from_hash(CF, &b[9].header.hash());
    assert_ne!(a, c);
}

/// An explorer over recorded headers.
struct Mock {
    name: &'static str,
    by_height: HashMap<u32, Block>,
    by_hash: HashMap<[u8; 32], Header>,
    tip: u32,
    hint_offset: i64,
    hint_fixed: Option<u32>,
    fail: Option<Error>,
    lie_at: Option<u32>,
    calls: u32,
}

impl Mock {
    fn new(name: &'static str, sets: &[&str]) -> Mock {
        let mut by_height = HashMap::new();
        let mut by_hash = HashMap::new();
        for s in sets {
            for b in load(s) {
                by_height.insert(b.height, b);
                by_hash.insert(b.header.hash(), b.header);
            }
        }
        Mock { name, by_height, by_hash, tip: 0, hint_offset: 0, hint_fixed: None, fail: None, lie_at: None, calls: 0 }
    }
    fn with_tip(mut self, tip: u32) -> Mock {
        self.tip = tip;
        self
    }
    fn missing(&self) -> Error {
        Error::Http { source: self.name.into(), status: 404 }
    }
    fn check(&mut self) -> Result<(), Error> {
        self.calls += 1;
        match &self.fail {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }
}

fn down(name: &str) -> Error {
    Error::Network { source: name.into(), what: "down".into() }
}

impl Source for Mock {
    fn name(&self) -> &str {
        self.name
    }
    fn tip_height(&mut self) -> Result<u32, Error> {
        self.check()?;
        Ok(self.tip)
    }
    fn hash_at(&mut self, h: u32) -> Result<[u8; 32], Error> {
        self.check()?;
        if self.lie_at == Some(h) {
            return Ok([7; 32]);
        }
        if h > self.tip {
            return Err(self.missing());
        }
        self.by_height.get(&h).map(|b| b.header.hash()).ok_or_else(|| self.missing())
    }
    fn header(&mut self, hash: &[u8; 32]) -> Result<Header, Error> {
        self.check()?;
        self.by_hash.get(hash).copied().ok_or_else(|| self.missing())
    }
    fn height_hint(&mut self, ts: u64) -> Result<u32, Error> {
        self.check()?;
        if let Some(h) = self.hint_fixed {
            return Ok(h);
        }
        // The last block at or before ts, like mempool.space, plus an offset.
        let h = self
            .by_height
            .values()
            .filter(|b| b.header.time() as u64 <= ts && b.height <= self.tip)
            .map(|b| b.height)
            .max()
            .ok_or_else(|| self.missing())?;
        Ok((h as i64 + self.hint_offset) as u32)
    }
}

fn primary(tip: u32) -> Mock {
    Mock::new("a", &[RANGE]).with_tip(tip)
}

#[test]
fn resolve_over_a_mock_chain() {
    let mut a = primary(974875);
    let mut b = Mock::new("b", &[RANGE]).with_tip(974876);
    let o = resolve(CF, &mut a, Some(&mut b), None).unwrap();
    assert_eq!(o.daily.day, 20764);
    assert_eq!(o.daily.height, 974869);
    assert_eq!(o.daily.seed, 0x4b9c_c6b9_ba92_b55f);
    assert_eq!(o.cross_check, CrossCheck::Agreed);
    assert!(o.cross_checked());
    assert_eq!(o.requests, a.calls + b.calls);
    assert_eq!(b.calls, 2);
    assert!(a.calls <= 40, "one day attempt took {} requests", a.calls);
}

#[test]
fn every_tip_gives_the_same_daily_from_its_third_confirmation() {
    // Day 20763's daily is 974733; day 20764's is 974869. From each daily's
    // third confirmation on, every tip in the recording gives that block, and
    // in between (today's not yet confirmed) yesterday's stays current.
    for tip in 974736..=974889 {
        let mut a = primary(tip);
        let o = resolve(CF, &mut a, None, None).unwrap_or_else(|e| panic!("tip {tip}: {e}"));
        let want = if tip >= 974872 { (20764, 974869) } else { (20763, 974733) };
        assert_eq!((o.daily.day, o.daily.height), want, "tip {tip}");
        assert!(o.requests <= MAX_REQUESTS);
        assert_eq!(o.cross_check, CrossCheck::NotAsked);
    }
}

#[test]
fn a_wrong_hint_costs_requests_not_the_answer() {
    for off in [-25i64, -10, -3, -1, 1, 3, 10, 25] {
        let mut a = primary(974880);
        a.hint_offset = off;
        let o = resolve(CF, &mut a, None, None).unwrap_or_else(|e| panic!("offset {off}: {e}"));
        assert_eq!((o.daily.day, o.daily.height), (20764, 974869), "offset {off}");
    }
}

#[test]
fn a_midnight_with_an_early_stamped_block_above_the_daily() {
    let mut a = Mock::new("a", &[D58]).with_tip(974055);
    let o = resolve(CF, &mut a, None, None).unwrap();
    assert_eq!((o.daily.day, o.daily.height), (20758, 974042));
}

#[test]
fn a_hint_into_yesterday_is_an_error_not_yesterday() {
    // The tip says day 20764, the hint points into day 20763. Walking up from
    // there to today's anchor is far more than the budget: an error, never a
    // quiet switch to yesterday's block.
    let mut a = primary(974875);
    a.hint_fixed = Some(974732);
    assert_eq!(resolve(CF, &mut a, None, None), Err(Error::TooManyRequests));
    assert_eq!(a.calls, MAX_REQUESTS);
}

#[test]
fn a_claimed_tip_is_not_a_confirmation() {
    // The explorer claims a tip at 974889 but every height above 974870 maps to
    // the header of 974870: the daily 974869 has one linked block on top.
    struct Stuck(Mock);
    impl Source for Stuck {
        fn name(&self) -> &str {
            "stuck"
        }
        fn tip_height(&mut self) -> Result<u32, Error> {
            Ok(974889)
        }
        fn hash_at(&mut self, h: u32) -> Result<[u8; 32], Error> {
            self.0.hash_at(h.min(974870))
        }
        fn header(&mut self, hash: &[u8; 32]) -> Result<Header, Error> {
            self.0.header(hash)
        }
        fn height_hint(&mut self, t: u64) -> Result<u32, Error> {
            self.0.height_hint(t)
        }
    }
    let r = resolve(CF, &mut Stuck(primary(974889)), None, None);
    assert!(matches!(r, Err(Error::BrokenLink { .. })), "{r:?}");
}

#[test]
fn not_yet_today_falls_back_to_yesterday_but_errors_do_not() {
    // Tip 974871: today's daily 974869 has two blocks on top, not three.
    let o = resolve(CF, &mut primary(974871), None, None).unwrap();
    assert_eq!((o.daily.day, o.daily.height), (20763, 974733));
    // A tampered block in today's walk is an error, not a fallback.
    let mut a = primary(974871);
    let h = a.by_height[&974860].header;
    let mut bad = h;
    bad.0[75] ^= 0x01; // bits
    a.by_hash.insert(h.hash(), bad);
    let r = resolve(CF, &mut a, None, None);
    assert_eq!(r, Err(Error::WrongHeader));
}

#[test]
fn a_known_daily_for_yesterday_skips_the_fallback_walk() {
    // Tip 974871: today (20764) is not yet, so yesterday's is current.
    let mut a = primary(974871);
    let derived = resolve(CF, &mut a, None, None).unwrap();
    let full = a.calls;
    assert_eq!((derived.daily.day, derived.daily.height), (20763, 974733));

    let mut a = primary(974871);
    let mut b = Mock::new("b", &[RANGE]).with_tip(974871);
    let o = resolve(CF, &mut a, Some(&mut b), Some(&derived.daily)).unwrap();
    assert_eq!(o.daily, derived.daily);
    assert!(o.cross_checked(), "a known daily is still cross-checked");
    assert!(a.calls + 25 < full, "{} requests with the known daily, {full} without", a.calls);

    // A known daily the second explorer contradicts is an error.
    let mut forged = derived.daily.clone();
    forged.hash_hex = load(D63)[0].header.hash_display();
    let mut b = Mock::new("b", &[RANGE]).with_tip(974871);
    assert_eq!(
        resolve(CF, &mut primary(974871), Some(&mut b), Some(&forged)),
        Err(Error::CrossCheckMismatch { height: 974733 })
    );

    // A known daily of another day is ignored: today's confirmed daily wins,
    // and an older one does not replace the fallback walk.
    let o = resolve(CF, &mut primary(974875), None, Some(&derived.daily)).unwrap();
    assert_eq!((o.daily.day, o.daily.height), (20764, 974869));
    let mut old = derived.daily.clone();
    old.day = 20762;
    let mut a = primary(974871);
    assert_eq!(resolve(CF, &mut a, None, Some(&old)).unwrap(), derived);
    assert_eq!(a.calls, full);
}

#[test]
fn second_source_unreachable_or_failing_is_reported() {
    let mut a = primary(974875);
    let mut b = Mock::new("b", &[]);
    b.fail = Some(down("b"));
    let o = resolve(CF, &mut a, Some(&mut b), None).unwrap();
    assert_eq!(o.cross_check, CrossCheck::Unreachable(down("b")));
    assert!(!o.cross_checked());
    assert_eq!(o.daily.height, 974869);

    let mut a = primary(974875);
    let mut b = Mock::new("b", &[]).with_tip(974875);
    let o = resolve(CF, &mut a, Some(&mut b), None).unwrap();
    assert_eq!(o.cross_check, CrossCheck::Failed(Error::Http { source: "b".into(), status: 404 }));

    let mut a = primary(974875);
    let mut b = Mock::new("b", &[]);
    b.fail = Some(Error::BadResponse { source: "b".into(), what: "junk".into() });
    let o = resolve(CF, &mut a, Some(&mut b), None).unwrap();
    assert!(matches!(o.cross_check, CrossCheck::Failed(Error::BadResponse { .. })));
}

#[test]
fn cross_check_mismatch_is_an_error() {
    let mut a = primary(974875);
    let mut b = Mock::new("b", &[RANGE]).with_tip(974875);
    b.lie_at = Some(974869);
    assert_eq!(resolve(CF, &mut a, Some(&mut b), None), Err(Error::CrossCheckMismatch { height: 974869 }));
}

#[test]
fn a_primary_far_behind_the_second_is_an_error() {
    // A stale primary at 974871 would serve yesterday's daily as current.
    let mut b = Mock::new("b", &[RANGE]).with_tip(974871 + 7);
    assert_eq!(
        resolve(CF, &mut primary(974871), Some(&mut b), None),
        Err(Error::PrimaryBehind { primary: 974871, secondary: 974878 })
    );
    let mut b = Mock::new("b", &[RANGE]).with_tip(974871 + 6);
    assert!(resolve(CF, &mut primary(974871), Some(&mut b), None).unwrap().cross_checked());
}

#[test]
fn an_explorer_that_answers_with_the_wrong_header_is_refused() {
    struct Liar(Mock);
    impl Source for Liar {
        fn name(&self) -> &str {
            "liar"
        }
        fn tip_height(&mut self) -> Result<u32, Error> {
            self.0.tip_height()
        }
        fn hash_at(&mut self, h: u32) -> Result<[u8; 32], Error> {
            self.0.hash_at(h)
        }
        fn height_hint(&mut self, t: u64) -> Result<u32, Error> {
            self.0.height_hint(t)
        }
        fn header(&mut self, _hash: &[u8; 32]) -> Result<Header, Error> {
            Ok(load(D64)[0].header)
        }
    }
    assert_eq!(resolve(CF, &mut Liar(primary(974875)), None, None), Err(Error::WrongHeader));
}

#[test]
fn an_empty_domain_is_refused() {
    assert_eq!(resolve(b"", &mut primary(974875), None, None), Err(Error::EmptyDomain));
}

/// Live check against both explorers. Run with
/// `cargo test --features fetch -- --ignored`.
#[cfg(feature = "fetch")]
#[test]
#[ignore = "needs the network"]
fn live_today() {
    let o = blockseed::http::fetch_today(CF).expect("live daily");
    println!("{:?}", o);
    assert!(o.requests <= MAX_REQUESTS + 2);
    assert_eq!(o.daily.hash_hex.len(), 64);
    assert!(o.daily.hash_hex.starts_with("0000000"));
    assert!(o.daily.height > 975_000);
}

/// Seeds under the domain `clusterflock-daily-v1` for every recorded block,
/// as produced by the original implementation before this crate was split out.
/// Rows: (height, displayed hash, seed).
const CF_VECTORS: &[(u32, &str, u64)] = &[
    (974861, "00000000000000000000e76bd46517d7c3ce553c0d9bd6968dfb7efd72516d48", 0x5668_b0dc_9525_47fd),
    (974862, "00000000000000000000d327e01b1988f4572a34e630d9844b5031dc94af143c", 0xfcad_7877_7fbd_2e16),
    (974863, "00000000000000000001b304be6b20d58966168e723bedc75c1b9a8d5d94e3c1", 0x6949_a495_7393_f5fb),
    (974864, "00000000000000000001712e2e64f01e7c6e3ec4da08a9b70ce0bbc3bc9d7947", 0x5b49_58ea_ee59_cdba),
    (974865, "0000000000000000000029e807982b5f2cdd664cd249d7604aa0a666de8e6683", 0x4dfb_f59a_6c8f_d046),
    (974866, "00000000000000000000cebad0d2d551037f43d23b2238daed435e6fa7cebb59", 0xa8a5_c526_1ea8_c59c),
    (974867, "0000000000000000000081a5090bb3a13fb217b8845da7574939e74a8de8a771", 0xa7f2_6453_442b_d02b),
    (974868, "000000000000000000006dc1db5188a78ea5132b86233a0e38cf2906308bdccb", 0x68e6_734a_b087_8fdf),
    (974869, "0000000000000000000123e050878a33503aca65df86ca668fca2ec493b46f79", 0x4b9c_c6b9_ba92_b55f),
    (974870, "000000000000000000010490c9125489d44b04d2c3b68199f6c108f212ebdfcf", 0x2277_17b2_2271_bca1),
    (974871, "00000000000000000001e50317b382cb660edf9554491179acd291156c844a38", 0xe403_7b2a_4801_2443),
    (974872, "00000000000000000000e21b986091a294811578c7e7f0311f3cd13f852a8e20", 0xca68_ee96_bdc1_ffea),
    (974873, "0000000000000000000056bbed4b5addc6a289af480a078e0187a55143e6d03b", 0xf9c2_b4ba_54c0_ca28),
    (974874, "000000000000000000016ed849ba632a31171b699698ada7ea86ec4d92ffd20d", 0x1b21_910b_cdda_340c),
    (974875, "000000000000000000012eecf9ab36f051f0770e9d42ada81ed5bb3cfef579b3", 0x0092_7302_7c91_c641),
    (974725, "000000000000000000001ac3b5965ecbb090eac33c18820ec9febc9db0f04012", 0xf15d_7c4f_1ae0_93ba),
    (974726, "00000000000000000000e5a954e98fe7d9be76ddaae7020f5f4b8348707d19f0", 0xb51c_1b8c_78f9_c920),
    (974727, "0000000000000000000077fdb483dffa8b5d323c4b27c40a3006ef61b8875f82", 0xb846_c6c0_16d9_0067),
    (974728, "000000000000000000007289d0aa60362222f984f7cd981fda053a0c6942624c", 0xfb54_53a3_1d36_a66a),
    (974729, "0000000000000000000151fcd271885e929eb3a67c07e84ea74688e003428c70", 0x2b89_8afd_8ee5_dc00),
    (974730, "00000000000000000000ba2fde04d46d2c8b0ebbffc6acce327a614a814ad370", 0x4488_5fe6_b20d_9bf7),
    (974731, "00000000000000000001084cb696acb26ece868dfa0746ce617f3f6732016349", 0xbea0_c1e1_e0f0_3b73),
    (974732, "000000000000000000014ac0b11b9b0730ae6bb928d5cae5a9c2c56532db66ac", 0xeb20_a2f9_7d3f_7973),
    (974733, "00000000000000000001be6912f1e6068e9835e000b1d2d866a50d8e2bea8a9d", 0xb14c_122f_167c_1b8a),
    (974734, "0000000000000000000138e1be3307475d9dd1c384d4e6f02610e55a0882778b", 0x1f0d_db45_6e7d_b1cb),
    (974735, "000000000000000000000044415320a52283e32f1e664e0cd9f2a281d01ba6b0", 0xa3b3_1758_8bfb_d376),
    (974736, "000000000000000000000ac973abbff58f579418203ac0d558f4bfde1057c350", 0x0870_fe81_589e_c567),
    (974737, "000000000000000000010818ba12f9e671694c3fbde656cfdbabad59d87ecb06", 0xe3b9_532d_329b_cdaf),
    (974738, "000000000000000000002e7c0782451d2a3d8ad138f8cf6ff7713665321db1d4", 0x5099_f371_921b_ef77),
    (974739, "00000000000000000001323821d3f6e85cb2de79c91d39d08821fb9178a48e83", 0x0784_6dd9_8ce3_7e28),
];

#[test]
fn seeds_are_bit_identical_to_the_original_implementation() {
    let mut n = 0;
    for data in [D64, D63] {
        for b in load(data) {
            let (_, hash, seed) = CF_VECTORS.iter().find(|v| v.0 == b.height).expect("vector row");
            assert_eq!(&b.header.hash_display(), hash);
            assert_eq!(seed_from_hash(CF, &b.header.hash()), *seed, "block {}", b.height);
            assert_eq!(seed_from_hash(CF, &hash_from_display(hash).unwrap()), *seed);
            n += 1;
        }
    }
    assert_eq!(n, CF_VECTORS.len());
    assert_eq!(seed_from_hash(CF, &[0u8; 32]), 0x7b1e_2b4f_90aa_346b);
}

#[test]
fn the_domain_is_part_of_the_seed() {
    let h = hash_from_display(CF_VECTORS[0].1).unwrap();
    assert_ne!(seed_from_hash(CF, &h), seed_from_hash(b"another-app-daily-v1", &h));
    assert_ne!(seed_from_hash(CF, &h), seed_from_hash(b"clusterflock-daily-v2", &h));
}
