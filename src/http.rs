//! The blocking HTTPS fetch: two Esplora-style explorers, meant for a
//! background thread. TLS is rustls with the bundled webpki roots (ureq 2.x,
//! `tls` feature); there is no native-tls and no openssl.

use crate::resolve::{resolve, Outcome, Source};
use crate::{hash_from_display, hash_to_display, Daily, Error, Header};
use std::io::{self, Read};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The User-Agent sent unless the caller supplies one: plain, no contact details.
pub const DEFAULT_USER_AGENT: &str = "blockseed";

/// Per-request bound, also applied to DNS and to the TCP connect.
const TIMEOUT: Duration = Duration::from_secs(8);
/// Bound on a whole resolution. A request is not started after it; one that is
/// running may overrun it by at most one DNS lookup plus one connect timeout.
/// The primary stops two request timeouts earlier, so that a slow primary
/// cannot use up the second explorer's time and turn the cross-check into
/// "unreachable".
const TOTAL_TIMEOUT: Duration = Duration::from_secs(90);
/// Largest body read from an explorer. Every answer is below 400 bytes.
const MAX_BODY: u64 = 4096;

/// The longest `Retry-After` honoured on a 429 or 503. A longer one fails at once.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(10);
/// The pause before the one retry when a 429 or 503 carries no usable `Retry-After`.
const DEFAULT_BACKOFF: Duration = Duration::from_secs(2);

const MEMPOOL: &str = "https://mempool.space/api";
const BLOCKSTREAM: &str = "https://blockstream.info/api";

/// DNS with a time limit. The standard resolver has none, so the lookup runs on
/// its own thread; on a timeout that thread is left to finish on its own.
fn resolve_dns(netloc: &str) -> io::Result<Vec<SocketAddr>> {
    let (tx, rx) = mpsc::channel();
    let name = netloc.to_string();
    std::thread::Builder::new()
        .name("blockseed-dns".into())
        .spawn(move || {
            let _ = tx.send(name.to_socket_addrs().map(Iterator::collect));
        })?;
    rx.recv_timeout(TIMEOUT)
        .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "DNS lookup timed out")))
}

/// A failed request, and whether it is worth one more try.
#[derive(Debug)]
enum Fail {
    /// Rate limited or briefly unavailable: try once more after `wait`.
    Retry { err: Error, wait: Duration },
    Final(Error),
}

/// The pause before retrying a response with this status, if it is worth
/// retrying: a 429 or 503 is, after its `Retry-After` in seconds (at most
/// [`MAX_RETRY_AFTER`]; a longer one is not retried) or after
/// [`DEFAULT_BACKOFF`] when it has none that parses.
fn backoff(status: u16, retry_after: Option<&str>) -> Option<Duration> {
    if status != 429 && status != 503 {
        return None;
    }
    match retry_after.and_then(|s| s.trim().parse::<u64>().ok()) {
        Some(secs) if Duration::from_secs(secs) > MAX_RETRY_AFTER => None,
        Some(secs) => Some(Duration::from_secs(secs)),
        None => Some(DEFAULT_BACKOFF),
    }
}

/// Run `call`; after a retryable failure, sleep and run it once more, unless
/// the pause would reach `deadline` (then the first failure stands).
fn retry_once<T>(
    deadline: Instant,
    mut call: impl FnMut() -> Result<T, Fail>,
    mut sleep: impl FnMut(Duration),
) -> Result<T, Error> {
    let final_err = |f: Fail| match f {
        Fail::Retry { err, .. } | Fail::Final(err) => err,
    };
    match call() {
        Ok(v) => Ok(v),
        Err(Fail::Final(e)) => Err(e),
        Err(Fail::Retry { err, wait }) => {
            if Instant::now() + wait >= deadline {
                return Err(err);
            }
            sleep(wait);
            call().map_err(final_err)
        }
    }
}

/// One explorer.
struct Explorer {
    name: &'static str,
    base: &'static str,
    agent: ureq::Agent,
    deadline: Instant,
}

impl Explorer {
    fn new(name: &'static str, base: &'static str, user_agent: &str, deadline: Instant) -> Explorer {
        let agent = ureq::AgentBuilder::new()
            .timeout(TIMEOUT)
            .timeout_connect(TIMEOUT)
            .resolver(resolve_dns)
            .user_agent(user_agent)
            .redirects(0)
            .build();
        Explorer { name, base, agent, deadline }
    }

    /// One GET, retried once after a rate limit (see [`retry_once`]).
    fn get(&self, path: &str) -> Result<String, Error> {
        retry_once(self.deadline, || self.get_once(path), std::thread::sleep)
    }

    fn get_once(&self, path: &str) -> Result<String, Fail> {
        let net = |what: String| Error::Network { source: self.name.to_string(), what };
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Fail::Final(net("time limit for the whole fetch reached".into())));
        }
        let url = format!("{}{}", self.base, path);
        let resp = self.agent.get(&url).timeout(left.min(TIMEOUT)).call().map_err(|e| match e {
            ureq::Error::Status(status, resp) => {
                let err = Error::Http { source: self.name.to_string(), status };
                match backoff(status, resp.header("Retry-After")) {
                    Some(wait) => Fail::Retry { err, wait },
                    None => Fail::Final(err),
                }
            }
            ureq::Error::Transport(t) => Fail::Final(net(t.to_string())),
        })?;
        let mut body = String::new();
        resp.into_reader().take(MAX_BODY).read_to_string(&mut body).map_err(|e| Fail::Final(net(e.to_string())))?;
        Ok(body.trim().to_string())
    }

    fn bad(&self, what: &str) -> Error {
        Error::BadResponse { source: self.name.to_string(), what: what.to_string() }
    }
}

impl Source for Explorer {
    fn name(&self) -> &str {
        self.name
    }

    fn tip_height(&mut self) -> Result<u32, Error> {
        self.get("/blocks/tip/height")?.parse().map_err(|_| self.bad("tip height"))
    }

    fn hash_at(&mut self, height: u32) -> Result<[u8; 32], Error> {
        let s = self.get(&format!("/block-height/{height}"))?;
        hash_from_display(&s).map_err(|_| self.bad("block hash"))
    }

    fn header(&mut self, hash: &[u8; 32]) -> Result<Header, Error> {
        let s = self.get(&format!("/block/{}/header", hash_to_display(hash)))?;
        Header::from_hex(&s).map_err(|_| self.bad("header"))
    }

    fn height_hint(&mut self, ts: u64) -> Result<u32, Error> {
        let s = self.get(&format!("/v1/mining/blocks/timestamp/{ts}"))?;
        let v: serde_json::Value = serde_json::from_str(&s).map_err(|_| self.bad("timestamp lookup"))?;
        v.get("height")
            .and_then(|h| h.as_u64())
            .and_then(|h| u32::try_from(h).ok())
            .ok_or_else(|| self.bad("timestamp lookup"))
    }
}

/// Resolve the current daily over the network: mempool.space, cross-checked on
/// blockstream.info, with the default User-Agent ([`DEFAULT_USER_AGENT`]).
/// Blocks for typically 5 to 20 seconds and at most about 90; call it from a
/// background thread.
///
/// `domain` is the application's versioned seed domain and must not be empty
/// (see the crate docs).
pub fn fetch_today(domain: &[u8]) -> Result<Outcome, Error> {
    fetch_today_with(domain, DEFAULT_USER_AGENT, None)
}

/// As [`fetch_today`], with your own User-Agent and, optionally, the daily you
/// already hold: if it is yesterday's and today's is not confirmed yet, it is
/// returned (cross-checked) without walking yesterday again. See
/// [`resolve`](crate::resolve::resolve) for how `known` is used.
pub fn fetch_today_with(domain: &[u8], user_agent: &str, known: Option<&Daily>) -> Result<Outcome, Error> {
    if domain.is_empty() {
        return Err(Error::EmptyDomain);
    }
    let end = Instant::now() + TOTAL_TIMEOUT;
    let mut primary = Explorer::new("mempool.space", MEMPOOL, user_agent, end - 2 * TIMEOUT);
    let mut second = Explorer::new("blockstream.info", BLOCKSTREAM, user_agent, end);
    resolve(domain, &mut primary, Some(&mut second), known)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http(status: u16) -> Error {
        Error::Http { source: "x".into(), status }
    }

    #[test]
    fn only_rate_limits_are_retried() {
        assert_eq!(backoff(429, None), Some(DEFAULT_BACKOFF));
        assert_eq!(backoff(503, Some("3")), Some(Duration::from_secs(3)));
        assert_eq!(backoff(429, Some(" 10 ")), Some(Duration::from_secs(10)));
        assert_eq!(backoff(429, Some("11")), None, "too long to wait");
        assert_eq!(backoff(429, Some("Wed, 21 Oct 2026 07:28:00 GMT")), Some(DEFAULT_BACKOFF));
        assert_eq!(backoff(404, None), None);
        assert_eq!(backoff(500, Some("1")), None);
    }

    /// A call that fails with `first` and then answers `second`.
    fn run(first: Fail, second: Result<u32, Fail>, deadline: Instant) -> (Result<u32, Error>, u32, Vec<Duration>) {
        let mut calls = 0;
        let mut slept = Vec::new();
        let mut answers = vec![second, Err(first)];
        let r = retry_once(
            deadline,
            || {
                calls += 1;
                answers.pop().expect("at most two calls")
            },
            |d| slept.push(d),
        );
        (r, calls, slept)
    }

    #[test]
    fn a_rate_limit_is_retried_once_after_its_pause() {
        let later = Instant::now() + Duration::from_secs(60);
        let wait = Duration::from_secs(3);
        let (r, calls, slept) = run(Fail::Retry { err: http(429), wait }, Ok(7), later);
        assert_eq!((r, calls, slept), (Ok(7), 2, vec![wait]));
        // Rate limited twice: the second failure is the answer, no third try.
        let (r, calls, _) = run(Fail::Retry { err: http(429), wait }, Err(Fail::Retry { err: http(503), wait }), later);
        assert_eq!((r, calls), (Err(http(503)), 2));
    }

    #[test]
    fn no_retry_past_the_deadline_or_after_a_final_failure() {
        let soon = Instant::now() + Duration::from_secs(1);
        let (r, calls, slept) = run(Fail::Retry { err: http(429), wait: DEFAULT_BACKOFF }, Ok(7), soon);
        assert_eq!((r, calls, slept.len()), (Err(http(429)), 1, 0));
        let later = Instant::now() + Duration::from_secs(60);
        let (r, calls, _) = run(Fail::Final(http(404)), Ok(7), later);
        assert_eq!((r, calls), (Err(http(404)), 1));
    }
}
