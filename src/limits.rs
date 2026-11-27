//! Shared state: who is connected, how fast they are going, and whether
//! the relay is under pressure.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nostr::key::PublicKey;

use crate::config::Config;

/// Length of the window used for counting new connections.
const NEW_CONN_WINDOW: Duration = Duration::from_secs(60);
/// Pressure mode stays on this long after the last busy second.
const PRESSURE_HOLD: Duration = Duration::from_secs(60);
/// How often counters are written to the log.
const STATS_EVERY: Duration = Duration::from_secs(60);

/// The address a client is counted under: IPv4 as is, IPv6 by /64 network,
/// because one attacker normally controls a whole /64.
pub(crate) fn count_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
    }
}

/// A token bucket: `capacity` tokens at most, refilled at `rate` per second.
struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn full(capacity: f64, now: Instant) -> Self {
        Self { tokens: capacity, last: now }
    }

    fn take(&mut self, rate: f64, capacity: f64, now: Instant) -> bool {
        let gained = now.duration_since(self.last).as_secs_f64() * rate;
        self.tokens = (self.tokens + gained).min(capacity);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// What we remember about one IP.
struct IpState {
    conns: usize,
    window_start: Instant,
    new_conns: u32,
    messages: Bucket,
    events: Bucket,
}

/// Counters for the log.
#[derive(Default)]
pub(crate) struct Stats {
    pub conns_accepted: AtomicU64,
    pub conns_refused: AtomicU64,
    pub forwarded: AtomicU64,
    pub rate_limited: AtomicU64,
    pub malformed: AtomicU64,
    pub bad_signature: AtomicU64,
    pub blocked_key: AtomicU64,
    pub events_limited: AtomicU64,
    pub key_limited: AtomicU64,
    pub pow_missing: AtomicU64,
    pub subs_refused: AtomicU64,
}

impl Stats {
    fn line(&self) -> String {
        format!(
            "accepted={} refused={} forwarded={} rate_limited={} malformed={} \
             bad_signature={} blocked_key={} events_limited={} key_limited={} pow_missing={} \
             subs_refused={}",
            self.conns_accepted.load(Relaxed),
            self.conns_refused.load(Relaxed),
            self.forwarded.load(Relaxed),
            self.rate_limited.load(Relaxed),
            self.malformed.load(Relaxed),
            self.bad_signature.load(Relaxed),
            self.blocked_key.load(Relaxed),
            self.events_limited.load(Relaxed),
            self.key_limited.load(Relaxed),
            self.pow_missing.load(Relaxed),
            self.subs_refused.load(Relaxed),
        )
    }
}

pub(crate) struct Shield {
    pub cfg: Config,
    pub stats: Stats,
    ips: Mutex<HashMap<IpAddr, IpState>>,
    keys: Mutex<HashMap<(IpAddr, PublicKey), Bucket>>,
    open_conns: AtomicUsize,
    events_this_second: AtomicU64,
    pressure: AtomicBool,
}

impl Shield {
    pub fn new(cfg: Config) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            stats: Stats::default(),
            ips: Mutex::default(),
            keys: Mutex::default(),
            open_conns: AtomicUsize::new(0),
            events_this_second: AtomicU64::new(0),
            pressure: AtomicBool::new(false),
        })
    }

    pub fn under_pressure(&self) -> bool {
        self.pressure.load(Relaxed)
    }

    /// Count an incoming event towards the pressure measurement.
    pub fn saw_event(&self) {
        self.events_this_second.fetch_add(1, Relaxed);
    }


    /// Runs forever: measures pressure once a second, and now and then
    /// forgets idle clients and writes counters to the log.
    pub async fn housekeeping(self: Arc<Self>) {
        let mut hot_at: Option<Instant> = None;
        let mut last_stats = Instant::now();
        let mut last_line = String::new();
        loop {
            let now = Instant::now();
            let events = self.events_this_second.swap(0, Relaxed) as f64;
            let hot = self.open_conns.load(Relaxed) >= self.cfg.pressure_conns
                || events >= self.cfg.pressure_events_per_sec;
            if hot {
                hot_at = Some(now);
            }
            let pressure = hot_at.is_some_and(|t| now.duration_since(t) < PRESSURE_HOLD);
            if self.pressure.swap(pressure, Relaxed) != pressure {
                println!("haskshield: pressure mode {}", if pressure { "ON" } else { "off" });
            }

            if now.duration_since(last_stats) >= STATS_EVERY {
                last_stats = now;
                self.prune(now);
                let line = self.stats.line();
                if line != last_line {
                    println!("haskshield: open={} {line}", self.open_conns.load(Relaxed));
                    last_line = line;
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    /// Forget IPs and keys that have been quiet for a while.
    fn prune(&self, now: Instant) {
        self.ips.lock().unwrap().retain(|_, s| {
            s.conns > 0 || now.duration_since(s.window_start) < NEW_CONN_WINDOW
        });
        self.keys
            .lock()
            .unwrap()
            .retain(|_, b| now.duration_since(b.last) < Duration::from_secs(120));
    }
}

/// One open connection for an IP. Its place is given back when dropped.
pub(crate) struct Slot {
    shield: Arc<Shield>,
    ip: IpAddr,
    /// Set for IPs on the allow list.
    unlimited: bool,
}

impl Slot {
    /// Claim a place for a new connection. `None` means refused.
    pub fn acquire(shield: &Arc<Shield>, ip: IpAddr) -> Option<Self> {
        let cfg = &shield.cfg;
        if cfg.block_ips.contains(&ip) {
            return None;
        }
        let unlimited = cfg.allow_ips.contains(&ip);
        let now = Instant::now();
        let mut ips = shield.ips.lock().unwrap();
        let state = ips.entry(ip).or_insert_with(|| IpState {
            conns: 0,
            window_start: now,
            new_conns: 0,
            messages: Bucket::full(cfg.burst(), now),
            events: Bucket::full(f64::from(cfg.events_per_min_per_ip), now),
        });
        if now.duration_since(state.window_start) >= NEW_CONN_WINDOW {
            state.window_start = now;
            state.new_conns = 0;
        }
        // Refused attempts count too, so hammering does not pay off.
        state.new_conns = state.new_conns.saturating_add(1);
        let over = state.new_conns > cfg.max_new_conn_per_min
            || state.conns >= cfg.max_conn_per_ip;
        if over && !unlimited {
            return None;
        }
        state.conns += 1;
        shield.open_conns.fetch_add(1, Relaxed);
        Some(Self { shield: shield.clone(), ip, unlimited })
    }

    /// Take one message token for this IP. False means over the limit.
    pub fn allow_message(&self) -> bool {
        if self.unlimited {
            return true;
        }
        let cfg = &self.shield.cfg;
        let now = Instant::now();
        match self.shield.ips.lock().unwrap().get_mut(&self.ip) {
            Some(state) => state.messages.take(cfg.msgs_per_sec, cfg.burst(), now),
            None => false,
        }
    }
}

impl Slot {
    /// Take one event token for this IP. False means the IP is publishing
    /// faster than `events_per_min_per_ip`.
    pub fn allow_event(&self) -> bool {
        let per_min = f64::from(self.shield.cfg.events_per_min_per_ip);
        if self.unlimited || per_min == 0.0 {
            return true;
        }
        let now = Instant::now();
        match self.shield.ips.lock().unwrap().get_mut(&self.ip) {
            Some(state) => state.events.take(per_min / 60.0, per_min, now),
            None => false,
        }
    }

    /// Take one token for a key as used from this IP. False means the key
    /// is publishing faster than `events_per_min_per_pubkey`.
    pub fn allow_event_from(&self, key: &PublicKey) -> bool {
        let per_min = f64::from(self.shield.cfg.events_per_min_per_pubkey);
        if per_min == 0.0 {
            return true;
        }
        let now = Instant::now();
        self.shield
            .keys
            .lock()
            .unwrap()
            .entry((self.ip, *key))
            .or_insert_with(|| Bucket::full(per_min, now))
            .take(per_min / 60.0, per_min, now)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        if let Some(state) = self.shield.ips.lock().unwrap().get_mut(&self.ip) {
            state.conns = state.conns.saturating_sub(1);
        }
        self.shield.open_conns.fetch_sub(1, Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_is_counted_per_64() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::9".parse().unwrap();
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(count_key(a), count_key(b));
        assert_ne!(count_key(a), count_key(other));
    }

    #[test]
    fn a_bucket_refills_over_time() {
        let start = Instant::now();
        let mut bucket = Bucket::full(2.0, start);
        assert!(bucket.take(1.0, 2.0, start));
        assert!(bucket.take(1.0, 2.0, start));
        assert!(!bucket.take(1.0, 2.0, start));
        assert!(bucket.take(1.0, 2.0, start + Duration::from_secs(1)));
    }
}
