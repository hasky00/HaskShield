//! Settings, read from environment variables.

use std::collections::HashSet;
use std::env;
use std::net::IpAddr;
use std::str::FromStr;

use nostr::key::PublicKey;

use crate::limits::count_key;

#[derive(Clone, Debug)]
pub struct Config {
    /// Address HaskShield listens on, e.g. `0.0.0.0:7778`.
    pub listen: String,
    /// The relay behind the shield, e.g. `ws://127.0.0.1:7777`.
    pub upstream: String,
    /// Read the client IP from `X-Forwarded-For`. Turn this on only when
    /// HaskShield runs behind a reverse proxy such as Caddy; otherwise a
    /// client could fake its IP.
    pub trust_proxy: bool,

    /// Most connections one IP may hold open at the same time.
    pub max_conn_per_ip: usize,
    /// Most new connections one IP may open per minute.
    pub max_new_conn_per_min: u32,

    /// Messages per second one IP may send, across all its connections.
    /// Short bursts of up to five times this are allowed.
    pub msgs_per_sec: f64,
    /// Largest single message a client may send, in bytes.
    pub max_message_bytes: usize,
    /// Most subscriptions one connection may hold open.
    pub max_subs_per_conn: usize,
    /// Most filters allowed in one REQ or COUNT.
    pub max_filters_per_req: usize,

    /// Check the id and signature of every event before the relay sees it.
    /// The per-key limit, the lists of keys and proof of work all depend on
    /// this, because an unchecked event can claim any key.
    pub verify_events: bool,
    /// Events one IP may publish per minute, whatever keys it uses. This
    /// is what stops an address that makes a new key for every note.
    /// 0 turns the limit off.
    pub events_per_min_per_ip: u32,
    /// Events one key may publish per minute from one IP. 0 turns the
    /// limit off.
    ///
    /// It is counted per IP on purpose. A limit per key alone would let
    /// anyone silence a person by replaying that person's old, validly
    /// signed events until their key was over the limit.
    pub events_per_min_per_pubkey: u32,
    /// Proof of work (NIP-13) every event must carry. 0 turns it off.
    pub min_pow: u8,

    /// Proof of work required while the relay is under pressure. 0 means
    /// pressure mode changes nothing.
    pub pressure_pow: u8,
    /// Pressure mode starts at this many open connections in total.
    pub pressure_conns: usize,
    /// Pressure mode starts at this many incoming events per second.
    pub pressure_events_per_sec: f64,

    /// Keys that skip the per-key limit and proof of work.
    pub allow_pubkeys: HashSet<PublicKey>,
    /// Keys whose events are always refused.
    pub block_pubkeys: HashSet<PublicKey>,
    /// IPs that skip the connection and message limits.
    pub allow_ips: HashSet<IpAddr>,
    /// IPs that are always refused.
    pub block_ips: HashSet<IpAddr>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:7778".into(),
            upstream: "ws://127.0.0.1:7777".into(),
            trust_proxy: false,
            max_conn_per_ip: 20,
            max_new_conn_per_min: 60,
            msgs_per_sec: 20.0,
            max_message_bytes: 131_072,
            max_subs_per_conn: 20,
            max_filters_per_req: 20,
            verify_events: true,
            events_per_min_per_ip: 120,
            events_per_min_per_pubkey: 30,
            min_pow: 0,
            pressure_pow: 0,
            pressure_conns: 2000,
            pressure_events_per_sec: 50.0,
            allow_pubkeys: HashSet::new(),
            block_pubkeys: HashSet::new(),
            allow_ips: HashSet::new(),
            block_ips: HashSet::new(),
        }
    }
}

/// A number or other simple value. A value that does not parse is an error
/// rather than a silent fall back to the default.
fn value<T: FromStr>(name: &str, default: T) -> Result<T, String> {
    match env::var(name) {
        Ok(v) => v.trim().parse().map_err(|_| format!("{name}: cannot read \"{v}\"")),
        Err(_) => Ok(default),
    }
}

fn flag(name: &str, default: bool) -> Result<bool, String> {
    match env::var(name).as_deref().map(str::trim) {
        Ok("1" | "true" | "on") => Ok(true),
        Ok("0" | "false" | "off") => Ok(false),
        Ok(v) => Err(format!("{name}: use 1 or 0, not \"{v}\"")),
        Err(_) => Ok(default),
    }
}

/// A list separated by commas or whitespace.
fn list<T>(name: &str, parse: impl Fn(&str) -> Option<T>) -> Result<HashSet<T>, String>
where
    T: std::hash::Hash + Eq,
{
    let raw = env::var(name).unwrap_or_default();
    raw.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(|s| parse(s).ok_or_else(|| format!("{name}: cannot read \"{s}\"")))
        .collect()
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let d = Self::default();
        let pubkey = |s: &str| PublicKey::parse(s).ok();
        let ip = |s: &str| s.parse().ok().map(count_key);
        Ok(Self {
            listen: env::var("HASKSHIELD_LISTEN").unwrap_or(d.listen),
            upstream: env::var("HASKSHIELD_UPSTREAM").unwrap_or(d.upstream),
            trust_proxy: flag("HASKSHIELD_TRUST_PROXY", d.trust_proxy)?,
            max_conn_per_ip: value("HASKSHIELD_MAX_CONN_PER_IP", d.max_conn_per_ip)?,
            max_new_conn_per_min: value("HASKSHIELD_MAX_NEW_CONN_PER_MIN", d.max_new_conn_per_min)?,
            msgs_per_sec: value("HASKSHIELD_MSGS_PER_SEC", d.msgs_per_sec)?,
            max_message_bytes: value("HASKSHIELD_MAX_MESSAGE_BYTES", d.max_message_bytes)?,
            max_subs_per_conn: value("HASKSHIELD_MAX_SUBS_PER_CONN", d.max_subs_per_conn)?,
            max_filters_per_req: value("HASKSHIELD_MAX_FILTERS_PER_REQ", d.max_filters_per_req)?,
            verify_events: flag("HASKSHIELD_VERIFY_EVENTS", d.verify_events)?,
            events_per_min_per_ip: value(
                "HASKSHIELD_EVENTS_PER_MIN_PER_IP",
                d.events_per_min_per_ip,
            )?,
            events_per_min_per_pubkey: value(
                "HASKSHIELD_EVENTS_PER_MIN_PER_PUBKEY",
                d.events_per_min_per_pubkey,
            )?,
            min_pow: value("HASKSHIELD_MIN_POW", d.min_pow)?,
            pressure_pow: value("HASKSHIELD_PRESSURE_POW", d.pressure_pow)?,
            pressure_conns: value("HASKSHIELD_PRESSURE_CONNS", d.pressure_conns)?,
            pressure_events_per_sec: value(
                "HASKSHIELD_PRESSURE_EVENTS_PER_SEC",
                d.pressure_events_per_sec,
            )?,
            allow_pubkeys: list("HASKSHIELD_ALLOW_PUBKEYS", pubkey)?,
            block_pubkeys: list("HASKSHIELD_BLOCK_PUBKEYS", pubkey)?,
            allow_ips: list("HASKSHIELD_ALLOW_IPS", ip)?,
            block_ips: list("HASKSHIELD_BLOCK_IPS", ip)?,
        })
    }

    pub(crate) fn burst(&self) -> f64 {
        (self.msgs_per_sec * 5.0).max(1.0)
    }
}
