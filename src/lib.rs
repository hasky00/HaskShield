//! HaskShield: a websocket proxy that sits in front of a Nostr relay.
//!
//! What it does today:
//!
//! * Layer 1, connections: a cap on open connections per IP, a cap on new
//!   connections per IP per minute, and a deadline for the handshake.
//! * Layer 2, messages: a message rate limit per IP and a size limit per
//!   message.
//! * Plain HTTP requests (such as the NIP-11 relay information document)
//!   are passed through to the relay.
//!
//! IPv6 clients are counted per /64 network, because one attacker normally
//! controls a whole /64.

use std::collections::HashMap;
use std::env;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{accept_async_with_config, connect_async};

/// How long a client gets to send its request headers.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest a plain HTTP exchange may take.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
/// Length of the window used for counting new connections.
const NEW_CONN_WINDOW: Duration = Duration::from_secs(60);
/// A connection is closed after this many messages over the rate limit.
const MAX_STRIKES: u32 = 50;
/// Largest request head we are willing to read.
const MAX_HEAD_BYTES: usize = 8192;

type Error = Box<dyn std::error::Error + Send + Sync>;

/// Settings, read from environment variables.
#[derive(Clone, Debug)]
pub struct Config {
    /// Address HaskShield listens on, e.g. `0.0.0.0:7778`.
    pub listen: String,
    /// The relay behind the shield, e.g. `ws://127.0.0.1:7777`.
    pub upstream: String,
    /// Most connections one IP may hold open at the same time.
    pub max_conn_per_ip: usize,
    /// Most new connections one IP may open per minute.
    pub max_new_conn_per_min: u32,
    /// Messages per second one IP may send, across all its connections.
    /// Short bursts of up to five times this are allowed.
    pub msgs_per_sec: f64,
    /// Largest single message a client may send, in bytes.
    pub max_message_bytes: usize,
    /// Read the client IP from `X-Forwarded-For`. Turn this on only when
    /// HaskShield runs behind a reverse proxy such as Caddy; otherwise a
    /// client could fake its IP.
    pub trust_proxy: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:7778".into(),
            upstream: "ws://127.0.0.1:7777".into(),
            max_conn_per_ip: 20,
            max_new_conn_per_min: 60,
            msgs_per_sec: 20.0,
            max_message_bytes: 131_072,
            trust_proxy: false,
        }
    }
}

impl Config {
    pub fn from_env() -> Self {
        fn num<T: std::str::FromStr>(name: &str, default: T) -> T {
            env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
        }
        let d = Self::default();
        Self {
            listen: env::var("HASKSHIELD_LISTEN").unwrap_or(d.listen),
            upstream: env::var("HASKSHIELD_UPSTREAM").unwrap_or(d.upstream),
            max_conn_per_ip: num("HASKSHIELD_MAX_CONN_PER_IP", d.max_conn_per_ip),
            max_new_conn_per_min: num("HASKSHIELD_MAX_NEW_CONN_PER_MIN", d.max_new_conn_per_min),
            msgs_per_sec: num("HASKSHIELD_MSGS_PER_SEC", d.msgs_per_sec),
            max_message_bytes: num("HASKSHIELD_MAX_MESSAGE_BYTES", d.max_message_bytes),
            trust_proxy: env::var("HASKSHIELD_TRUST_PROXY").is_ok_and(|v| v == "1"),
        }
    }

    fn burst(&self) -> f64 {
        (self.msgs_per_sec * 5.0).max(1.0)
    }
}

/// What we remember about one IP.
struct IpState {
    conns: usize,
    window_start: Instant,
    new_conns: u32,
    tokens: f64,
    last_refill: Instant,
}

type Shared = Arc<Mutex<HashMap<IpAddr, IpState>>>;

/// One open connection slot for an IP. The slot is given back when dropped.
struct Slot {
    shared: Shared,
    ip: IpAddr,
}

impl Slot {
    fn acquire(shared: &Shared, ip: IpAddr, cfg: &Config) -> Option<Self> {
        let now = Instant::now();
        let mut map = shared.lock().unwrap();
        let state = map.entry(ip).or_insert_with(|| IpState {
            conns: 0,
            window_start: now,
            new_conns: 0,
            tokens: cfg.burst(),
            last_refill: now,
        });
        if now.duration_since(state.window_start) >= NEW_CONN_WINDOW {
            state.window_start = now;
            state.new_conns = 0;
        }
        // Refused attempts count too, so hammering does not pay off.
        state.new_conns = state.new_conns.saturating_add(1);
        if state.new_conns > cfg.max_new_conn_per_min || state.conns >= cfg.max_conn_per_ip {
            return None;
        }
        state.conns += 1;
        Some(Self { shared: shared.clone(), ip })
    }

    /// Take one message token for this IP. False means over the limit.
    fn allow_message(&self, cfg: &Config) -> bool {
        let now = Instant::now();
        let mut map = self.shared.lock().unwrap();
        let Some(state) = map.get_mut(&self.ip) else {
            return false;
        };
        let gained = now.duration_since(state.last_refill).as_secs_f64() * cfg.msgs_per_sec;
        state.tokens = (state.tokens + gained).min(cfg.burst());
        state.last_refill = now;
        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut map = self.shared.lock().unwrap();
        if let Some(state) = map.get_mut(&self.ip) {
            state.conns = state.conns.saturating_sub(1);
        }
    }
}

/// Forget IPs that have no open connections and no recent attempts.
fn prune(shared: &Shared) {
    let now = Instant::now();
    shared.lock().unwrap().retain(|_, s| {
        s.conns > 0 || now.duration_since(s.window_start) < NEW_CONN_WINDOW
    });
}

/// The address a client is counted under: IPv4 as is, IPv6 by /64 network.
fn count_key(ip: IpAddr) -> IpAddr {
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

/// Value of a header in a raw request head, if present.
fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// The IP to count a connection against.
fn client_ip(head: &str, peer: IpAddr, trust_proxy: bool) -> IpAddr {
    let ip = if trust_proxy {
        header(head, "x-forwarded-for")
            // The last entry is the one our own reverse proxy added.
            .and_then(|v| v.rsplit(',').next())
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(peer)
    } else {
        peer
    };
    count_key(ip)
}

/// Look at the request head without taking it off the socket.
async fn peek_head(stream: &TcpStream) -> Option<String> {
    let mut buf = vec![0u8; MAX_HEAD_BYTES];
    loop {
        let n = stream.peek(&mut buf).await.ok()?;
        if n == 0 {
            return None;
        }
        if let Some(end) = buf[..n].windows(4).position(|w| w == b"\r\n\r\n") {
            return Some(String::from_utf8_lossy(&buf[..end]).into_owned());
        }
        if n == buf.len() {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// `host:port` of the relay, for plain HTTP requests.
fn upstream_http_addr(upstream: &str) -> Option<String> {
    let rest = upstream.strip_prefix("ws://")?;
    let host = rest.split('/').next()?;
    Some(if host.contains(':') { host.to_string() } else { format!("{host}:80") })
}

async fn refuse(mut stream: TcpStream, status: &str) {
    let msg = format!("HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    let _ = stream.write_all(msg.as_bytes()).await;
}

/// The reply a client gets for a message that was over the rate limit.
fn rate_limit_reply(msg: &Message) -> Message {
    const WHY: &str = "rate-limited: slow down";
    let parsed = msg
        .to_text()
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(t).ok());
    let reply = match parsed.as_ref().and_then(|v| v.as_array()) {
        Some(a) if a.first().and_then(|k| k.as_str()) == Some("EVENT") => a
            .get(1)
            .and_then(|e| e.get("id"))
            .and_then(|id| id.as_str())
            .map(|id| serde_json::json!(["OK", id, false, WHY])),
        Some(a) if matches!(a.first().and_then(|k| k.as_str()), Some("REQ" | "COUNT")) => a
            .get(1)
            .and_then(|s| s.as_str())
            .map(|sub| serde_json::json!(["CLOSED", sub, WHY])),
        _ => None,
    }
    .unwrap_or_else(|| serde_json::json!(["NOTICE", WHY]));
    Message::text(reply.to_string())
}

/// Accept connections forever.
pub async fn run(cfg: Config, listener: TcpListener) {
    let shared: Shared = Arc::default();

    let pruned = shared.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            prune(&pruned);
        }
    });

    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            continue;
        };
        let cfg = cfg.clone();
        let shared = shared.clone();
        tokio::spawn(async move {
            let _ = handle(cfg, shared, stream, peer).await;
        });
    }
}

async fn handle(
    cfg: Config,
    shared: Shared,
    stream: TcpStream,
    peer: SocketAddr,
) -> Result<(), Error> {
    // A client that does not send its headers in time is dropped.
    let Ok(Some(head)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, peek_head(&stream)).await else {
        return Ok(());
    };

    let ip = client_ip(&head, peer.ip(), cfg.trust_proxy);
    let Some(slot) = Slot::acquire(&shared, ip, &cfg) else {
        refuse(stream, "429 Too Many Requests").await;
        return Ok(());
    };

    let wants_websocket =
        header(&head, "upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    if wants_websocket {
        websocket(cfg, slot, stream).await
    } else {
        http(cfg, stream).await
    }
}

/// Pass a plain HTTP request (NIP-11, landing page) straight to the relay.
async fn http(cfg: Config, mut stream: TcpStream) -> Result<(), Error> {
    let Some(addr) = upstream_http_addr(&cfg.upstream) else {
        refuse(stream, "502 Bad Gateway").await;
        return Ok(());
    };
    let Ok(mut relay) = TcpStream::connect(addr).await else {
        refuse(stream, "502 Bad Gateway").await;
        return Ok(());
    };
    let _ = tokio::time::timeout(
        HTTP_TIMEOUT,
        tokio::io::copy_bidirectional(&mut stream, &mut relay),
    )
    .await;
    Ok(())
}

async fn websocket(cfg: Config, slot: Slot, stream: TcpStream) -> Result<(), Error> {
    let limits = WebSocketConfig::default()
        .max_message_size(Some(cfg.max_message_bytes))
        .max_frame_size(Some(cfg.max_message_bytes));
    let client = accept_async_with_config(stream, Some(limits)).await?;
    let (relay, _) = connect_async(cfg.upstream.as_str()).await?;

    let (mut client_tx, mut client_rx) = client.split();
    let (mut relay_tx, mut relay_rx) = relay.split();
    let mut strikes = 0u32;

    // When either side closes, the loop ends and both sides are dropped.
    loop {
        tokio::select! {
            from_client = client_rx.next() => {
                // An oversized message arrives here as an error.
                let Some(Ok(msg)) = from_client else { break };
                if msg.is_close() {
                    let _ = relay_tx.send(msg).await;
                    break;
                }
                // Pings and pongs are answered by the websocket layer.
                if !(msg.is_text() || msg.is_binary()) {
                    continue;
                }
                if !slot.allow_message(&cfg) {
                    strikes += 1;
                    if strikes > MAX_STRIKES
                        || client_tx.send(rate_limit_reply(&msg)).await.is_err()
                    {
                        break;
                    }
                    continue;
                }
                if relay_tx.send(msg).await.is_err() {
                    break;
                }
            }
            from_relay = relay_rx.next() => {
                let Some(Ok(msg)) = from_relay else { break };
                if !(msg.is_text() || msg.is_binary()) {
                    continue;
                }
                if client_tx.send(msg).await.is_err() {
                    break;
                }
            }
        }
    }
    Ok(())
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
    fn forwarded_ip_is_used_only_when_trusted() {
        let head = "GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 9.9.9.9, 203.0.113.7";
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(client_ip(head, peer, false), peer);
        assert_eq!(client_ip(head, peer, true), "203.0.113.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn rate_limit_replies_match_the_message_kind() {
        let event = Message::text(r#"["EVENT",{"id":"abc"}]"#);
        assert_eq!(
            rate_limit_reply(&event).to_text().unwrap(),
            r#"["OK","abc",false,"rate-limited: slow down"]"#
        );
        let req = Message::text(r#"["REQ","sub1",{}]"#);
        assert_eq!(
            rate_limit_reply(&req).to_text().unwrap(),
            r#"["CLOSED","sub1","rate-limited: slow down"]"#
        );
        let junk = Message::text("not json");
        assert_eq!(
            rate_limit_reply(&junk).to_text().unwrap(),
            r#"["NOTICE","rate-limited: slow down"]"#
        );
    }
}
