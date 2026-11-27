//! HaskShield: a websocket proxy that sits in front of a Nostr relay.
//!
//! This first version does one thing: layer 1, a cap on how many
//! connections a single IP may hold open. Everything else passes through
//! to the relay untouched.

use std::collections::HashMap;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::{accept_hdr_async, connect_async};

/// Settings, read from environment variables.
#[derive(Clone, Debug)]
pub struct Config {
    /// Address HaskShield listens on, e.g. `0.0.0.0:7778`.
    pub listen: String,
    /// The relay behind the shield, e.g. `ws://127.0.0.1:7777`.
    pub upstream: String,
    /// Most connections one IP may hold open at the same time.
    pub max_conn_per_ip: usize,
    /// Read the client IP from `X-Forwarded-For`. Turn this on only when
    /// HaskShield runs behind a reverse proxy such as Caddy; otherwise a
    /// client could fake its IP.
    pub trust_proxy: bool,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            listen: env::var("HASKSHIELD_LISTEN").unwrap_or_else(|_| "0.0.0.0:7778".into()),
            upstream: env::var("HASKSHIELD_UPSTREAM")
                .unwrap_or_else(|_| "ws://127.0.0.1:7777".into()),
            max_conn_per_ip: env::var("HASKSHIELD_MAX_CONN_PER_IP")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(20),
            trust_proxy: env::var("HASKSHIELD_TRUST_PROXY").is_ok_and(|v| v == "1"),
        }
    }
}

type Counts = Arc<Mutex<HashMap<IpAddr, usize>>>;

/// One open connection slot for an IP. The slot is given back when dropped.
struct Slot {
    counts: Counts,
    ip: IpAddr,
}

impl Slot {
    fn acquire(counts: &Counts, ip: IpAddr, max: usize) -> Option<Self> {
        let mut map = counts.lock().unwrap();
        let n = map.entry(ip).or_insert(0);
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(Self { counts: counts.clone(), ip })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut map = self.counts.lock().unwrap();
        if let Some(n) = map.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

/// The IP to count a connection against.
fn client_ip(req: &Request, peer: IpAddr, trust_proxy: bool) -> IpAddr {
    if !trust_proxy {
        return peer;
    }
    req.headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        // The last entry is the one our own reverse proxy added.
        .and_then(|v| v.rsplit(',').next())
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(peer)
}

/// Accept connections forever.
pub async fn run(cfg: Config, listener: TcpListener) {
    let counts: Counts = Arc::default();
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            continue;
        };
        let cfg = cfg.clone();
        let counts = counts.clone();
        tokio::spawn(async move {
            let _ = handle(cfg, counts, stream, peer).await;
        });
    }
}

async fn handle(
    cfg: Config,
    counts: Counts,
    stream: TcpStream,
    peer: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Layer 1: refuse the handshake when this IP already has too many
    // connections open.
    let mut slot = None;
    let client = accept_hdr_async(stream, |req: &Request, resp: Response| {
        let ip = client_ip(req, peer.ip(), cfg.trust_proxy);
        match Slot::acquire(&counts, ip, cfg.max_conn_per_ip) {
            Some(s) => {
                slot = Some(s);
                Ok(resp)
            }
            None => {
                let mut refuse = ErrorResponse::new(Some("too many connections".into()));
                *refuse.status_mut() = StatusCode::TOO_MANY_REQUESTS;
                Err(refuse)
            }
        }
    })
    .await?;
    let _slot = slot;

    let (relay, _) = connect_async(cfg.upstream.as_str()).await?;

    let (mut client_tx, mut client_rx) = client.split();
    let (mut relay_tx, mut relay_rx) = relay.split();

    let to_relay = async {
        while let Some(Ok(msg)) = client_rx.next().await {
            if relay_tx.send(msg).await.is_err() {
                break;
            }
        }
    };
    let to_client = async {
        while let Some(Ok(msg)) = relay_rx.next().await {
            if client_tx.send(msg).await.is_err() {
                break;
            }
        }
    };

    // When either side closes, the other is dropped too.
    tokio::select! {
        _ = to_relay => {}
        _ = to_client => {}
    }
    Ok(())
}
