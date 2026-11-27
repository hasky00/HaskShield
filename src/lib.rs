//! HaskShield: a websocket proxy that sits in front of a Nostr relay and
//! turns spam and floods away before they reach it.
//!
//! Checks run cheapest first:
//!
//! 1. Connections: open connections per IP, new connections per IP per
//!    minute, a deadline for the handshake, lists of allowed and blocked IPs.
//! 2. Messages: message rate per IP, message size, open subscriptions per
//!    connection, filters per request.
//! 3. Events: id and signature, blocked keys, event rate per IP and per key.
//! 4. Proof of work (NIP-13), always or only while under pressure.
//!
//! Plain HTTP requests (such as the NIP-11 relay information document) are
//! passed through to the relay.

mod check;
mod config;
mod limits;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{accept_async_with_config, connect_async_with_config};

use check::{Conn, Verdict, rate_limit_reply};
pub use config::Config;
use limits::{Shield, Slot, count_key};

/// How long a client gets to send its request headers.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest a plain HTTP exchange may take.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
/// A connection is closed after this many messages over the rate limit.
const MAX_STRIKES: u32 = 50;
/// Read buffer per websocket. Small, because most connections sit idle.
const READ_BUFFER_BYTES: usize = 4096;
/// Largest request head we are willing to read.
const MAX_HEAD_BYTES: usize = 8192;

type Error = Box<dyn std::error::Error + Send + Sync>;

/// Value of a header in a raw request head, if present.
fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// The client's real IP address.
fn client_ip(head: &str, peer: IpAddr, trust_proxy: bool) -> IpAddr {
    if !trust_proxy {
        return peer;
    }
    header(head, "x-forwarded-for")
        // The last entry is the one our own reverse proxy added.
        .and_then(|v| v.rsplit(',').next())
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(peer)
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

/// Accept connections forever.
pub async fn run(cfg: Config, listener: TcpListener) {
    let shield = Shield::new(cfg);
    tokio::spawn(shield.clone().housekeeping());
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            continue;
        };
        let shield = shield.clone();
        tokio::spawn(async move {
            let _ = handle(shield, stream, peer).await;
        });
    }
}

async fn handle(shield: Arc<Shield>, stream: TcpStream, peer: SocketAddr) -> Result<(), Error> {
    // A client that does not send its headers in time is dropped.
    let Ok(Some(head)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, peek_head(&stream)).await else {
        return Ok(());
    };

    let ip = client_ip(&head, peer.ip(), shield.cfg.trust_proxy);
    let Some(slot) = Slot::acquire(&shield, count_key(ip)) else {
        shield.stats.conns_refused.fetch_add(1, Relaxed);
        refuse(stream, "429 Too Many Requests").await;
        return Ok(());
    };
    shield.stats.conns_accepted.fetch_add(1, Relaxed);

    let wants_websocket =
        header(&head, "upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    if wants_websocket {
        websocket(&shield, slot, stream, ip).await
    } else {
        http(&shield, stream).await
    }
}

/// Pass a plain HTTP request (NIP-11, landing page) straight to the relay.
async fn http(shield: &Shield, mut stream: TcpStream) -> Result<(), Error> {
    let Some(addr) = upstream_http_addr(&shield.cfg.upstream) else {
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

async fn websocket(
    shield: &Shield,
    slot: Slot,
    stream: TcpStream,
    ip: IpAddr,
) -> Result<(), Error> {
    let cfg = &shield.cfg;
    let stats = &shield.stats;
    // The library's default read buffer is 128 KiB per socket. With two
    // sockets per client that is a quarter of a megabyte each, far too much
    // for a shield that must hold many idle connections.
    let small = WebSocketConfig::default().read_buffer_size(READ_BUFFER_BYTES);
    let limits = small
        .max_message_size(Some(cfg.max_message_bytes))
        .max_frame_size(Some(cfg.max_message_bytes));
    let client = accept_async_with_config(stream, Some(limits)).await?;

    // Tell the relay who the client really is, so its own logs and limits
    // do not see every connection as coming from the shield.
    let mut request = cfg.upstream.as_str().into_client_request()?;
    let ip = HeaderValue::from_str(&ip.to_string())?;
    request.headers_mut().insert("x-forwarded-for", ip.clone());
    request.headers_mut().insert("x-real-ip", ip);
    let (relay, _) = connect_async_with_config(request, Some(small), false).await?;

    let (mut client_tx, mut client_rx) = client.split();
    let (mut relay_tx, mut relay_rx) = relay.split();
    let mut conn = Conn::default();
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
                // Pings and pongs are answered by the websocket layer, and
                // Nostr has no binary messages.
                let Ok(text) = msg.to_text() else { continue };
                if !msg.is_text() {
                    continue;
                }

                if !slot.allow_message() {
                    stats.rate_limited.fetch_add(1, Relaxed);
                    strikes += 1;
                    if strikes > MAX_STRIKES
                        || client_tx.send(rate_limit_reply(&msg)).await.is_err()
                    {
                        break;
                    }
                    continue;
                }
                match conn.check(shield, &slot, text) {
                    Verdict::Forward => {
                        stats.forwarded.fetch_add(1, Relaxed);
                        if relay_tx.send(msg).await.is_err() {
                            break;
                        }
                    }
                    Verdict::Refuse(reply) => {
                        if client_tx.send(reply).await.is_err() {
                            break;
                        }
                    }
                }
            }
            from_relay = relay_rx.next() => {
                let Some(Ok(msg)) = from_relay else { break };
                if !msg.is_text() {
                    continue;
                }
                if let Ok(text) = msg.to_text() {
                    conn.saw_from_relay(text);
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
    use tokio_tungstenite::tungstenite::Message;

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
