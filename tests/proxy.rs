use futures_util::{SinkExt, StreamExt};
use haskshield::{Config, run};
use nostr::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, accept_async, connect_async};

type Client = WebSocketStream<MaybeTlsStream<TcpStream>>;

const INFO: &str = r#"{"name":"test relay"}"#;

/// A stand-in relay. Websocket clients get every message sent straight
/// back; plain HTTP clients get a small relay information document.
async fn fake_relay() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut head = [0u8; 2048];
                let n = stream.peek(&mut head).await.unwrap();
                let head = String::from_utf8_lossy(&head[..n]).to_lowercase();
                if head.contains("upgrade: websocket") {
                    let seen_ip = head
                        .lines()
                        .find_map(|l| l.strip_prefix("x-forwarded-for:"))
                        .unwrap_or("none")
                        .trim()
                        .to_string();
                    let mut ws = accept_async(stream).await.unwrap();
                    while let Some(Ok(msg)) = ws.next().await {
                        if !msg.is_text() {
                            continue;
                        }
                        // A subscription called "whoami" is answered with
                        // the client IP the relay was told about.
                        let reply = match msg.to_text() {
                            Ok(t) if t.contains(r#""whoami""#) => Message::text(seen_ip.clone()),
                            _ => msg,
                        };
                        if ws.send(reply).await.is_err() {
                            break;
                        }
                    }
                } else {
                    let mut sink = [0u8; 2048];
                    let _ = stream.read(&mut sink).await;
                    let reply = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/nostr+json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{INFO}",
                        INFO.len()
                    );
                    let _ = stream.write_all(reply.as_bytes()).await;
                }
            });
        }
    });
    format!("ws://{addr}")
}

/// Start a shield in front of a fake relay. Returns its `host:port`.
async fn shield(cfg: Config) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = Config { listen: addr.to_string(), upstream: fake_relay().await, ..cfg };
    tokio::spawn(run(cfg, listener));
    addr.to_string()
}

/// Start a shield and connect one client to it.
async fn connect(cfg: Config) -> Client {
    let url = format!("ws://{}", shield(cfg).await);
    connect_async(url.as_str()).await.unwrap().0
}

/// Limits loose enough that a test only trips the one it sets itself.
fn loose() -> Config {
    Config {
        max_conn_per_ip: 100,
        max_new_conn_per_min: 10_000,
        msgs_per_sec: 10_000.0,
        events_per_min_per_ip: 0,
        events_per_min_per_pubkey: 0,
        ..Config::default()
    }
}

/// A fixed test key. `n` picks which one.
fn keys(n: u8) -> Keys {
    Keys::parse(&format!("{:064x}", u64::from(n) + 1)).unwrap()
}

fn note(keys: &Keys, content: &str) -> Event {
    EventBuilder::new(Kind::TextNote, content).finalize(keys).unwrap()
}

/// A note whose id carries at least `bits` of proof of work.
fn mined_note(keys: &Keys, bits: u8) -> Event {
    (0..).map(|i| note(keys, &format!("mined {i}"))).find(|e| e.check_pow(bits)).unwrap()
}

fn publish(event: &Event) -> String {
    format!(r#"["EVENT",{}]"#, event.as_json())
}

/// Send one message and return the reply.
async fn ask(ws: &mut Client, text: &str) -> String {
    ws.send(Message::text(text)).await.unwrap();
    ws.next().await.unwrap().unwrap().into_text().unwrap().to_string()
}

#[tokio::test]
async fn messages_pass_through_both_ways() {
    let mut ws = connect(loose()).await;
    assert_eq!(ask(&mut ws, r#"["REQ","a",{}]"#).await, r#"["REQ","a",{}]"#);
}

#[tokio::test]
async fn the_relay_is_told_the_client_ip() {
    let mut ws = connect(loose()).await;
    assert_eq!(ask(&mut ws, r#"["REQ","whoami",{}]"#).await, "127.0.0.1");
}

#[tokio::test]
async fn extra_connections_from_one_ip_are_refused() {
    let url = format!("ws://{}", shield(Config { max_conn_per_ip: 2, ..loose() }).await);
    let (_a, _) = connect_async(url.as_str()).await.unwrap();
    let (b, _) = connect_async(url.as_str()).await.unwrap();
    assert!(connect_async(url.as_str()).await.is_err(), "third should be refused");

    // Closing one frees its slot.
    drop(b);
    let mut ok = false;
    for _ in 0..50 {
        if connect_async(url.as_str()).await.is_ok() {
            ok = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(ok, "slot should be free again after a connection closes");
}

#[tokio::test]
async fn too_many_new_connections_per_minute_are_refused() {
    let url = format!("ws://{}", shield(Config { max_new_conn_per_min: 3, ..loose() }).await);
    for _ in 0..3 {
        let (ws, _) = connect_async(url.as_str()).await.unwrap();
        drop(ws);
    }
    assert!(connect_async(url.as_str()).await.is_err(), "fourth should be refused");
}

#[tokio::test]
async fn blocked_ips_are_refused_and_allowed_ips_skip_the_limits() {
    let local = "127.0.0.1".parse().unwrap();
    let blocked = Config { block_ips: [local].into(), ..loose() };
    let url = format!("ws://{}", shield(blocked).await);
    assert!(connect_async(url.as_str()).await.is_err());

    let allowed = Config { allow_ips: [local].into(), max_conn_per_ip: 1, ..loose() };
    let url = format!("ws://{}", shield(allowed).await);
    let (_a, _) = connect_async(url.as_str()).await.unwrap();
    assert!(connect_async(url.as_str()).await.is_ok(), "allowed IP is not capped");
}

#[tokio::test]
async fn relay_information_document_passes_through() {
    let addr = shield(loose()).await;
    let mut stream = TcpStream::connect(&addr).await.unwrap();
    let request =
        format!("GET / HTTP/1.1\r\nHost: {addr}\r\nAccept: application/nostr+json\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).await.unwrap();
    assert!(reply.starts_with("HTTP/1.1 200 OK"), "got: {reply}");
    assert!(reply.ends_with(INFO), "got: {reply}");
}

#[tokio::test]
async fn messages_over_the_rate_limit_get_a_rate_limited_reply() {
    // One message per second, so the burst allowance is five.
    let mut ws = connect(Config { msgs_per_sec: 1.0, ..loose() }).await;
    for i in 0..10 {
        ws.send(Message::text(format!(r#"["COUNT","{i}",{{}}]"#))).await.unwrap();
    }
    let (mut passed, mut limited) = (0, 0);
    for _ in 0..10 {
        let reply = ws.next().await.unwrap().unwrap().into_text().unwrap();
        if reply.starts_with(r#"["CLOSED""#) {
            assert!(reply.contains("rate-limited: slow down"), "got: {reply}");
            limited += 1;
        } else {
            passed += 1;
        }
    }
    assert_eq!((passed, limited), (5, 5));
}

#[tokio::test]
async fn an_oversized_message_closes_the_connection() {
    let mut ws = connect(Config { max_message_bytes: 1024, ..loose() }).await;
    ws.send(Message::text("x".repeat(4096))).await.unwrap();
    // No echo comes back: the shield drops the connection instead.
    let next = ws.next().await;
    assert!(!matches!(next, Some(Ok(ref m)) if m.is_text()), "got: {next:?}");
}

#[tokio::test]
async fn junk_never_reaches_the_relay() {
    let mut ws = connect(loose()).await;
    assert_eq!(ask(&mut ws, "hello").await, r#"["NOTICE","invalid: not a Nostr message"]"#);
    let reply = ask(&mut ws, r#"["EVENT",{"id":"abc","content":"no signature"}]"#).await;
    assert_eq!(reply, r#"["OK","abc",false,"invalid: malformed event"]"#);
}

#[tokio::test]
async fn a_properly_signed_event_passes() {
    let mut ws = connect(loose()).await;
    // Content with characters that are easy to get wrong when hashing.
    let event = note(&keys(0), "hej \"verden\"\n\ttab \\ æøå 🧁 \u{1}");
    let sent = publish(&event);
    assert_eq!(ask(&mut ws, &sent).await, sent);
}

#[tokio::test]
async fn a_tampered_event_is_refused() {
    let mut ws = connect(loose()).await;
    let mut event = note(&keys(0), "original");
    event.content = "changed after signing".into();
    let reply = ask(&mut ws, &publish(&event)).await;
    assert_eq!(
        reply,
        format!(r#"["OK","{}",false,"invalid: bad event id or signature"]"#, event.id)
    );
}

#[tokio::test]
async fn a_key_posting_too_fast_is_limited_but_other_keys_are_not() {
    let mut ws = connect(Config { events_per_min_per_pubkey: 2, ..loose() }).await;
    for i in 0..2 {
        let sent = publish(&note(&keys(0), &format!("note {i}")));
        assert_eq!(ask(&mut ws, &sent).await, sent);
    }
    let reply = ask(&mut ws, &publish(&note(&keys(0), "one too many"))).await;
    assert!(reply.contains("rate-limited: this key is posting too fast"), "got: {reply}");

    let other = publish(&note(&keys(1), "someone else"));
    assert_eq!(ask(&mut ws, &other).await, other);
}

#[tokio::test]
async fn an_address_cannot_dodge_the_limit_by_changing_keys() {
    let mut ws = connect(Config { events_per_min_per_ip: 2, ..loose() }).await;
    for n in 0..2 {
        let sent = publish(&note(&keys(n), "hello"));
        assert_eq!(ask(&mut ws, &sent).await, sent);
    }
    let reply = ask(&mut ws, &publish(&note(&keys(2), "a third key"))).await;
    assert!(reply.contains("rate-limited: too many events from your address"), "got: {reply}");
}

#[tokio::test]
async fn a_blocked_key_cannot_post() {
    let blocked = keys(0);
    let cfg = Config { block_pubkeys: [blocked.public_key()].into(), ..loose() };
    let mut ws = connect(cfg).await;
    let reply = ask(&mut ws, &publish(&note(&blocked, "hello"))).await;
    assert!(reply.contains("blocked: this key may not post here"), "got: {reply}");
}

#[tokio::test]
async fn proof_of_work_is_required_when_set() {
    let friend = keys(1);
    let cfg = Config { min_pow: 8, allow_pubkeys: [friend.public_key()].into(), ..loose() };
    let mut ws = connect(cfg).await;

    let plain = (0..).map(|i| note(&keys(0), &format!("plain {i}"))).find(|e| !e.check_pow(8));
    let reply = ask(&mut ws, &publish(&plain.unwrap())).await;
    assert!(reply.contains("pow: difficulty 8 required"), "got: {reply}");

    let mined = publish(&mined_note(&keys(0), 8));
    assert_eq!(ask(&mut ws, &mined).await, mined);

    // A key on the allow list posts without proof of work.
    let from_friend = (0..).map(|i| note(&friend, &format!("hi {i}"))).find(|e| !e.check_pow(8));
    let sent = publish(&from_friend.unwrap());
    assert_eq!(ask(&mut ws, &sent).await, sent);
}

#[tokio::test]
async fn pressure_mode_asks_for_proof_of_work() {
    // A threshold of zero connections means pressure from the first moment.
    let cfg = Config { pressure_conns: 0, pressure_pow: 8, ..loose() };
    let mut ws = connect(cfg).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let plain = (0..).map(|i| note(&keys(0), &format!("plain {i}"))).find(|e| !e.check_pow(8));
    let reply = ask(&mut ws, &publish(&plain.unwrap())).await;
    assert!(reply.contains("pow: relay is under heavy load"), "got: {reply}");

    // Reading still works under pressure.
    assert_eq!(ask(&mut ws, r#"["REQ","a",{}]"#).await, r#"["REQ","a",{}]"#);
}

#[tokio::test]
async fn open_subscriptions_per_connection_are_capped() {
    let mut ws = connect(Config { max_subs_per_conn: 2, ..loose() }).await;
    for sub in ["a", "b"] {
        let req = format!(r#"["REQ","{sub}",{{}}]"#);
        assert_eq!(ask(&mut ws, &req).await, req);
    }
    let reply = ask(&mut ws, r#"["REQ","c",{}]"#).await;
    assert_eq!(reply, r#"["CLOSED","c","rate-limited: too many open subscriptions"]"#);

    // Replacing an open subscription is fine, and closing one frees a place.
    assert_eq!(ask(&mut ws, r#"["REQ","a",{}]"#).await, r#"["REQ","a",{}]"#);
    assert_eq!(ask(&mut ws, r#"["CLOSE","a"]"#).await, r#"["CLOSE","a"]"#);
    assert_eq!(ask(&mut ws, r#"["REQ","c",{}]"#).await, r#"["REQ","c",{}]"#);
}

#[tokio::test]
async fn too_many_filters_in_one_request_are_refused() {
    let mut ws = connect(Config { max_filters_per_req: 2, ..loose() }).await;
    let reply = ask(&mut ws, r#"["REQ","a",{},{},{}]"#).await;
    assert_eq!(reply, r#"["CLOSED","a","invalid: too many filters"]"#);
}
