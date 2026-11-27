use futures_util::{SinkExt, StreamExt};
use haskshield::{Config, run};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_async, connect_async};

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
                    let mut ws = accept_async(stream).await.unwrap();
                    while let Some(Ok(msg)) = ws.next().await {
                        if msg.is_text() && ws.send(msg).await.is_err() {
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

/// Limits loose enough that a test only trips the one it sets itself.
fn loose() -> Config {
    Config {
        max_conn_per_ip: 100,
        max_new_conn_per_min: 10_000,
        msgs_per_sec: 10_000.0,
        ..Config::default()
    }
}

#[tokio::test]
async fn messages_pass_through_both_ways() {
    let url = format!("ws://{}", shield(loose()).await);
    let (mut ws, _) = connect_async(url.as_str()).await.unwrap();
    ws.send(Message::text(r#"["REQ","a",{}]"#)).await.unwrap();
    let reply = ws.next().await.unwrap().unwrap();
    assert_eq!(reply.into_text().unwrap().as_str(), r#"["REQ","a",{}]"#);
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
    let url = format!("ws://{}", shield(Config { msgs_per_sec: 1.0, ..loose() }).await);
    let (mut ws, _) = connect_async(url.as_str()).await.unwrap();
    for i in 0..10 {
        ws.send(Message::text(format!(r#"["EVENT",{{"id":"{i}"}}]"#))).await.unwrap();
    }
    let (mut passed, mut limited) = (0, 0);
    for _ in 0..10 {
        let reply = ws.next().await.unwrap().unwrap().into_text().unwrap();
        if reply.starts_with(r#"["OK""#) {
            assert!(reply.contains("rate-limited"), "got: {reply}");
            limited += 1;
        } else {
            passed += 1;
        }
    }
    assert_eq!((passed, limited), (5, 5));
}

#[tokio::test]
async fn an_oversized_message_closes_the_connection() {
    let url = format!("ws://{}", shield(Config { max_message_bytes: 1024, ..loose() }).await);
    let (mut ws, _) = connect_async(url.as_str()).await.unwrap();
    ws.send(Message::text("x".repeat(4096))).await.unwrap();
    // No echo comes back: the shield drops the connection instead.
    let next = ws.next().await;
    assert!(!matches!(next, Some(Ok(ref m)) if m.is_text()), "got: {next:?}");
}
