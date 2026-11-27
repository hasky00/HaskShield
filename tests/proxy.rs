use futures_util::{SinkExt, StreamExt};
use haskshield::{Config, run};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_async, connect_async};

/// A stand-in relay that sends every message straight back.
async fn echo_relay() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut ws = accept_async(stream).await.unwrap();
                while let Some(Ok(msg)) = ws.next().await {
                    if msg.is_text() && ws.send(msg).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    format!("ws://{addr}")
}

async fn shield(upstream: String, max_conn_per_ip: usize) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = Config {
        listen: addr.to_string(),
        upstream,
        max_conn_per_ip,
        trust_proxy: false,
    };
    tokio::spawn(run(cfg, listener));
    format!("ws://{addr}")
}

#[tokio::test]
async fn messages_pass_through_both_ways() {
    let url = shield(echo_relay().await, 5).await;
    let (mut ws, _) = connect_async(url.as_str()).await.unwrap();
    ws.send(Message::text(r#"["REQ","a",{}]"#)).await.unwrap();
    let reply = ws.next().await.unwrap().unwrap();
    assert_eq!(reply.into_text().unwrap().as_str(), r#"["REQ","a",{}]"#);
}

#[tokio::test]
async fn extra_connections_from_one_ip_are_refused() {
    let url = shield(echo_relay().await, 2).await;
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
