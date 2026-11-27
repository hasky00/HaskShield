//! A small load generator, for measuring HaskShield on your own machine.
//!
//! It starts a stand-in relay, then opens many connections through a
//! running HaskShield and sends one request on each.
//!
//! ```text
//! # terminal 1: the stand-in relay listens on 127.0.0.1:7777
//! # terminal 2:
//! HASKSHIELD_ALLOW_IPS=127.0.0.1 cargo run --release
//! # terminal 1:
//! cargo run --release --example load -- 5000
//! ```

use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_async, connect_async};

#[tokio::main]
async fn main() {
    let count: usize = std::env::args().nth(1).and_then(|n| n.parse().ok()).unwrap_or(1000);
    let shield = std::env::args().nth(2).unwrap_or_else(|| "ws://127.0.0.1:7778".into());

    let relay = TcpListener::bind("127.0.0.1:7777").await.expect("port 7777 is taken");
    tokio::spawn(async move {
        while let Ok((stream, _)) = relay.accept().await {
            tokio::spawn(async move {
                let Ok(mut ws) = accept_async(stream).await else { return };
                while let Some(Ok(msg)) = ws.next().await {
                    if msg.is_text() && ws.send(msg).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let started = Instant::now();
    let mut clients = Vec::with_capacity(count);
    let mut failed = 0;
    for i in 0..count {
        match connect_async(shield.as_str()).await {
            Ok((mut ws, _)) => {
                let req = format!(r#"["REQ","load{i}",{{}}]"#);
                let echoed = ws.send(Message::text(req.clone())).await.is_ok()
                    && matches!(ws.next().await, Some(Ok(m)) if m.to_text().ok() == Some(&req));
                if echoed { clients.push(ws) } else { failed += 1 }
            }
            Err(_) => failed += 1,
        }
    }
    println!(
        "{} connections open and answering through {shield}, {failed} failed, in {:.1}s",
        clients.len(),
        started.elapsed().as_secs_f64()
    );
    println!("holding them open for 15 seconds; measure the haskshield process now");
    tokio::time::sleep(Duration::from_secs(15)).await;
}
