//! Checks a running HaskShield (or a relay) from the outside, the way a
//! client would see it.
//!
//! ```text
//! cargo run --example check -- ws://127.0.0.1:7778
//! ```
//!
//! It reads the relay information document, opens a subscription, and
//! publishes two events from a throwaway key: a good one, which should be
//! accepted, and a tampered one, which the shield should refuse. Both are
//! ephemeral (kind 20001), so the relay does not store them.

use std::process::ExitCode;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use nostr::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

const WAIT: Duration = Duration::from_secs(10);

/// Fetch the relay information document over plain HTTP.
async fn info(host: &str) -> Result<String, String> {
    let mut stream = TcpStream::connect(host).await.map_err(|e| e.to_string())?;
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nAccept: application/nostr+json\r\n\
         Connection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.map_err(|e| e.to_string())?;
    let mut reply = Vec::new();
    let _ = tokio::time::timeout(WAIT, stream.read_to_end(&mut reply)).await;
    let reply = String::from_utf8_lossy(&reply);
    let (head, body) = reply.split_once("\r\n\r\n").ok_or("no HTTP reply")?;
    let status = head.lines().next().unwrap_or_default();
    if !status.contains(" 200") {
        return Err(format!("status was \"{status}\""));
    }
    let start = body.find('{').ok_or("reply was not JSON")?;
    let doc: serde_json::Value =
        serde_json::from_str(&body[start..=body.rfind('}').unwrap_or(start)])
            .map_err(|_| "reply was not JSON")?;
    Ok(format!(
        "name \"{}\", software {}",
        doc["name"].as_str().unwrap_or("?"),
        doc["software"].as_str().unwrap_or("?")
    ))
}

#[tokio::main]
async fn main() -> ExitCode {
    let url = std::env::args().nth(1).unwrap_or_else(|| "ws://127.0.0.1:7778".into());
    let mut failed = 0;
    let mut report = |name: &str, result: Result<String, String>| match result {
        Ok(detail) => println!("PASS  {name}: {detail}"),
        Err(why) => {
            failed += 1;
            println!("FAIL  {name}: {why}");
        }
    };

    match url.strip_prefix("ws://") {
        Some(host) => report("relay information (NIP-11)", info(host).await),
        None => println!("SKIP  relay information (NIP-11): only checked for ws:// addresses"),
    }

    let mut ws = match connect_async(url.as_str()).await {
        Ok((ws, _)) => ws,
        Err(why) => {
            println!("FAIL  connect: {why}");
            return ExitCode::FAILURE;
        }
    };
    report("connect", Ok(url.clone()));

    // Read replies until one starts with one of the wanted labels.
    async fn until(
        ws: &mut (impl StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
                  + Unpin),
        labels: &[&str],
    ) -> Result<(String, usize), String> {
        let mut seen = 0;
        loop {
            let next = tokio::time::timeout(WAIT, ws.next()).await;
            let Ok(Some(Ok(msg))) = next else {
                let wanted = labels.join(" or ");
                return Err(format!("no {wanted} within {} seconds", WAIT.as_secs()));
            };
            let Ok(text) = msg.to_text() else { continue };
            if labels.iter().any(|l| text.starts_with(&format!(r#"["{l}""#))) {
                return Ok((text.to_string(), seen));
            }
            seen += 1;
        }
    }

    let req = r#"["REQ","haskshield-check",{"kinds":[1],"limit":3}]"#;
    let _ = ws.send(Message::text(req)).await;
    report(
        "read (REQ until EOSE)",
        until(&mut ws, &["EOSE"]).await.map(|(_, events)| format!("{events} events, then EOSE")),
    );
    let _ = ws.send(Message::text(r#"["CLOSE","haskshield-check"]"#)).await;

    // Some relays do not answer OK for an ephemeral event, so also listen
    // for it: getting it back on a subscription proves it went through.
    let keys = Keys::generate();
    let listen = format!(
        r#"["REQ","haskshield-echo",{{"kinds":[20001],"authors":["{}"]}}]"#,
        keys.public_key().to_hex()
    );
    let _ = ws.send(Message::text(listen)).await;
    let _ = until(&mut ws, &["EOSE"]).await;

    let good = EventBuilder::new(Kind::Custom(20001), "haskshield check").finalize(&keys).unwrap();
    let _ = ws.send(Message::text(format!(r#"["EVENT",{}]"#, good.as_json()))).await;
    report(
        "write a signed event",
        until(&mut ws, &["OK", "EVENT"]).await.and_then(|(reply, _)| {
            if reply.starts_with(r#"["EVENT""#) {
                Ok("delivered to a subscriber".into())
            } else if reply.contains(",true,") {
                Ok("accepted".into())
            } else {
                Err(reply)
            }
        }),
    );
    let _ = ws.send(Message::text(r#"["CLOSE","haskshield-echo"]"#)).await;

    let mut bad = EventBuilder::new(Kind::Custom(20001), "original").finalize(&keys).unwrap();
    bad.content = "changed after signing".into();
    let _ = ws.send(Message::text(format!(r#"["EVENT",{}]"#, bad.as_json()))).await;
    report(
        "refuse a tampered event",
        until(&mut ws, &["OK"]).await.and_then(|(reply, _)| {
            if reply.contains(",false,") { Ok(reply) } else { Err(reply) }
        }),
    );

    if failed == 0 {
        println!("all checks passed");
        ExitCode::SUCCESS
    } else {
        println!("{failed} check(s) failed");
        ExitCode::FAILURE
    }
}
