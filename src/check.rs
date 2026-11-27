//! Decides what happens to each message a client sends.

use std::collections::HashSet;
use std::sync::atomic::Ordering::Relaxed;

use nostr::event::Event;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;

use crate::limits::{Shield, Slot};

/// Longest subscription id NIP-01 allows.
const MAX_SUB_ID: usize = 64;

/// What to do with a client message.
pub(crate) enum Verdict {
    /// Send it on to the relay.
    Forward,
    /// Do not send it on; tell the client why instead.
    Refuse(Message),
}

/// What we remember about one connection.
#[derive(Default)]
pub(crate) struct Conn {
    subs: HashSet<String>,
}

fn notice(why: &str) -> Message {
    Message::text(json!(["NOTICE", why]).to_string())
}

fn closed(sub: &str, why: &str) -> Message {
    Message::text(json!(["CLOSED", sub, why]).to_string())
}

/// Reply to a refused event. Falls back to a NOTICE when the event carries
/// no usable id to answer with.
fn not_ok(event: Option<&Value>, why: &str) -> Message {
    match event.and_then(|e| e.get("id")).and_then(Value::as_str) {
        Some(id) if id.len() <= 64 => Message::text(json!(["OK", id, false, why]).to_string()),
        _ => notice(why),
    }
}

/// The reply for a message that was over the IP's message rate. This runs
/// before the message is examined, so it reads only what it needs.
pub(crate) fn rate_limit_reply(msg: &Message) -> Message {
    const WHY: &str = "rate-limited: slow down";
    let parsed = msg.to_text().ok().and_then(|t| serde_json::from_str::<Value>(t).ok());
    let parts = parsed.as_ref().and_then(Value::as_array);
    match parts.and_then(|a| a.first()).and_then(Value::as_str) {
        Some("EVENT") => not_ok(parts.and_then(|a| a.get(1)), WHY),
        Some("REQ" | "COUNT") => match parts.and_then(|a| a.get(1)).and_then(Value::as_str) {
            Some(sub) if sub.len() <= MAX_SUB_ID => closed(sub, WHY),
            _ => notice(WHY),
        },
        _ => notice(WHY),
    }
}

impl Conn {
    /// Examine one text message from the client.
    pub fn check(&mut self, shield: &Shield, slot: &Slot, text: &str) -> Verdict {
        let stats = &shield.stats;
        let Ok(Value::Array(parts)) = serde_json::from_str::<Value>(text) else {
            stats.malformed.fetch_add(1, Relaxed);
            return Verdict::Refuse(notice("invalid: not a Nostr message"));
        };
        match parts.first().and_then(Value::as_str) {
            Some("EVENT") => self.check_event(shield, slot, parts.get(1)),
            Some(kind @ ("REQ" | "COUNT")) => self.check_request(shield, kind, &parts),
            Some("CLOSE") => {
                if let Some(sub) = parts.get(1).and_then(Value::as_str) {
                    self.subs.remove(sub);
                }
                Verdict::Forward
            }
            // AUTH and anything newer go to the relay untouched.
            Some(_) => Verdict::Forward,
            None => {
                stats.malformed.fetch_add(1, Relaxed);
                Verdict::Refuse(notice("invalid: not a Nostr message"))
            }
        }
    }

    fn check_event(&mut self, shield: &Shield, slot: &Slot, raw: Option<&Value>) -> Verdict {
        let cfg = &shield.cfg;
        let stats = &shield.stats;
        shield.saw_event();
        if !cfg.verify_events {
            return Verdict::Forward;
        }

        let Some(event) = raw.and_then(|v| Event::deserialize(v).ok()) else {
            stats.malformed.fetch_add(1, Relaxed);
            return Verdict::Refuse(not_ok(raw, "invalid: malformed event"));
        };
        // Cheap look-up first: a blocked key does not earn a signature check.
        if cfg.block_pubkeys.contains(&event.pubkey) {
            stats.blocked_key.fetch_add(1, Relaxed);
            return Verdict::Refuse(not_ok(raw, "blocked: this key may not post here"));
        }
        // Also before the signature check, so one address cannot make the
        // shield verify signatures without end.
        if !slot.allow_event() {
            stats.events_limited.fetch_add(1, Relaxed);
            let why = "rate-limited: too many events from your address";
            return Verdict::Refuse(not_ok(raw, why));
        }
        if event.verify().is_err() {
            stats.bad_signature.fetch_add(1, Relaxed);
            return Verdict::Refuse(not_ok(raw, "invalid: bad event id or signature"));
        }
        if cfg.allow_pubkeys.contains(&event.pubkey) {
            return Verdict::Forward;
        }

        let pressure = shield.under_pressure();
        let pow = if pressure { cfg.min_pow.max(cfg.pressure_pow) } else { cfg.min_pow };
        if pow > 0 && !event.check_pow(pow) {
            stats.pow_missing.fetch_add(1, Relaxed);
            let why = if pressure && cfg.pressure_pow > cfg.min_pow {
                format!("pow: relay is under heavy load, difficulty {pow} required for now")
            } else {
                format!("pow: difficulty {pow} required")
            };
            return Verdict::Refuse(not_ok(raw, &why));
        }
        if !slot.allow_event_from(&event.pubkey) {
            stats.key_limited.fetch_add(1, Relaxed);
            return Verdict::Refuse(not_ok(raw, "rate-limited: this key is posting too fast"));
        }
        Verdict::Forward
    }

    fn check_request(&mut self, shield: &Shield, kind: &str, parts: &[Value]) -> Verdict {
        let cfg = &shield.cfg;
        let stats = &shield.stats;
        let Some(sub) = parts.get(1).and_then(Value::as_str) else {
            stats.malformed.fetch_add(1, Relaxed);
            return Verdict::Refuse(notice("invalid: subscription id missing"));
        };
        if sub.is_empty() || sub.len() > MAX_SUB_ID {
            stats.malformed.fetch_add(1, Relaxed);
            return Verdict::Refuse(notice("invalid: subscription id must be 1 to 64 characters"));
        }
        if parts.len() - 2 > cfg.max_filters_per_req {
            stats.subs_refused.fetch_add(1, Relaxed);
            return Verdict::Refuse(closed(sub, "invalid: too many filters"));
        }
        // A COUNT is answered once and holds nothing open.
        if kind == "REQ" && !self.subs.contains(sub) {
            if self.subs.len() >= cfg.max_subs_per_conn {
                stats.subs_refused.fetch_add(1, Relaxed);
                return Verdict::Refuse(closed(sub, "rate-limited: too many open subscriptions"));
            }
            self.subs.insert(sub.to_string());
        }
        Verdict::Forward
    }

    /// Note a message from the relay, so a subscription the relay closed
    /// no longer counts against the client.
    pub fn saw_from_relay(&mut self, text: &str) {
        if !text.starts_with(r#"["CLOSED""#) {
            return;
        }
        if let Ok(Value::Array(parts)) = serde_json::from_str::<Value>(text)
            && let Some(sub) = parts.get(1).and_then(Value::as_str)
        {
            self.subs.remove(sub);
        }
    }
}
