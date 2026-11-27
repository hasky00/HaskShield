# HaskShield

A Nostr-native shield that sits in front of a relay and keeps spam and floods out, without breaking any client.

Status: early. Layers 1 and 2 are built and tested against a stand-in relay. It has not run in front of a live relay yet. Layers 3 to 5 are still plans.

## Why

Open relays are getting hit from two directions at once:

1. **Connection floods.** Huge numbers of IPs open websockets and hammer the relay with requests until it stops answering.
2. **Event spam.** Junk notes are written faster than any operator can clean them up.

Ordinary bot protection (browser challenges, captchas) does not work here. Nostr clients such as Damus, Primal and Amethyst cannot solve a browser challenge, so that kind of shield locks out real users together with the bots.

HaskShield only uses defences the Nostr protocol already supports, so every client keeps working unchanged.

## How it works

```
client (Damus, Primal, Amethyst, ...)
        |
        v
   HaskShield        <- decides who gets through
        |
        v
  relay (strfry or any other)
```

HaskShield is a websocket proxy. Clients connect to it exactly as they would to the relay. The relay behind it needs no changes.

Checks run cheapest first, so junk is rejected before it costs anything:

| Layer | What it checks | Cost |
|---|---|---|
| 1. Connection | Connections per IP, new connections per minute, slow handshakes | Very low |
| 2. Message | Message rate per IP, message size | Low |
| 3. Event | Rate per pubkey, duplicate content, number of open subscriptions | Low |
| 4. Proof | Proof of work (NIP-13), auth (NIP-42) when the relay is under pressure | Medium |
| 5. Review | Optional slower check for unclear cases only | High |

Layers 4 and 5 switch on only when needed. In calm times the relay stays as open as its operator wants.

## Planned features

- Per-IP connection and rate limits
- Per-pubkey write limits
- Pressure mode: raise proof-of-work or require auth automatically while under attack, relax afterwards
- Allow list and block list (pubkeys, IPs)
- One config file, sensible defaults
- Runs as a single container next to the relay
- Plain counters for what was let through and what was rejected, and why

## What it will not do

- It cannot absorb a very large volumetric attack on a small server. It makes rejecting junk cheap, which keeps the relay up far longer, but bandwidth is still bandwidth.
- It does not read or judge the meaning of ordinary posts. It limits behaviour, not opinions.
- It does not need, or ask for, any change in Nostr clients.

## Run it

```
HASKSHIELD_LISTEN=0.0.0.0:7778 \
HASKSHIELD_UPSTREAM=ws://127.0.0.1:7777 \
cargo run --release
```

Point clients (or your reverse proxy) at HaskShield instead of the relay.

| Setting | Default | Meaning |
|---|---|---|
| `HASKSHIELD_LISTEN` | `0.0.0.0:7778` | Address HaskShield listens on |
| `HASKSHIELD_UPSTREAM` | `ws://127.0.0.1:7777` | The relay behind it |
| `HASKSHIELD_MAX_CONN_PER_IP` | `20` | Open connections one IP may hold |
| `HASKSHIELD_MAX_NEW_CONN_PER_MIN` | `60` | New connections one IP may open per minute |
| `HASKSHIELD_MSGS_PER_SEC` | `20` | Messages per second per IP, with bursts of five times this |
| `HASKSHIELD_MAX_MESSAGE_BYTES` | `131072` | Largest single message from a client |
| `HASKSHIELD_TRUST_PROXY` | off | Set to `1` only behind a reverse proxy such as Caddy, so the client IP is read from `X-Forwarded-For` |

What a client sees when it is over a limit:

- Too many connections: the connection is refused with HTTP 429.
- Too many messages: `["OK", id, false, "rate-limited: slow down"]` for an event, `["CLOSED", sub, "rate-limited: slow down"]` for a subscription. A client that keeps going is disconnected.
- A message that is too large: the connection is closed.

IPv6 clients are counted per /64 network. Plain HTTP requests, including the relay information document (NIP-11), are passed through to the relay; this needs a `ws://` upstream.

Written in Rust. Run the tests with `cargo test`.

## Open decisions

- Proxy only, or also a strfry write-policy plugin for layer 3
- How pressure mode decides that the relay is under attack
- Per-pubkey limits need the event signature checked first, otherwise anyone could get another person's key rate-limited by sending fake events in their name
- Licence

## Test bed

The first deployment target is the open relay at `wss://hasky.chat`.

## Made by

Hasky Labs, Copenhagen.
